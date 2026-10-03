package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;
import com.github.guoyyit.paymentmemoencryptionjava.scan.MemoScanner;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanCheckpoint;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanFailure;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanFailureReason;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Memo;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.TransferStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScannerTest {

    @TempDir
    Path tempDir;

    private Path dataDir;
    private TransferStore store;
    private PayeeKeyStore keyStore;
    private MemoCrypto crypto;

    @BeforeEach
    void setUp() {
        dataDir = tempDir.resolve("data");
        store = new TransferStore(dataDir.resolve("stream"));
        keyStore = new PayeeKeyStore("alice");
        keyStore.rotate();
        crypto = new MemoCrypto();
    }

    private void commitEncrypted(String requestId, String from, String... memos) {
        Transfer transfer = new Transfer();
        transfer.setRequestId(requestId);
        transfer.setFromPayeeId(from);
        transfer.setToPayeeId("alice");
        for (int i = 0; i < memos.length; i++) {
            byte[] envelope = crypto.encrypt("alice", keyStore.getActive().getGenId(),
                    keyStore.getActive().getPublicKey(), memos[i]);
            transfer.getMemos().add(new Memo(i, envelope));
        }
        store.commit(transfer);
    }

    private List<RecoveredMemo> scanWith(int batchSize, String checkpointName) {
        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve(checkpointName), batchSize);
        return scanner.scan().getRecovered();
    }

    @Test
    void outputIsIndependentOfBatchSize() {
        commitEncrypted("req-1", "bob", "m1");
        commitEncrypted("req-2", "bob", "m2", "m3");
        commitEncrypted("req-3", "carol", "m4");

        List<RecoveredMemo> small = scanWith(1, "cp-small");
        List<RecoveredMemo> large = scanWith(100, "cp-large");

        assertEquals(small.size(), large.size());
        assertEquals(4, small.size());
        for (int i = 0; i < small.size(); i++) {
            assertEquals(small.get(i).getPlaintext(), large.get(i).getPlaintext());
            assertEquals(small.get(i).getSeq(), large.get(i).getSeq());
            assertEquals(small.get(i).getKeyGenId(), large.get(i).getKeyGenId());
        }
    }

    @Test
    void rescanAfterCheckpointEmitsNothingNew() {
        commitEncrypted("req-1", "bob", "m1");
        commitEncrypted("req-2", "bob", "m2");

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult first = scanner.scan();
        ScanResult second = scanner.scan();

        assertEquals(2, first.getRecovered().size());
        assertEquals(0, second.getRecovered().size());
    }

    @Test
    void checkpointResumeSkipsAlreadyProcessedTransfers() {
        commitEncrypted("req-1", "bob", "m1");
        commitEncrypted("req-2", "bob", "m2");
        commitEncrypted("req-3", "bob", "m3");
        commitEncrypted("req-4", "bob", "m4");

        // simulate a crash after processing seq 2
        new ScanCheckpoint("alice", 2).save(dataDir.resolve("cp"));

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult result = scanner.scan();

        assertEquals(2, result.getRecovered().size());
        assertEquals("m3", result.getRecovered().get(0).getPlaintext());
        assertEquals("m4", result.getRecovered().get(1).getPlaintext());
        assertEquals(4L, result.getLastSeq());
    }

    @Test
    void failuresAreIsolatedAndDoNotStopScan() {
        commitEncrypted("req-1", "bob", "good-1");

        // tamper a memo in the middle transfer
        byte[] tampered = crypto.encrypt("alice", keyStore.getActive().getGenId(),
                keyStore.getActive().getPublicKey(), "tampered");
        tampered[tampered.length - 1] ^= 0x01;
        Transfer bad = new Transfer();
        bad.setRequestId("req-2");
        bad.setFromPayeeId("bob");
        bad.setToPayeeId("alice");
        bad.getMemos().add(new Memo(0, tampered));
        store.commit(bad);

        commitEncrypted("req-3", "bob", "good-2");

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult result = scanner.scan();

        assertEquals(2, result.getRecovered().size());
        assertEquals("good-1", result.getRecovered().get(0).getPlaintext());
        assertEquals("good-2", result.getRecovered().get(1).getPlaintext());
        assertEquals(1, result.getFailures().size());
        ScanFailure failure = result.getFailures().get(0);
        assertEquals(ScanFailureReason.DECRYPTION_FAILED, failure.getReason());
        assertEquals(2L, failure.getSeq());
    }

    @Test
    void unknownGenerationIsRejectedAndScanContinues() {
        // envelope claims generation 99, which the payee never held
        byte[] envelope = crypto.encrypt("alice", 99L,
                keyStore.getActive().getPublicKey(), "ghost");
        Transfer transfer = new Transfer();
        transfer.setRequestId("req-1");
        transfer.setFromPayeeId("bob");
        transfer.setToPayeeId("alice");
        transfer.getMemos().add(new Memo(0, envelope));
        store.commit(transfer);

        commitEncrypted("req-2", "bob", "real");

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult result = scanner.scan();

        assertEquals(1, result.getRecovered().size());
        assertEquals("real", result.getRecovered().get(0).getPlaintext());
        assertEquals(1, result.getFailures().size());
        assertEquals(ScanFailureReason.UNKNOWN_GENERATION, result.getFailures().get(0).getReason());
    }

    @Test
    void lateArrivalFillsGapAndRecoversInOrder() {
        commitEncrypted("req-1", "bob", "m1");
        // simulate a commit that landed ahead of seq 2
        Path transferFile = dataDir.resolve("stream").resolve("transfers").resolve("3.json");
        Transfer ahead = new Transfer();
        ahead.setSeq(3);
        ahead.setTransferId("tx-3");
        ahead.setRequestId("req-3");
        ahead.setFromPayeeId("bob");
        ahead.setToPayeeId("alice");
        ahead.setCreatedAt(java.time.Instant.now());
        byte[] m3 = crypto.encrypt("alice", keyStore.getActive().getGenId(),
                keyStore.getActive().getPublicKey(), "m3");
        ahead.getMemos().add(new Memo(0, m3));
        try {
            Files.createDirectories(transferFile.getParent());
            Files.writeString(transferFile, new com.fasterxml.jackson.databind.ObjectMapper()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(transferDoc(ahead)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult gapped = scanner.scan();
        assertEquals(1, gapped.getRecovered().size());
        assertEquals("m1", gapped.getRecovered().get(0).getPlaintext());

        // the missing seq 2 arrives late (store assigns seq 2)
        commitEncrypted("req-2", "bob", "m2");

        ScanResult filled = scanner.scan();
        assertEquals(2, filled.getRecovered().size());
        assertEquals("m2", filled.getRecovered().get(0).getPlaintext());
        assertEquals("m3", filled.getRecovered().get(1).getPlaintext());
    }

    private java.util.Map<String, Object> transferDoc(Transfer transfer) {
        return java.util.Map.of(
                "seq", transfer.getSeq(),
                "transferId", transfer.getTransferId(),
                "requestId", transfer.getRequestId(),
                "fromPayeeId", transfer.getFromPayeeId(),
                "toPayeeId", transfer.getToPayeeId(),
                "createdAt", transfer.getCreatedAt().toEpochMilli(),
                "memos", transfer.getMemos().stream()
                        .map(m -> java.util.Map.of(
                                "index", m.getIndex(),
                                "envelope", java.util.Base64.getEncoder().encodeToString(m.getEnvelope())))
                        .toList());
    }

    @Test
    void malformedEnvelopeIsRejected() {
        Transfer transfer = new Transfer();
        transfer.setRequestId("req-1");
        transfer.setFromPayeeId("bob");
        transfer.setToPayeeId("alice");
        transfer.getMemos().add(new Memo(0, new byte[]{1, 2, 3}));
        store.commit(transfer);

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("cp"), 10);
        ScanResult result = scanner.scan();

        assertEquals(0, result.getRecovered().size());
        assertEquals(1, result.getFailures().size());
        assertEquals(ScanFailureReason.MALFORMED, result.getFailures().get(0).getReason());
        assertTrue(result.getFailures().get(0).getDetail().length() > 0);
    }
}
