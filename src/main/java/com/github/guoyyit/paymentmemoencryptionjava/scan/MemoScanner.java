package com.github.guoyyit.paymentmemoencryptionjava.scan;

import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Memo;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.TransferStore;

import java.nio.file.Path;
import java.util.List;

/**
 * Memo scanner placeholder.
 */
public class MemoScanner {

    private final PayeeKeyStore keyStore;
    private final TransferStore store;
    private final MemoCrypto crypto;
    private final Path checkpointFile;
    private final int batchSize;

    public MemoScanner(PayeeKeyStore keyStore, TransferStore store, MemoCrypto crypto,
                       Path checkpointFile, int batchSize) {
        this.keyStore = keyStore;
        this.store = store;
        this.crypto = crypto;
        this.checkpointFile = checkpointFile;
        this.batchSize = Math.max(1, batchSize);
    }

    /**
     * Scans all committed transfers after the checkpoint and returns the
     * recovered memos and failures.
     */
    public ScanResult scan() {
        String payeeId = keyStore.getPayeeId();
        ScanCheckpoint checkpoint = ScanCheckpoint.load(checkpointFile, payeeId);
        ScanResult result = new ScanResult();
        result.setPayeeId(payeeId);
        result.setLastSeq(checkpoint.getLastSeq());

        while (true) {
            List<Transfer> batch = store.poll(checkpoint.getLastSeq(), batchSize);
            if (batch.isEmpty()) {
                break;
            }
            for (Transfer transfer : batch) {
                processTransfer(transfer, result);
                checkpoint.setLastSeq(transfer.getSeq());
                checkpoint.save(checkpointFile);
            }
            if (batch.size() < batchSize) {
                break;
            }
        }
        result.setLastSeq(checkpoint.getLastSeq());
        return result;
    }

    private void processTransfer(Transfer transfer, ScanResult result) {
        for (Memo memo : transfer.getMemos()) {
            MemoCrypto.DecryptOutcome outcome =
                    crypto.decrypt(keyStore.getPayeeId(), keyStore, memo.getEnvelope());
            switch (outcome.getStatus()) {
                case RECOVERED -> {
                    RecoveredMemo recovered = new RecoveredMemo();
                    recovered.setSeq(transfer.getSeq());
                    recovered.setTransferId(transfer.getTransferId());
                    recovered.setMemoIndex(memo.getIndex());
                    recovered.setFromPayeeId(transfer.getFromPayeeId());
                    recovered.setToPayeeId(transfer.getToPayeeId());
                    recovered.setPlaintext(outcome.getPlaintext());
                    recovered.setKeyGenId(outcome.getKeyGenId());
                    result.getRecovered().add(recovered);
                }
                case MALFORMED -> result.getFailures().add(new ScanFailure(
                        transfer.getSeq(), memo.getIndex(),
                        ScanFailureReason.MALFORMED, "envelope structurally invalid"));
                case UNKNOWN_GENERATION -> result.getFailures().add(new ScanFailure(
                        transfer.getSeq(), memo.getIndex(),
                        ScanFailureReason.UNKNOWN_GENERATION,
                        "key generation " + genIdOf(memo.getEnvelope()) + " not held by payee"));
                case DECRYPTION_FAILED -> result.getFailures().add(new ScanFailure(
                        transfer.getSeq(), memo.getIndex(),
                        ScanFailureReason.DECRYPTION_FAILED,
                        "authentication tag mismatch or wrong key"));
                case NOT_FOR_PAYEE -> {
                    // memo addressed to another payee: silently skipped
                }
            }
        }
    }

    private static long genIdOf(byte[] envelope) {
        try {
            int payeeLen = ((envelope[1] & 0xFF) << 8) | (envelope[2] & 0xFF);
            int pos = 3 + payeeLen;
            long value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (envelope[pos + i] & 0xFFL);
            }
            return value;
        } catch (Exception e) {
            return -1;
        }
    }
}
