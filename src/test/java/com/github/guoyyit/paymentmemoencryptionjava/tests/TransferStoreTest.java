package com.github.guoyyit.paymentmemoencryptionjava.tests;

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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransferStoreTest {

    @TempDir
    Path tempDir;

    private TransferStore store;

    @BeforeEach
    void setUp() {
        store = new TransferStore(tempDir.resolve("data"));
    }

    private Transfer transfer(String requestId, String from, String to, String... memos) {
        Transfer transfer = new Transfer();
        transfer.setRequestId(requestId);
        transfer.setFromPayeeId(from);
        transfer.setToPayeeId(to);
        for (int i = 0; i < memos.length; i++) {
            transfer.getMemos().add(new Memo(i, memos[i].getBytes()));
        }
        return transfer;
    }

    @Test
    void commitsAreIdempotentOnRequestId() {
        Transfer first = store.commit(transfer("req-1", "bob", "alice", "a"));
        Transfer second = store.commit(transfer("req-1", "bob", "alice", "a"));

        assertEquals(first.getSeq(), second.getSeq());
        assertEquals(first.getTransferId(), second.getTransferId());
        assertEquals(1, store.maxSeq());
    }

    @Test
    void commitsGetMonotonicSeq() {
        Transfer t1 = store.commit(transfer("req-1", "bob", "alice"));
        Transfer t2 = store.commit(transfer("req-2", "bob", "alice"));
        Transfer t3 = store.commit(transfer("req-3", "bob", "alice"));

        assertEquals(1L, t1.getSeq());
        assertEquals(2L, t2.getSeq());
        assertEquals(3L, t3.getSeq());
    }

    @Test
    void pollReturnsContiguousPrefixInOrder() {
        store.commit(transfer("req-1", "bob", "alice"));
        store.commit(transfer("req-2", "bob", "alice"));
        store.commit(transfer("req-3", "bob", "alice"));

        List<Transfer> firstBatch = store.poll(0, 2);
        assertEquals(2, firstBatch.size());
        assertEquals(1L, firstBatch.get(0).getSeq());
        assertEquals(2L, firstBatch.get(1).getSeq());

        List<Transfer> secondBatch = store.poll(2, 2);
        assertEquals(1, secondBatch.size());
        assertEquals(3L, secondBatch.get(0).getSeq());
    }

    @Test
    void pollStopsAtGapsAndResumesWhenFilled() throws Exception {
        store.commit(transfer("req-1", "bob", "alice"));
        // simulate a commit that landed ahead of seq 2: create seq 3 directly
        Path transferFile = tempDir.resolve("data").resolve("transfers").resolve("3.json");
        Transfer ahead = transfer("req-3", "bob", "alice");
        ahead.setSeq(3);
        ahead.setTransferId("tx-3");
        ahead.setCreatedAt(java.time.Instant.now());
        Files.writeString(transferFile, new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(java.util.Map.of(
                        "seq", 3,
                        "transferId", "tx-3",
                        "requestId", "req-3",
                        "fromPayeeId", "bob",
                        "toPayeeId", "alice",
                        "createdAt", System.currentTimeMillis(),
                        "memos", List.of())));

        List<Transfer> gapped = store.poll(0, 10);
        assertEquals(1, gapped.size(), () -> "gap must stop delivery");
        assertEquals(1L, gapped.get(0).getSeq());

        // the missing seq 2 arrives late
        store.commit(transfer("req-2", "bob", "alice"));
        List<Transfer> filled = store.poll(0, 10);
        assertEquals(3, filled.size());
        assertEquals(1L, filled.get(0).getSeq());
        assertEquals(2L, filled.get(1).getSeq());
        assertEquals(3L, filled.get(2).getSeq());
    }

    @Test
    void crashRecoveryRestoresCommittedTransfer() throws Exception {
        Transfer committed = store.commit(transfer("req-1", "bob", "alice", "memo"));
        // simulate crash after idempotency marker but before transfer body move
        Path body = tempDir.resolve("data").resolve("transfers").resolve("1.json");
        Files.deleteIfExists(body);

        TransferStore restarted = new TransferStore(tempDir.resolve("data"));
        List<Transfer> polled = restarted.poll(0, 10);

        assertEquals(1, polled.size());
        assertEquals(committed.getRequestId(), polled.get(0).getRequestId());
        assertEquals(committed.getSeq(), polled.get(0).getSeq());
        assertNotEquals(0, polled.get(0).getMemos().size());
        assertTrue(Files.exists(body));
    }
}
