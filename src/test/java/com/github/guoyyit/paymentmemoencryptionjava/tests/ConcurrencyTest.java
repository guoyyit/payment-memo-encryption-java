package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.config.MemoProperties;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyTest {

    @TempDir
    Path tempDir;

    private MemoService service;

    @BeforeEach
    void setUp() {
        MemoProperties properties = new MemoProperties();
        properties.setDataDir(tempDir.resolve("data").toString());
        service = new MemoService(properties);
        service.init();
        service.rotateKey("alice");
    }

    private CreateTransferRequest request(String requestId, String to, String... memos) {
        CreateTransferRequest request = new CreateTransferRequest();
        request.setRequestId(requestId);
        request.setFromPayeeId("bob");
        request.setToPayeeId(to);
        request.setMemos(List.of(memos));
        return request;
    }

    @Test
    void concurrentCommitsAndScansRecoverAllMemosExactlyOnce() throws Exception {
        int producers = 6;
        int transfersPerProducer = 15;
        int expected = producers * transfersPerProducer;

        ExecutorService executor = Executors.newFixedThreadPool(producers + 2);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        for (int p = 0; p < producers; p++) {
            final int producer = p;
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < transfersPerProducer; i++) {
                        service.createTransfer(request("req-" + producer + "-" + i,
                                "alice", "memo-" + producer + "-" + i));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        for (int s = 0; s < 2; s++) {
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 20; i++) {
                        ScanResult result = service.scan("alice");
                        for (RecoveredMemo memo : result.getRecovered()) {
                            // every recovered memo must be one we committed
                            assertTrue(memo.getPlaintext().startsWith("memo-"));
                        }
                        Thread.sleep(3);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        start.countDown();
        for (Future<?> future : futures) {
            future.get();
        }
        executor.shutdown();

        // definitive scan from a fresh checkpoint
        Path checkpoint = tempDir.resolve("data").resolve("checkpoints").resolve("alice.checkpoint");
        Files.deleteIfExists(checkpoint);
        ScanResult result = service.scan("alice");

        assertEquals(expected, result.getRecovered().size());
        long unique = result.getRecovered().stream()
                .map(m -> m.getTransferId() + "#" + m.getMemoIndex())
                .distinct()
                .count();
        assertEquals(expected, unique);
        assertEquals(0, result.getFailures().size());
    }

    @Test
    void duplicateRequestIdConcurrentSubmitCreatesExactlyOneTransfer() throws Exception {
        int threads = 12;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Transfer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    return service.createTransfer(request("same-req", "alice", "memo"));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                }
            }));
        }
        start.countDown();
        Set<Long> seqs = new HashSet<>();
        for (Future<Transfer> future : futures) {
            seqs.add(future.get().getSeq());
        }
        executor.shutdown();

        assertEquals(1, seqs.size());

        Path checkpoint = tempDir.resolve("data").resolve("checkpoints").resolve("alice.checkpoint");
        Files.deleteIfExists(checkpoint);
        ScanResult result = service.scan("alice");
        assertEquals(1, result.getRecovered().size());
        assertEquals("memo", result.getRecovered().get(0).getPlaintext());
    }
}
