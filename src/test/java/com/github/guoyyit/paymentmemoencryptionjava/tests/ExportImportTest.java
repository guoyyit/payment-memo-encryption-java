package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.config.MemoProperties;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ExportImportTest {

    @TempDir
    Path tempDir;

    private MemoService service(Path dataDir) {
        MemoProperties properties = new MemoProperties();
        properties.setDataDir(dataDir.toString());
        MemoService service = new MemoService(properties);
        service.init();
        return service;
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
    void exportImportRebuildsAllHistoricalMemos() throws IOException {
        Path dataDirA = tempDir.resolve("dataA");
        MemoService serviceA = service(dataDirA);
        serviceA.rotateKey("alice");
        serviceA.createTransfer(request("req-1", "alice", "gen1-memo"));
        serviceA.rotateKey("alice");
        serviceA.createTransfer(request("req-2", "alice", "gen2-memo-a", "gen2-memo-b"));
        ScanResult resultA = serviceA.scan("alice");
        assertEquals(3, resultA.getRecovered().size());

        String bundle = serviceA.exportKeys("alice", "correct horse battery staple".toCharArray());

        // new instance: fresh data dir, same stream copied over
        Path dataDirB = tempDir.resolve("dataB");
        MemoService serviceB = service(dataDirB);
        copyStream(dataDirA, dataDirB);
        serviceB.importKeys("alice", bundle, "correct horse battery staple".toCharArray());

        ScanResult resultB = serviceB.scan("alice");

        assertEquals(resultA.getRecovered().size(), resultB.getRecovered().size());
        for (int i = 0; i < resultA.getRecovered().size(); i++) {
            RecoveredMemo a = resultA.getRecovered().get(i);
            RecoveredMemo b = resultB.getRecovered().get(i);
            assertEquals(a.getPlaintext(), b.getPlaintext());
            assertEquals(a.getKeyGenId(), b.getKeyGenId());
            assertEquals(a.getSeq(), b.getSeq());
            assertEquals(a.getTransferId(), b.getTransferId());
            assertEquals(a.getMemoIndex(), b.getMemoIndex());
        }
    }

    @Test
    void wrongPasswordRejectsImport() {
        Path dataDirA = tempDir.resolve("dataA");
        MemoService serviceA = service(dataDirA);
        serviceA.rotateKey("alice");
        String bundle = serviceA.exportKeys("alice", "right-password".toCharArray());

        Path dataDirB = tempDir.resolve("dataB");
        MemoService serviceB = service(dataDirB);
        assertThrows(IllegalArgumentException.class,
                () -> serviceB.importKeys("alice", bundle, "wrong-password".toCharArray()));
    }

    private void copyStream(Path from, Path to) throws IOException {
        Path streamFrom = from.resolve("stream");
        Path streamTo = to.resolve("stream");
        Files.createDirectories(streamTo);
        try (var walk = Files.walk(streamFrom)) {
            for (Path source : walk.toList()) {
                Path destination = streamTo.resolve(streamFrom.relativize(source));
                if (Files.isDirectory(source)) {
                    Files.createDirectories(destination);
                } else {
                    Files.copy(source, destination);
                }
            }
        }
    }
}
