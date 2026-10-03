package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.config.MemoProperties;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.KeyGeneration;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class KeyRotationTest {

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
    void historicalAndNewMemosRecoverableAfterRotation() {
        // generation 1: one memo
        service.createTransfer(request("req-1", "alice", "before-rotation"));

        KeyGeneration rotated = service.rotateKey("alice");
        assertEquals(2L, rotated.getGenId());

        // generation 2: two memos
        service.createTransfer(request("req-2", "alice", "after-rotation-1", "after-rotation-2"));

        ScanResult result = service.scan("alice");
        assertEquals(3, result.getRecovered().size());
        assertEquals(0, result.getFailures().size());

        RecoveredMemo first = result.getRecovered().get(0);
        assertEquals("before-rotation", first.getPlaintext());
        assertEquals(1L, first.getKeyGenId());

        RecoveredMemo second = result.getRecovered().get(1);
        assertEquals("after-rotation-1", second.getPlaintext());
        assertEquals(2L, second.getKeyGenId());

        RecoveredMemo third = result.getRecovered().get(2);
        assertEquals("after-rotation-2", third.getPlaintext());
        assertEquals(2L, third.getKeyGenId());
    }

    @Test
    void multipleRotationsKeepAllGenerations() {
        service.createTransfer(request("req-1", "alice", "gen-1"));
        service.rotateKey("alice");
        service.createTransfer(request("req-2", "alice", "gen-2"));
        service.rotateKey("alice");
        service.createTransfer(request("req-3", "alice", "gen-3"));

        ScanResult result = service.scan("alice");
        assertEquals(3, result.getRecovered().size());
        assertEquals(1L, result.getRecovered().get(0).getKeyGenId());
        assertEquals(2L, result.getRecovered().get(1).getKeyGenId());
        assertEquals(3L, result.getRecovered().get(2).getKeyGenId());
        assertNotEquals(result.getRecovered().get(0).getKeyGenId(),
                result.getRecovered().get(2).getKeyGenId());
    }
}
