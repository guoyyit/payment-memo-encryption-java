package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.config.MemoProperties;
import com.github.guoyyit.paymentmemoencryptionjava.dto.CreateTransferRequest;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.service.MemoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfigTest {

    @TempDir
    Path tempDir;

    private MemoService service;
    private MemoProperties properties;

    @BeforeEach
    void setUp() {
        properties = new MemoProperties();
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
    void memoOverMaxLengthIsRejected() {
        String tooLong = "x".repeat(properties.getMaxLength() + 1);
        assertThrows(IllegalArgumentException.class,
                () -> service.createTransfer(request("req-1", "alice", tooLong)));
    }

    @Test
    void memoAtMaxLengthIsAccepted() {
        String atLimit = "x".repeat(properties.getMaxLength());
        service.createTransfer(request("req-1", "alice", atLimit));
        ScanResult result = service.scan("alice");
        assertEquals(1, result.getRecovered().size());
        assertEquals(atLimit, result.getRecovered().get(0).getPlaintext());
    }

    @Test
    void tooManyMemosIsRejected() {
        String[] memos = new String[properties.getMaxMemosPerTransfer() + 1];
        for (int i = 0; i < memos.length; i++) {
            memos[i] = "m" + i;
        }
        CreateTransferRequest req = request("req-1", "alice", memos);
        assertThrows(IllegalArgumentException.class, () -> service.createTransfer(req));
    }

    @Test
    void memosAtLimitIsAccepted() {
        String[] memos = new String[properties.getMaxMemosPerTransfer()];
        for (int i = 0; i < memos.length; i++) {
            memos[i] = "m" + i;
        }
        service.createTransfer(request("req-1", "alice", memos));
        ScanResult result = service.scan("alice");
        assertEquals(properties.getMaxMemosPerTransfer(), result.getRecovered().size());
    }

    @Test
    void scanBatchSizeDoesNotChangeOutput() {
        properties.setScanBatchSize(1);
        service.createTransfer(request("req-1", "alice", "m1"));
        service.createTransfer(request("req-2", "alice", "m2"));
        service.createTransfer(request("req-3", "alice", "m3"));

        ScanResult result = service.scan("alice");
        assertEquals(3, result.getRecovered().size());
        assertEquals("m1", result.getRecovered().get(0).getPlaintext());
        assertEquals("m2", result.getRecovered().get(1).getPlaintext());
        assertEquals("m3", result.getRecovered().get(2).getPlaintext());
    }
}
