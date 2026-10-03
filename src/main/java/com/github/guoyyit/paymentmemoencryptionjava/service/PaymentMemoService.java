package com.github.guoyyit.paymentmemoencryptionjava.service;

import com.github.guoyyit.paymentmemoencryptionjava.config.LimitConfig;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.KeyManager;
import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCipher;
import com.github.guoyyit.paymentmemoencryptionjava.domain.MemoInput;
import com.github.guoyyit.paymentmemoencryptionjava.domain.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.recovery.RecoveryMaterial;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanOutcome;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanPosition;
import com.github.guoyyit.paymentmemoencryptionjava.stream.TransferLog;

import java.nio.file.Path;
import java.util.List;

public class PaymentMemoService {

    public PaymentMemoService(Path dataDirectory, LimitConfig config) {
    }

    public String createRecipient() {
        return null;
    }

    public int rotateKey(String recipientId) {
        return -1;
    }

    public Transfer sendTransfer(String requestId, List<MemoInput> memos) {
        return null;
    }

    public ScanOutcome scanBatch(String recipientId) {
        return null;
    }

    public void commitScan(String recipientId, ScanPosition position) {
    }

    public RecoveryMaterial exportRecoveryMaterial() {
        return null;
    }

    public void importRecoveryMaterial(RecoveryMaterial material) {
    }

    public KeyManager keyManager() {
        return null;
    }

    public MemoCipher cipher() {
        return null;
    }
}
