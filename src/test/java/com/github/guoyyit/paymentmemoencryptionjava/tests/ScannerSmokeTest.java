package com.github.guoyyit.paymentmemoencryptionjava.tests;

import com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto;
import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;
import com.github.guoyyit.paymentmemoencryptionjava.scan.MemoScanner;
import com.github.guoyyit.paymentmemoencryptionjava.scan.RecoveredMemo;
import com.github.guoyyit.paymentmemoencryptionjava.scan.ScanResult;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Memo;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.Transfer;
import com.github.guoyyit.paymentmemoencryptionjava.transfer.TransferStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScannerSmokeTest {

    @TempDir
    Path tempDir;

    @Test
    void endToEndScan() {
        Path dataDir = tempDir.resolve("data");
        TransferStore store = new TransferStore(dataDir);
        PayeeKeyStore keyStore = new PayeeKeyStore("alice");
        keyStore.rotate();
        MemoCrypto crypto = new MemoCrypto();

        byte[] enc1 = crypto.encrypt("alice", 1L, keyStore.getActive().getPublicKey(), "memo-1");
        byte[] enc2 = crypto.encrypt("alice", 1L, keyStore.getActive().getPublicKey(), "memo-2");

        Transfer t1 = new Transfer();
        t1.setRequestId("req-1");
        t1.setFromPayeeId("bob");
        t1.setToPayeeId("alice");
        t1.getMemos().add(new Memo(0, enc1));
        store.commit(t1);

        Transfer t2 = new Transfer();
        t2.setRequestId("req-2");
        t2.setFromPayeeId("carol");
        t2.setToPayeeId("alice");
        t2.getMemos().add(new Memo(0, enc2));
        store.commit(t2);

        MemoScanner scanner = new MemoScanner(keyStore, store, crypto,
                dataDir.resolve("scan.checkpoint"), 10);
        ScanResult result = scanner.scan();

        assertEquals(2, result.getRecovered().size());
        assertEquals("memo-1", result.getRecovered().get(0).getPlaintext());
        assertEquals("memo-2", result.getRecovered().get(1).getPlaintext());
        assertEquals(1L, result.getRecovered().get(0).getKeyGenId());
        assertEquals(0, result.getFailures().size());
    }
}
