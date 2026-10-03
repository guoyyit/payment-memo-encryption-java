package com.github.guoyyit.paymentmemoencryptionjava.scan;

public interface CursorStore {

    ScanPosition load(String recipientId);

    void store(String recipientId, ScanPosition position);
}
