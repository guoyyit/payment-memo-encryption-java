package com.github.guoyyit.paymentmemoencryptionjava.scan;

public record ScanPosition(long nextSequence, long nextOffset) {

    public static ScanPosition start() {
        return new ScanPosition(0L, 0L);
    }
}
