package com.github.guoyyit.paymentmemoencryptionjava.scan;

public record ScanFailure(long transferSequence,
                          int memoIndex,
                          String recipientId,
                          int keyGeneration,
                          FailureReason reason) {
}
