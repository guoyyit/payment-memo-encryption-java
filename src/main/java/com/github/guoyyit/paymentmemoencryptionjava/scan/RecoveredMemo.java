package com.github.guoyyit.paymentmemoencryptionjava.scan;

public record RecoveredMemo(long transferSequence,
                            int memoIndex,
                            String recipientId,
                            int keyGeneration,
                            String text) {
}
