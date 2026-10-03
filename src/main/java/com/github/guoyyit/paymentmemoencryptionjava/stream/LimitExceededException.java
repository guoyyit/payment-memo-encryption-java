package com.github.guoyyit.paymentmemoencryptionjava.stream;

public class LimitExceededException extends RuntimeException {
    public LimitExceededException(String message) {
        super(message);
    }
}
