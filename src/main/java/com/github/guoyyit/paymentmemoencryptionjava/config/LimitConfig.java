package com.github.guoyyit.paymentmemoencryptionjava.config;

public record LimitConfig(int maxMemoBytes, int maxMemosPerTransfer, int scanBatchSize) {
}
