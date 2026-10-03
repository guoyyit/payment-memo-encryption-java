package com.github.guoyyit.paymentmemoencryptionjava.crypto;

public record KeyGeneration(String recipientId, int generation, byte[] secret) {
}
