package com.github.guoyyit.paymentmemoencryptionjava.domain;

public record EncryptedMemo(String recipientId, int keyGeneration, byte[] iv, byte[] ciphertext) {
}
