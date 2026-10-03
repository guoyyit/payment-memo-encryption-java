package com.github.guoyyit.paymentmemoencryptionjava.recovery;

import com.github.guoyyit.paymentmemoencryptionjava.crypto.KeyGeneration;

import java.util.List;

public record RecoveryMaterial(List<KeyGeneration> keys) {
}
