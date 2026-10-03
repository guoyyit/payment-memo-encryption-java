package com.github.guoyyit.paymentmemoencryptionjava.domain;

import java.util.List;

public record Transfer(long sequence, String requestId, List<EncryptedMemo> memos) {
}
