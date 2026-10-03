package com.github.guoyyit.paymentmemoencryptionjava.stream;

import com.github.guoyyit.paymentmemoencryptionjava.domain.Transfer;

import java.util.List;

public record LogSlice(List<Transfer> transfers, long nextOffset) {
}
