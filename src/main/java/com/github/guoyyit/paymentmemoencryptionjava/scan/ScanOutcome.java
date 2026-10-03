package com.github.guoyyit.paymentmemoencryptionjava.scan;

import java.util.List;

public record ScanOutcome(List<RecoveredMemo> memos,
                          List<ScanFailure> failures,
                          ScanPosition nextPosition,
                          boolean hasMore) {
}
