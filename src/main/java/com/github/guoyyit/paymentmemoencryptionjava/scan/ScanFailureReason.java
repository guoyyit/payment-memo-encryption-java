package com.github.guoyyit.paymentmemoencryptionjava.scan;

/**
 * Reasons a memo envelope is rejected during scanning.
 */
public enum ScanFailureReason {
    MALFORMED,
    UNKNOWN_GENERATION,
    DECRYPTION_FAILED
}
