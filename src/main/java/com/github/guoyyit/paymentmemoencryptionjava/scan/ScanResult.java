package com.github.guoyyit.paymentmemoencryptionjava.scan;

import java.util.ArrayList;
import java.util.List;

/**
 * Outcome of a scan batch.
 */
public class ScanResult {

    private String payeeId;
    private long lastSeq;
    private List<RecoveredMemo> recovered = new ArrayList<>();
    private List<ScanFailure> failures = new ArrayList<>();

    public String getPayeeId() {
        return payeeId;
    }

    public void setPayeeId(String payeeId) {
        this.payeeId = payeeId;
    }

    public long getLastSeq() {
        return lastSeq;
    }

    public void setLastSeq(long lastSeq) {
        this.lastSeq = lastSeq;
    }

    public List<RecoveredMemo> getRecovered() {
        return recovered;
    }

    public void setRecovered(List<RecoveredMemo> recovered) {
        this.recovered = recovered;
    }

    public List<ScanFailure> getFailures() {
        return failures;
    }

    public void setFailures(List<ScanFailure> failures) {
        this.failures = failures;
    }
}
