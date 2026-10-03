package com.github.guoyyit.paymentmemoencryptionjava.scan;

/**
 * A rejected envelope found during scanning.
 */
public class ScanFailure {

    private long seq;
    private int memoIndex;
    private ScanFailureReason reason;
    private String detail;

    public ScanFailure() {
    }

    public ScanFailure(long seq, int memoIndex, ScanFailureReason reason, String detail) {
        this.seq = seq;
        this.memoIndex = memoIndex;
        this.reason = reason;
        this.detail = detail;
    }

    public long getSeq() {
        return seq;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public int getMemoIndex() {
        return memoIndex;
    }

    public void setMemoIndex(int memoIndex) {
        this.memoIndex = memoIndex;
    }

    public ScanFailureReason getReason() {
        return reason;
    }

    public void setReason(ScanFailureReason reason) {
        this.reason = reason;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }
}
