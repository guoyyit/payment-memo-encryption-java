package com.github.guoyyit.paymentmemoencryptionjava.scan;

/**
 * A memo successfully recovered from the transfer stream.
 */
public class RecoveredMemo {

    private long seq;
    private String transferId;
    private int memoIndex;
    private String fromPayeeId;
    private String toPayeeId;
    private String plaintext;
    private long keyGenId;

    public long getSeq() {
        return seq;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public String getTransferId() {
        return transferId;
    }

    public void setTransferId(String transferId) {
        this.transferId = transferId;
    }

    public int getMemoIndex() {
        return memoIndex;
    }

    public void setMemoIndex(int memoIndex) {
        this.memoIndex = memoIndex;
    }

    public String getFromPayeeId() {
        return fromPayeeId;
    }

    public void setFromPayeeId(String fromPayeeId) {
        this.fromPayeeId = fromPayeeId;
    }

    public String getToPayeeId() {
        return toPayeeId;
    }

    public void setToPayeeId(String toPayeeId) {
        this.toPayeeId = toPayeeId;
    }

    public String getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(String plaintext) {
        this.plaintext = plaintext;
    }

    public long getKeyGenId() {
        return keyGenId;
    }

    public void setKeyGenId(long keyGenId) {
        this.keyGenId = keyGenId;
    }
}
