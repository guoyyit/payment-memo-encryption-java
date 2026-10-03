package com.github.guoyyit.paymentmemoencryptionjava.transfer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A local transfer placeholder.
 */
public class Transfer {

    private long seq;
    private String transferId;
    private String requestId;
    private String fromPayeeId;
    private String toPayeeId;
    private Instant createdAt;
    private List<Memo> memos = new ArrayList<>();

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

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
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

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public List<Memo> getMemos() {
        return memos;
    }

    public void setMemos(List<Memo> memos) {
        this.memos = memos;
    }
}
