package com.github.guoyyit.paymentmemoencryptionjava.dto;

import java.util.List;

/**
 * Request to create a local transfer with encrypted memos.
 */
public class CreateTransferRequest {

    private String requestId;
    private String fromPayeeId;
    private String toPayeeId;
    private List<String> memos;

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

    public List<String> getMemos() {
        return memos;
    }

    public void setMemos(List<String> memos) {
        this.memos = memos;
    }
}
