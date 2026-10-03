package com.github.guoyyit.paymentmemoencryptionjava.transfer;

/**
 * A single encrypted memo carried by a transfer.
 */
public class Memo {

    private int index;
    private byte[] envelope;

    public Memo() {
    }

    public Memo(int index, byte[] envelope) {
        this.index = index;
        this.envelope = envelope;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public byte[] getEnvelope() {
        return envelope;
    }

    public void setEnvelope(byte[] envelope) {
        this.envelope = envelope;
    }
}
