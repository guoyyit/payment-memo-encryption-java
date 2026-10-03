package com.github.guoyyit.paymentmemoencryptionjava.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Wire format of an encrypted memo envelope:
 * <pre>
 *   byte 0      : version (1)
 *   bytes 1-2   : payeeId UTF-8 length (unsigned short, big endian)
 *   bytes 3..   : payeeId UTF-8 bytes
 *   next 8 bytes: key generation id (long, big endian)
 *   next 32     : ephemeral X25519 public key
 *   next 12     : AES-GCM IV
 *   remaining   : AES-GCM ciphertext (plaintext + 16 byte authentication tag)
 * </pre>
 * The AAD covers everything except the IV and ciphertext, i.e. the header
 * binds payee identity, key generation and the ephemeral key together.
 */
public final class Envelope {

    public static final byte VERSION = 1;
    public static final int EPHEMERAL_KEY_LEN = 32;
    public static final int IV_LEN = 12;
    public static final int TAG_LEN = 16;
    public static final int HEADER_FIXED_LEN = 1 + 2 + 8 + EPHEMERAL_KEY_LEN;

    private Envelope() {
    }

    public static byte[] encode(String payeeId, long keyGenId, byte[] ephemeralPublicKey,
                                 byte[] iv, byte[] ciphertext) {
        try {
            byte[] payeeBytes = payeeId.getBytes(StandardCharsets.UTF_8);
            if (payeeBytes.length > 0xFFFF) {
                throw new IllegalArgumentException("payeeId too long");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(VERSION);
            out.write((payeeBytes.length >> 8) & 0xFF);
            out.write(payeeBytes.length & 0xFF);
            out.write(payeeBytes);
            writeLong(out, keyGenId);
            out.write(ephemeralPublicKey);
            out.write(iv);
            out.write(ciphertext);
            return out.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Parses an envelope, rejecting truncated or structurally invalid data.
     */
    public static Parsed parse(byte[] data) throws MalformedEnvelopeException {
        if (data == null || data.length < HEADER_FIXED_LEN + IV_LEN + TAG_LEN) {
            throw new MalformedEnvelopeException("envelope truncated");
        }
        int pos = 0;
        int version = data[pos++] & 0xFF;
        if (version != VERSION) {
            throw new MalformedEnvelopeException("unsupported version: " + version);
        }
        int payeeLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        if (data.length < pos + payeeLen + 8 + EPHEMERAL_KEY_LEN + IV_LEN + TAG_LEN) {
            throw new MalformedEnvelopeException("envelope truncated");
        }
        String payeeId = new String(data, pos, payeeLen, StandardCharsets.UTF_8);
        pos += payeeLen;
        long keyGenId = readLong(data, pos);
        pos += 8;
        byte[] ephemeralPublicKey = new byte[EPHEMERAL_KEY_LEN];
        System.arraycopy(data, pos, ephemeralPublicKey, 0, EPHEMERAL_KEY_LEN);
        pos += EPHEMERAL_KEY_LEN;
        byte[] header = new byte[pos];
        System.arraycopy(data, 0, header, 0, pos);
        byte[] iv = new byte[IV_LEN];
        System.arraycopy(data, pos, iv, 0, IV_LEN);
        pos += IV_LEN;
        int cipherLen = data.length - pos;
        if (cipherLen < TAG_LEN) {
            throw new MalformedEnvelopeException("ciphertext truncated");
        }
        byte[] ciphertext = new byte[cipherLen];
        System.arraycopy(data, pos, ciphertext, 0, cipherLen);
        return new Parsed(payeeId, keyGenId, ephemeralPublicKey, iv, ciphertext, header);
    }

    private static void writeLong(ByteArrayOutputStream out, long value) {
        for (int i = 7; i >= 0; i--) {
            out.write((int) ((value >> (8L * i)) & 0xFF));
        }
    }

    private static long readLong(byte[] data, int pos) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[pos + i] & 0xFFL);
        }
        return value;
    }

    /**
     * A structurally parsed envelope.
     */
    public static final class Parsed {
        private final String payeeId;
        private final long keyGenId;
        private final byte[] ephemeralPublicKey;
        private final byte[] iv;
        private final byte[] ciphertext;
        private final byte[] header;

        Parsed(String payeeId, long keyGenId, byte[] ephemeralPublicKey, byte[] iv,
               byte[] ciphertext, byte[] header) {
            this.payeeId = payeeId;
            this.keyGenId = keyGenId;
            this.ephemeralPublicKey = ephemeralPublicKey;
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.header = header;
        }

        public String getPayeeId() {
            return payeeId;
        }

        public long getKeyGenId() {
            return keyGenId;
        }

        public byte[] getEphemeralPublicKey() {
            return ephemeralPublicKey;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        /**
         * Authenticated associated data: the full envelope header.
         */
        public byte[] getHeader() {
            return header;
        }
    }

    /**
     * Thrown when an envelope cannot even be structurally parsed.
     */
    public static class MalformedEnvelopeException extends Exception {

        public MalformedEnvelopeException(String message) {
            super(message);
        }
    }
}
