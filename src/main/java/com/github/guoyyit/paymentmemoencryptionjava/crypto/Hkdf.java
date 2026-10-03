package com.github.guoyyit.paymentmemoencryptionjava.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * RFC 5869 HKDF using HMAC-SHA256.
 */
public final class Hkdf {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private Hkdf() {
    }

    /**
     * Derives key material from the given input keying material.
     *
     * @param salt   optional salt (use a fixed application salt when no random salt is available)
     * @param ikm    input keying material (e.g. X25519 shared secret)
     * @param info   context/application info binding the derived key to its purpose
     * @param length desired output length in bytes
     */
    public static byte[] deriveKey(byte[] salt, byte[] ikm, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            byte[] actualSalt = (salt == null || salt.length == 0)
                    ? new byte[HASH_LEN] : salt;
            mac.init(new SecretKeySpec(actualSalt, HMAC_ALGORITHM));
            byte[] prk = mac.doFinal(ikm);

            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            int counter = 1;
            while (pos < length) {
                mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));
                mac.update(t);
                mac.update(info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int toCopy = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, okm, pos, toCopy);
                pos += toCopy;
                counter++;
            }
            return okm;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HKDF-SHA256 unavailable", e);
        }
    }

    static byte[] salt(String applicationSalt) {
        return applicationSalt.getBytes(StandardCharsets.UTF_8);
    }
}
