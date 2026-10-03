package com.github.guoyyit.paymentmemoencryptionjava.crypto;

import com.github.guoyyit.paymentmemoencryptionjava.domain.EncryptedMemo;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Encrypts and authenticates a single memo.
 *
 * <p>For every (recipient, key generation, transfer sequence, memo index) context a fresh
 * AES-256 key is derived from the recipient's generation secret with HKDF-SHA-256. The same
 * context is passed as GCM additional authenticated data, so a ciphertext cannot be moved
 * between transfers, recipients or memo slots without being detected.
 */
public class MemoCipher {

    private static final String HKDF_INFO_PREFIX = "payment-memo-v1";
    private static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int HMAC_SHA256_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptedMemo seal(KeyGeneration key, long transferSequence, int memoIndex, String plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            secureRandom.nextBytes(iv);
            byte[] context = context(key.recipientId(), key.generation(), transferSequence, memoIndex);
            SecretKeySpec aeadKey = new SecretKeySpec(deriveKey(key.secret(), context), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aeadKey, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(context);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return new EncryptedMemo(key.recipientId(), key.generation(), iv, ciphertext);
        } catch (GeneralSecurityException e) {
            throw new MemoDecryptionException("Failed to seal memo", e);
        }
    }

    public byte[] open(EncryptedMemo memo, KeyGeneration key, long transferSequence, int memoIndex) {
        if (memo.iv() == null || memo.iv().length != IV_BYTES
                || memo.ciphertext() == null || memo.ciphertext().length == 0) {
            throw new MemoDecryptionException("Malformed memo payload", null);
        }
        try {
            byte[] context = context(key.recipientId(), key.generation(), transferSequence, memoIndex);
            SecretKeySpec aeadKey = new SecretKeySpec(deriveKey(key.secret(), context), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aeadKey, new GCMParameterSpec(TAG_BITS, memo.iv()));
            cipher.updateAAD(context);
            return cipher.doFinal(memo.ciphertext());
        } catch (AEADBadTagException e) {
            throw new MemoIntegrityException("Memo authentication tag verification failed", e);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new MemoDecryptionException("Memo decryption failed", e);
        }
    }

    private static byte[] context(String recipientId, int generation, long transferSequence, int memoIndex) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] prefix = HKDF_INFO_PREFIX.getBytes(StandardCharsets.US_ASCII);
        byte[] recipient = recipientId.getBytes(StandardCharsets.UTF_8);
        writeInt(out, prefix.length);
        out.writeBytes(prefix);
        writeInt(out, recipient.length);
        out.writeBytes(recipient);
        writeInt(out, generation);
        writeLong(out, transferSequence);
        writeInt(out, memoIndex);
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeLong(ByteArrayOutputStream out, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) ((value >>> shift) & 0xFF));
        }
    }

    private static byte[] deriveKey(byte[] secret, byte[] info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[HMAC_SHA256_BYTES], "HmacSHA256"));
        byte[] pseudoRandomKey = mac.doFinal(secret);

        mac.init(new SecretKeySpec(pseudoRandomKey, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 0x01);
        byte[] okm = mac.doFinal();
        byte[] key = new byte[KEY_BYTES];
        System.arraycopy(okm, 0, key, 0, KEY_BYTES);
        return key;
    }
}
