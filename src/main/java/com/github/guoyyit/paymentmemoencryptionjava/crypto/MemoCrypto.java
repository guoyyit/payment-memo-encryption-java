package com.github.guoyyit.paymentmemoencryptionjava.crypto;

import com.github.guoyyit.paymentmemoencryptionjava.keystore.PayeeKeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Memo encryption/decryption placeholder.
 */
public class MemoCrypto {

    private static final String XDH = "XDH";
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int AES_KEY_LEN = 32;
    private static final int TAG_BITS = 128;
    private static final byte[] HKDF_SALT =
            "payment-memo-encryption-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO_PREFIX =
            "payment-memo-v1|".getBytes(StandardCharsets.UTF_8);
    // SPKI prefix for an X25519 SubjectPublicKeyInfo (12 bytes), followed by
    // the 32-byte raw public key.
    private static final byte[] X25519_SPKI_PREFIX =
            java.util.Base64.getDecoder().decode("MCowBQYDK2VuAyEA");

    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a fresh X25519 key pair for a new payee key generation.
     */
    public static KeyPair generateX25519KeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(XDH);
            generator.initialize(NamedParameterSpec.X25519);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 key generation unavailable", e);
        }
    }

    /**
     * Encrypts a memo to the payee of the given key generation.
     */
    public byte[] encrypt(String payeeId, long keyGenId, PublicKey payeePublicKey, String plaintext) {
        try {
            KeyPair ephemeral = generateX25519KeyPair();
            byte[] shared = ecdh(ephemeral.getPrivate(), payeePublicKey);
            byte[] aesKey = deriveAesKey(payeeId, shared);

            byte[] iv = new byte[Envelope.IV_LEN];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, AES),
                    new GCMParameterSpec(TAG_BITS, iv));
            byte[] rawEphemeralPublic = rawX25519PublicKey(ephemeral.getPublic());
            cipher.updateAAD(buildAad(payeeId, keyGenId, rawEphemeralPublic));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(shared, (byte) 0);
            return Envelope.encode(payeeId, keyGenId, rawEphemeralPublic, iv, ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("memo encryption failed", e);
        }
    }

    /**
     * Attempts to decrypt an envelope addressed to {@code payeeId} using the
     * generations held by {@code keyStore}.
     */
    public DecryptOutcome decrypt(String payeeId, PayeeKeyStore keyStore, byte[] envelope) {
        Envelope.Parsed parsed;
        try {
            parsed = Envelope.parse(envelope);
        } catch (Envelope.MalformedEnvelopeException e) {
            return DecryptOutcome.failure(Status.MALFORMED);
        }
        if (!payeeId.equals(parsed.getPayeeId())) {
            return DecryptOutcome.failure(Status.NOT_FOR_PAYEE);
        }
        var generation = keyStore.findGeneration(parsed.getKeyGenId());
        if (generation.isEmpty()) {
            return DecryptOutcome.failure(Status.UNKNOWN_GENERATION);
        }
        try {
            byte[] shared = ecdh(generation.get().getPrivateKey(),
                    decodePublicKey(parsed.getEphemeralPublicKey()));
            byte[] aesKey = deriveAesKey(payeeId, shared);
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, AES),
                    new GCMParameterSpec(TAG_BITS, parsed.getIv()));
            cipher.updateAAD(parsed.getHeader());
            byte[] plain = cipher.doFinal(parsed.getCiphertext());
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(shared, (byte) 0);
            return DecryptOutcome.recovered(new String(plain, StandardCharsets.UTF_8),
                    parsed.getKeyGenId());
        } catch (Exception e) {
            return DecryptOutcome.failure(Status.DECRYPTION_FAILED);
        }
    }

    private static byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance(XDH);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    private static byte[] deriveAesKey(String payeeId, byte[] sharedSecret) {
        byte[] info = concat(HKDF_INFO_PREFIX, payeeId.getBytes(StandardCharsets.UTF_8));
        return Hkdf.deriveKey(HKDF_SALT, sharedSecret, info, AES_KEY_LEN);
    }

    private static byte[] buildAad(String payeeId, long keyGenId, byte[] ephemeralPublic) {
        return Envelope.encode(payeeId, keyGenId, ephemeralPublic, new byte[0], new byte[0]);
    }

    private static byte[] rawX25519PublicKey(PublicKey publicKey) {
        byte[] spki = publicKey.getEncoded();
        byte[] raw = new byte[Envelope.EPHEMERAL_KEY_LEN];
        System.arraycopy(spki, spki.length - raw.length, raw, 0, raw.length);
        return raw;
    }

    private static PublicKey decodePublicKey(byte[] raw) throws Exception {
        KeyFactory factory = KeyFactory.getInstance(XDH);
        byte[] spki = new byte[X25519_SPKI_PREFIX.length + raw.length];
        System.arraycopy(X25519_SPKI_PREFIX, 0, spki, 0, X25519_SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, X25519_SPKI_PREFIX.length, raw.length);
        return factory.generatePublic(new X509EncodedKeySpec(spki));
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public enum Status {
        RECOVERED,
        NOT_FOR_PAYEE,
        MALFORMED,
        UNKNOWN_GENERATION,
        DECRYPTION_FAILED
    }

    public static final class DecryptOutcome {
        private final Status status;
        private final String plaintext;
        private final long keyGenId;

        public DecryptOutcome(Status status, String plaintext, long keyGenId) {
            this.status = status;
            this.plaintext = plaintext;
            this.keyGenId = keyGenId;
        }

        public static DecryptOutcome recovered(String plaintext, long keyGenId) {
            return new DecryptOutcome(Status.RECOVERED, plaintext, keyGenId);
        }

        public static DecryptOutcome failure(Status status) {
            return new DecryptOutcome(status, null, -1);
        }

        public Status getStatus() {
            return status;
        }

        public String getPlaintext() {
            return plaintext;
        }

        public long getKeyGenId() {
            return keyGenId;
        }
    }
}
