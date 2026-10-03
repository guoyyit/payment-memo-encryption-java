package com.github.guoyyit.paymentmemoencryptionjava.keystore;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Holds all key generations of a single payee. Generations are monotonically
 * numbered; rotation retires the previously active generation but keeps its
 * private key so historical memos remain recoverable.
 *
 * <p>Persistence uses a small JSON file. Export material is encrypted with a
 * password-derived key (PBKDF2-HMAC-SHA256 then AES-GCM).
 */
public class PayeeKeyStore {

    private static final String XDH = "XDH";
    private static final String EXPORT_CIPHER = "AES/GCM/NoPadding";
    private static final int EXPORT_TAG_BITS = 128;
    private static final int EXPORT_IV_LEN = 12;
    private static final int EXPORT_SALT_LEN = 16;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PBKDF2_KEY_LEN = 256;
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final String payeeId;
    private final List<KeyGeneration> generations = new ArrayList<>();
    private long nextGenId = 1;

    public PayeeKeyStore(String payeeId) {
        this.payeeId = payeeId;
    }

    public String getPayeeId() {
        return payeeId;
    }

    public List<KeyGeneration> getGenerations() {
        return List.copyOf(generations);
    }

    /**
     * Creates a new active generation, retiring the previous one.
     */
    public synchronized KeyGeneration rotate() {
        for (KeyGeneration generation : generations) {
            if (generation.getStatus() == KeyGeneration.Status.ACTIVE) {
                generation.setStatus(KeyGeneration.Status.RETIRED);
            }
        }
        KeyPair pair = MemoCryptoAccess.generateX25519KeyPair();
        KeyGeneration generation = new KeyGeneration();
        generation.setGenId(nextGenId++);
        generation.setPublicKey(pair.getPublic());
        generation.setPrivateKey(pair.getPrivate());
        generation.setStatus(KeyGeneration.Status.ACTIVE);
        generation.setCreatedAt(Instant.now());
        generations.add(generation);
        return generation;
    }

    public synchronized Optional<KeyGeneration> findGeneration(long genId) {
        return generations.stream()
                .filter(g -> g.getGenId() == genId)
                .findFirst();
    }

    public synchronized KeyGeneration getActive() {
        return generations.stream()
                .filter(g -> g.getStatus() == KeyGeneration.Status.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("no active key generation"));
    }

    /**
     * Persists this store to a JSON file (atomic replace).
     */
    public synchronized void save(Path file) {
        try {
            List<StoredGeneration> stored = generations.stream()
                    .sorted(Comparator.comparingLong(KeyGeneration::getGenId))
                    .map(StoredGeneration::from)
                    .toList();
            Map<String, Object> doc = Map.of(
                    "payeeId", payeeId,
                    "nextGenId", nextGenId,
                    "generations", stored);
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = Files.createTempFile(parent, "keystore-", ".tmp");
            Files.writeString(tmp, JSON.writeValueAsString(doc));
            try {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception e) {
            throw new IllegalStateException("failed to save key store to " + file, e);
        }
    }

    /**
     * Loads a store previously written by {@link #save(Path)}.
     */
    @SuppressWarnings("unchecked")
    public static PayeeKeyStore load(Path file) {
        try {
            Map<String, Object> doc = JSON.readValue(Files.readString(file), Map.class);
            PayeeKeyStore store = new PayeeKeyStore((String) doc.get("payeeId"));
            store.nextGenId = ((Number) doc.get("nextGenId")).longValue();
            KeyFactory keyFactory = KeyFactory.getInstance(XDH);
            for (Map<String, Object> raw : (List<Map<String, Object>>) doc.get("generations")) {
                StoredGeneration stored = JSON.convertValue(raw, StoredGeneration.class);
                KeyGeneration generation = stored.toKeyGeneration(keyFactory);
                store.generations.add(generation);
            }
            return store;
        } catch (Exception e) {
            throw new IllegalStateException("failed to load key store from " + file, e);
        }
    }

    /**
     * Exports all generations encrypted with a password-derived key.
     * Bundle layout: salt(16) || iv(12) || AES-GCM(ciphertext).
     */
    public synchronized byte[] exportEncrypted(char[] password) {
        try {
            List<StoredGeneration> stored = generations.stream()
                    .sorted(Comparator.comparingLong(KeyGeneration::getGenId))
                    .map(StoredGeneration::from)
                    .toList();
            byte[] plain = JSON.writeValueAsBytes(Map.of(
                    "payeeId", payeeId,
                    "nextGenId", nextGenId,
                    "generations", stored));

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[EXPORT_SALT_LEN];
            random.nextBytes(salt);
            byte[] iv = new byte[EXPORT_IV_LEN];
            random.nextBytes(iv);
            SecretKeySpec key = deriveExportKey(password, salt);

            Cipher cipher = Cipher.getInstance(EXPORT_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(EXPORT_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plain);

            byte[] bundle = new byte[salt.length + iv.length + ciphertext.length];
            System.arraycopy(salt, 0, bundle, 0, salt.length);
            System.arraycopy(iv, 0, bundle, salt.length, iv.length);
            System.arraycopy(ciphertext, 0, bundle, salt.length + iv.length, ciphertext.length);
            return bundle;
        } catch (Exception e) {
            throw new IllegalStateException("failed to export key store", e);
        }
    }

    /**
     * Imports a bundle produced by {@link #exportEncrypted(char[])}.
     */
    @SuppressWarnings("unchecked")
    public static PayeeKeyStore importEncrypted(byte[] bundle, char[] password) {
        try {
            if (bundle.length < EXPORT_SALT_LEN + EXPORT_IV_LEN + 1) {
                throw new IllegalArgumentException("export bundle truncated");
            }
            byte[] salt = new byte[EXPORT_SALT_LEN];
            byte[] iv = new byte[EXPORT_IV_LEN];
            System.arraycopy(bundle, 0, salt, 0, EXPORT_SALT_LEN);
            System.arraycopy(bundle, EXPORT_SALT_LEN, iv, 0, EXPORT_IV_LEN);
            int cipherLen = bundle.length - EXPORT_SALT_LEN - EXPORT_IV_LEN;
            byte[] ciphertext = new byte[cipherLen];
            System.arraycopy(bundle, EXPORT_SALT_LEN + EXPORT_IV_LEN, ciphertext, 0, cipherLen);

            SecretKeySpec key = deriveExportKey(password, salt);
            Cipher cipher = Cipher.getInstance(EXPORT_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(EXPORT_TAG_BITS, iv));
            byte[] plain = cipher.doFinal(ciphertext);

            Map<String, Object> doc = JSON.readValue(plain, Map.class);
            PayeeKeyStore store = new PayeeKeyStore((String) doc.get("payeeId"));
            store.nextGenId = ((Number) doc.get("nextGenId")).longValue();
            KeyFactory keyFactory = KeyFactory.getInstance(XDH);
            for (Map<String, Object> raw : (List<Map<String, Object>>) doc.get("generations")) {
                StoredGeneration stored = JSON.convertValue(raw, StoredGeneration.class);
                store.generations.add(stored.toKeyGeneration(keyFactory));
            }
            return store;
        } catch (Exception e) {
            throw new IllegalArgumentException("failed to import key store (wrong password or corrupt bundle)", e);
        }
    }

    private static SecretKeySpec deriveExportKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        var spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * JSON-friendly view of a key generation.
     */
    public static final class StoredGeneration {
        public long genId;
        public String publicKey;
        public String privateKey;
        public String status;
        public long createdAt;

        static StoredGeneration from(KeyGeneration generation) {
            StoredGeneration stored = new StoredGeneration();
            stored.genId = generation.getGenId();
            stored.publicKey = Base64.getEncoder().encodeToString(generation.getPublicKey().getEncoded());
            stored.privateKey = Base64.getEncoder().encodeToString(generation.getPrivateKey().getEncoded());
            stored.status = generation.getStatus().name();
            stored.createdAt = generation.getCreatedAt().toEpochMilli();
            return stored;
        }

        KeyGeneration toKeyGeneration(KeyFactory keyFactory) throws Exception {
            PublicKey pub = keyFactory.generatePublic(new X509EncodedKeySpec(
                    Base64.getDecoder().decode(publicKey)));
            PrivateKey priv = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(privateKey)));
            KeyGeneration generation = new KeyGeneration();
            generation.setGenId(genId);
            generation.setPublicKey(pub);
            generation.setPrivateKey(priv);
            generation.setStatus(KeyGeneration.Status.valueOf(status));
            generation.setCreatedAt(Instant.ofEpochMilli(createdAt));
            return generation;
        }
    }

    /**
     * Indirection to avoid a compile-time dependency cycle: key generation
     * uses the same X25519 support as memo encryption.
     */
    private static final class MemoCryptoAccess {
        static KeyPair generateX25519KeyPair() {
            return com.github.guoyyit.paymentmemoencryptionjava.crypto.MemoCrypto.generateX25519KeyPair();
        }
    }
}
