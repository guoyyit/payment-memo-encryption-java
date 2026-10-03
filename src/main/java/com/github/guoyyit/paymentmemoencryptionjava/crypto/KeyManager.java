package com.github.guoyyit.paymentmemoencryptionjava.crypto;

import com.github.guoyyit.paymentmemoencryptionjava.recovery.RecoveryMaterial;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class KeyManager {

    static final int SECRET_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();
    private final ConcurrentMap<String, NavigableMap<Integer, byte[]>> keysByRecipient =
            new ConcurrentHashMap<>();

    public KeyManager() {
    }

    public String createRecipient() {
        String recipientId = java.util.UUID.randomUUID().toString();
        NavigableMap<Integer, byte[]> generations = new TreeMap<>();
        generations.put(1, newSecret());
        keysByRecipient.put(recipientId, generations);
        return recipientId;
    }

    public int rotate(String recipientId) {
        NavigableMap<Integer, byte[]> generations = requireRecipient(recipientId);
        synchronized (generations) {
            int nextGeneration = generations.lastKey() + 1;
            generations.put(nextGeneration, newSecret());
            return nextGeneration;
        }
    }

    public KeyGeneration currentKey(String recipientId) {
        NavigableMap<Integer, byte[]> generations = requireRecipient(recipientId);
        synchronized (generations) {
            Map.Entry<Integer, byte[]> last = generations.lastEntry();
            return new KeyGeneration(recipientId, last.getKey(), last.getValue().clone());
        }
    }

    public KeyGeneration key(String recipientId, int generation) {
        NavigableMap<Integer, byte[]> generations = keysByRecipient.get(recipientId);
        if (generations == null) {
            return null;
        }
        synchronized (generations) {
            byte[] secret = generations.get(generation);
            return secret == null
                    ? null
                    : new KeyGeneration(recipientId, generation, secret.clone());
        }
    }

    public RecoveryMaterial exportRecoveryMaterial() {
        List<KeyGeneration> snapshot = new ArrayList<>();
        for (Map.Entry<String, NavigableMap<Integer, byte[]>> recipient : keysByRecipient.entrySet()) {
            NavigableMap<Integer, byte[]> generations = recipient.getValue();
            synchronized (generations) {
                for (Map.Entry<Integer, byte[]> entry : generations.entrySet()) {
                    snapshot.add(new KeyGeneration(
                            recipient.getKey(), entry.getKey(), entry.getValue().clone()));
                }
            }
        }
        return new RecoveryMaterial(List.copyOf(snapshot));
    }

    public void importRecoveryMaterial(RecoveryMaterial material) {
        for (KeyGeneration keyGeneration : material.keys()) {
            NavigableMap<Integer, byte[]> generations =
                    keysByRecipient.computeIfAbsent(keyGeneration.recipientId(), ignored -> new TreeMap<>());
            synchronized (generations) {
                generations.putIfAbsent(keyGeneration.generation(), keyGeneration.secret().clone());
            }
        }
    }

    private NavigableMap<Integer, byte[]> requireRecipient(String recipientId) {
        NavigableMap<Integer, byte[]> generations = keysByRecipient.get(recipientId);
        if (generations == null) {
            throw new IllegalArgumentException("Unknown recipient: " + recipientId);
        }
        return generations;
    }

    private byte[] newSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        secureRandom.nextBytes(secret);
        return secret;
    }
}
