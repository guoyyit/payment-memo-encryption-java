package com.github.guoyyit.paymentmemoencryptionjava.scan;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Persistent scan position: the seq of the last fully processed transfer.
 * Written atomically after each transfer so a crash can resume from the
 * last committed position.
 */
public class ScanCheckpoint {

    private static final ObjectMapper JSON = new ObjectMapper();

    private String payeeId;
    private long lastSeq;

    public ScanCheckpoint() {
    }

    public ScanCheckpoint(String payeeId, long lastSeq) {
        this.payeeId = payeeId;
        this.lastSeq = lastSeq;
    }

    public String getPayeeId() {
        return payeeId;
    }

    public void setPayeeId(String payeeId) {
        this.payeeId = payeeId;
    }

    public long getLastSeq() {
        return lastSeq;
    }

    public void setLastSeq(long lastSeq) {
        this.lastSeq = lastSeq;
    }

    /**
     * Atomically persists this checkpoint.
     */
    public void save(Path file) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = Files.createTempFile(parent, "checkpoint-", ".tmp");
            Files.writeString(tmp, JSON.writeValueAsString(Map.of(
                    "payeeId", payeeId,
                    "lastSeq", lastSeq)));
            try {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to save checkpoint to " + file, e);
        }
    }

    /**
     * Loads a checkpoint, returning a fresh one (lastSeq = 0) when absent.
     */
    public static ScanCheckpoint load(Path file, String payeeId) {
        if (!Files.exists(file)) {
            return new ScanCheckpoint(payeeId, 0L);
        }
        try {
            Map<?, ?> doc = JSON.readValue(Files.readString(file), Map.class);
            return new ScanCheckpoint(
                    (String) doc.get("payeeId"),
                    ((Number) doc.get("lastSeq")).longValue());
        } catch (IOException e) {
            throw new IllegalStateException("failed to load checkpoint from " + file, e);
        }
    }
}
