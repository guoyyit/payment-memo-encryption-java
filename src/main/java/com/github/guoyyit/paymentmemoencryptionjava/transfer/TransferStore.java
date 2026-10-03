package com.github.guoyyit.paymentmemoencryptionjava.transfer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Persistent transfer log placeholder.
 */
public class TransferStore {

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final Path dataDir;
    private final Path transfersDir;
    private final Path requestsDir;
    private long nextSeq;

    public TransferStore(Path dataDir) {
        this.dataDir = dataDir;
        this.transfersDir = dataDir.resolve("transfers");
        this.requestsDir = dataDir.resolve("requests");
        try {
            Files.createDirectories(transfersDir);
            Files.createDirectories(requestsDir);
            this.nextSeq = loadMaxSeq() + 1;
            recover();
        } catch (IOException e) {
            throw new IllegalStateException("failed to initialize transfer store at " + dataDir, e);
        }
    }

    /**
     * Commits a transfer. Idempotent on {@code requestId}.
     */
    public synchronized Transfer commit(Transfer transfer) {
        try {
            Path marker = requestsDir.resolve(transfer.getRequestId());
            if (Files.exists(marker)) {
                return readTransfer(marker);
            }
            long seq = nextSeq++;
            transfer.setSeq(seq);
            if (transfer.getTransferId() == null) {
                transfer.setTransferId(java.util.UUID.randomUUID().toString());
            }
            if (transfer.getCreatedAt() == null) {
                transfer.setCreatedAt(Instant.now());
            }
            byte[] json = JSON.writeValueAsBytes(toDoc(transfer));

            Path transferFile = transfersDir.resolve(seq + ".json");
            Path tmp = Files.createTempFile(transfersDir, seq + "-", ".tmp");
            Files.write(tmp, json);

            Path markerTmp = Files.createTempFile(requestsDir, "req-", ".tmp");
            Files.write(markerTmp, json);
            try {
                Files.move(markerTmp, marker, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.FileAlreadyExistsException e) {
                // Defensive: synchronized method prevents this within one JVM.
                Files.deleteIfExists(tmp);
                Files.deleteIfExists(markerTmp);
                return readTransfer(marker);
            }

            try {
                Files.move(tmp, transferFile, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, transferFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            return transfer;
        } catch (IOException e) {
            throw new IllegalStateException("failed to commit transfer " + transfer.getRequestId(), e);
        }
    }

    /**
     * Returns up to {@code batchSize} transfers with {@code seq > afterSeq},
     * in ascending seq order, stopping at the first gap.
     */
    public List<Transfer> poll(long afterSeq, int batchSize) {
        int limit = Math.max(1, batchSize);
        List<Path> files = listTransferFiles();
        List<Transfer> result = new ArrayList<>();
        long expected = afterSeq + 1;
        for (Path file : files) {
            long seq = parseSeq(file);
            if (seq <= afterSeq) {
                continue;
            }
            if (seq != expected) {
                break;
            }
            try {
                result.add(readTransfer(file));
            } catch (IOException e) {
                throw new IllegalStateException("failed to read transfer " + file, e);
            }
            expected++;
            if (result.size() >= limit) {
                break;
            }
        }
        return result;
    }

    /**
     * Returns the highest committed seq, or 0 when empty.
     */
    public long maxSeq() {
        return loadMaxSeq();
    }

    private void recover() throws IOException {
        try (var stream = Files.list(requestsDir)) {
            List<Path> markers = stream.filter(Files::isRegularFile).toList();
            for (Path marker : markers) {
                Transfer transfer = readTransfer(marker);
                Path transferFile = transfersDir.resolve(transfer.getSeq() + ".json");
                if (!Files.exists(transferFile)) {
                    Path tmp = Files.createTempFile(transfersDir, transfer.getSeq() + "-", ".tmp");
                    Files.write(tmp, JSON.writeValueAsBytes(toDoc(transfer)));
                    try {
                        Files.move(tmp, transferFile, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                    } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                        Files.move(tmp, transferFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }
    }

    private long loadMaxSeq() {
        long max = 0;
        for (Path file : listTransferFiles()) {
            max = Math.max(max, parseSeq(file));
        }
        return max;
    }

    private List<Path> listTransferFiles() {
        try (var stream = Files.list(transfersDir)) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().matches("\\d+\\.json"))
                    .sorted(Comparator.comparingLong(this::parseSeq))
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    private long parseSeq(Path file) {
        String name = file.getFileName().toString();
        return Long.parseLong(name.substring(0, name.length() - ".json".length()));
    }

    private Transfer readTransfer(Path file) throws IOException {
        Map<?, ?> doc = JSON.readValue(Files.readString(file), Map.class);
        return fromDoc(doc);
    }

    private Map<String, Object> toDoc(Transfer transfer) {
        List<Map<String, Object>> memoDocs = transfer.getMemos().stream()
                .map(m -> Map.<String, Object>of(
                        "index", m.getIndex(),
                        "envelope", Base64.getEncoder().encodeToString(m.getEnvelope())))
                .toList();
        return Map.of(
                "seq", transfer.getSeq(),
                "transferId", transfer.getTransferId(),
                "requestId", transfer.getRequestId(),
                "fromPayeeId", transfer.getFromPayeeId(),
                "toPayeeId", transfer.getToPayeeId(),
                "createdAt", transfer.getCreatedAt().toEpochMilli(),
                "memos", memoDocs);
    }

    @SuppressWarnings("unchecked")
    private Transfer fromDoc(Map<?, ?> doc) {
        Transfer transfer = new Transfer();
        transfer.setSeq(((Number) doc.get("seq")).longValue());
        transfer.setTransferId((String) doc.get("transferId"));
        transfer.setRequestId((String) doc.get("requestId"));
        transfer.setFromPayeeId((String) doc.get("fromPayeeId"));
        transfer.setToPayeeId((String) doc.get("toPayeeId"));
        transfer.setCreatedAt(Instant.ofEpochMilli(((Number) doc.get("createdAt")).longValue()));
        List<Map<String, Object>> memoDocs = (List<Map<String, Object>>) doc.get("memos");
        List<Memo> memos = new ArrayList<>();
        for (Map<String, Object> memoDoc : memoDocs) {
            Memo memo = new Memo();
            memo.setIndex(((Number) memoDoc.get("index")).intValue());
            memo.setEnvelope(Base64.getDecoder().decode((String) memoDoc.get("envelope")));
            memos.add(memo);
        }
        transfer.setMemos(memos);
        return transfer;
    }

    /**
     * Looks up a committed transfer by request id.
     */
    public Optional<Transfer> findByRequestId(String requestId) {
        Path marker = requestsDir.resolve(requestId);
        if (!Files.exists(marker)) {
            return Optional.empty();
        }
        try {
            return Optional.of(readTransfer(marker));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Removes all data (used by tests).
     */
    public void reset() {
        try {
            deleteRecursively(dataDir);
            Files.createDirectories(transfersDir);
            Files.createDirectories(requestsDir);
            nextSeq = 1;
        } catch (IOException e) {
            throw new IllegalStateException("failed to reset store", e);
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (var walk = Files.walk(path)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
        }
    }
}
