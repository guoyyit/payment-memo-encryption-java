package com.github.guoyyit.paymentmemoencryptionjava.stream;

import com.github.guoyyit.paymentmemoencryptionjava.domain.EncryptedMemo;
import com.github.guoyyit.paymentmemoencryptionjava.domain.Transfer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Durable, append-only transfer stream backed by one JSON object per line.
 *
 * <p>Each successful {@link #append} is forced to disk before it returns, so committed
 * transfers are immediately durable. A monotonically increasing sequence number and the
 * physical byte offset of each line define a stable, order-preserving scan position that
 * tolerates out-of-order or late arriving readers. {@code requestId} makes submission
 * idempotent: resubmitting the same request returns the original transfer instead of
 * appending another one.
 */
public class TransferLog {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path file;
    private final ReentrantLock appendLock = new ReentrantLock();
    private final Map<String, TransferLocation> locationByRequestId = new HashMap<>();
    private long nextSequence;
    private long nextOffset;

    private record TransferLocation(long sequence, long offset) {
    }

    public TransferLog(Path file) {
        this.file = file;
        recover();
    }

    public Transfer append(String requestId, List<EncryptedMemo> memos) {
        appendLock.lock();
        try {
            TransferLocation existing = locationByRequestId.get(requestId);
            if (existing != null) {
                List<Transfer> slice = readSlice(existing.offset(), 1).transfers();
                if (slice.size() != 1 || !samePayload(slice.get(0), memos)) {
                    throw new IllegalStateException(
                            "requestId " + requestId + " already used with different content");
                }
                return slice.get(0);
            }

            long sequence = nextSequence + 1;
            long offset = nextOffset;
            byte[] line = MAPPER.writeValueAsString(Map.of(
                    "seq", sequence,
                    "requestId", requestId,
                    "memos", List.copyOf(memos))).getBytes(StandardCharsets.UTF_8);

            try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
                raf.seek(offset);
                raf.write(line);
                raf.write('\n');
                raf.getFD().sync();
            }

            nextSequence = sequence;
            nextOffset = offset + line.length + 1;
            locationByRequestId.put(requestId, new TransferLocation(sequence, offset));
            return new Transfer(sequence, requestId, List.copyOf(memos));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to append transfer", e);
        } finally {
            appendLock.unlock();
        }
    }

    public Optional<Transfer> findByRequestId(String requestId) {
        TransferLocation location = locationByRequestId.get(requestId);
        if (location == null) {
            return Optional.empty();
        }
        return Optional.of(readSlice(location.offset(), 1).transfers().get(0));
    }

    public LogSlice readSlice(long offset, int maxTransfers) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ);
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                        Channels.newInputStream(channel.position(offset)), StandardCharsets.UTF_8))) {
            List<Transfer> transfers = new ArrayList<>();
            long currentOffset = offset;
            String line;
            while (transfers.size() < maxTransfers && (line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    transfers.add(deserialize(line));
                }
                currentOffset += line.getBytes(StandardCharsets.UTF_8).length + 1L;
            }
            return new LogSlice(List.copyOf(transfers), currentOffset);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read transfer log", e);
        }
    }

    public long nextSequence() {
        return nextSequence;
    }

    public long lengthBytes() {
        appendLock.lock();
        try {
            return nextOffset;
        } finally {
            appendLock.unlock();
        }
    }

    private void recover() {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            if (Files.notExists(file)) {
                Files.createFile(file);
                return;
            }

            long validLength = 0;
            long sequence = 0;
            try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isBlank()) {
                        continue;
                    }
                    Transfer transfer = deserialize(line);
                    sequence = transfer.sequence();
                    long lineOffset = validLength;
                    validLength += line.getBytes(StandardCharsets.UTF_8).length + 1L;
                    locationByRequestId.put(transfer.requestId(),
                            new TransferLocation(transfer.sequence(), lineOffset));
                }
            } catch (IllegalStateException parseFailure) {
                try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
                    raf.setLength(validLength);
                    raf.getFD().sync();
                }
            }
            nextSequence = sequence;
            nextOffset = validLength;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to recover transfer log", e);
        }
    }

    private static Transfer deserialize(String line) {
        try {
            JsonNode root = MAPPER.readTree(line);
            long sequence = root.get("seq").asLong();
            String requestId = root.get("requestId").asText();
            List<EncryptedMemo> memos = new ArrayList<>();
            for (JsonNode memoNode : root.get("memos")) {
                memos.add(MAPPER.treeToValue(memoNode, EncryptedMemo.class));
            }
            return new Transfer(sequence, requestId, List.copyOf(memos));
        } catch (IOException e) {
            throw new IllegalStateException("Corrupt transfer log record", e);
        }
    }

    private static boolean samePayload(Transfer transfer, List<EncryptedMemo> memos) {
        return transfer.memos().equals(List.copyOf(memos));
    }
}
