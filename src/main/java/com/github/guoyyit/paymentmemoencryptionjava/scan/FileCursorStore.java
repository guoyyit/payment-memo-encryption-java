package com.github.guoyyit.paymentmemoencryptionjava.scan;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Persists one scan cursor per recipient as a small file containing
 * {@code nextSequence,nextOffset}. Writes go to a temporary file, are forced to disk and
 * then atomically renamed, so a crash leaves either the old or the new committed
 * position, never a torn one.
 */
public class FileCursorStore implements CursorStore {

    private static final String FILE_SUFFIX = ".cursor";

    private final Path directory;

    public FileCursorStore(Path directory) {
        this.directory = directory;
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create cursor directory", e);
        }
    }

    @Override
    public ScanPosition load(String recipientId) {
        Path cursorFile = cursorFile(recipientId);
        if (Files.notExists(cursorFile)) {
            return ScanPosition.start();
        }
        try {
            String content = Files.readString(cursorFile, StandardCharsets.UTF_8).trim();
            String[] parts = content.split(",");
            if (parts.length != 2) {
                throw new IllegalStateException("Corrupt cursor for recipient: " + recipientId);
            }
            return new ScanPosition(Long.parseLong(parts[0]), Long.parseLong(parts[1]));
        } catch (IOException | NumberFormatException e) {
            throw new IllegalStateException("Failed to load cursor for recipient: " + recipientId, e);
        }
    }

    @Override
    public void store(String recipientId, ScanPosition position) {
        Path cursorFile = cursorFile(recipientId);
        Path tempFile = directory.resolve(cursorFile.getFileName() + ".tmp");
        try (RandomAccessFile raf = new RandomAccessFile(tempFile.toFile(), "rw")) {
            raf.setLength(0);
            raf.write((position.nextSequence() + "," + position.nextOffset())
                    .getBytes(StandardCharsets.UTF_8));
            raf.getFD().sync();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to persist cursor for recipient: " + recipientId, e);
        }
        try {
            Files.move(tempFile, cursorFile,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to commit cursor for recipient: " + recipientId, e);
        }
    }

    private Path cursorFile(String recipientId) {
        String safeName = recipientId.replaceAll("[^A-Za-z0-9_-]", "_");
        return directory.resolve(safeName + FILE_SUFFIX);
    }
}
