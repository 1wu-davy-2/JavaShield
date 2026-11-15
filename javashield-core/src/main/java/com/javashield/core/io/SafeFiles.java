package com.javashield.core.io;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * File helpers for small local state files.
 *
 * <p>Windows can report a sharing violation while an antivirus scanner, indexer
 * or another JVM briefly holds the target open. These operations retry those
 * transient failures, and every replacement is staged through a unique temp
 * file so a crash cannot leave a truncated state document.</p>
 */
public final class SafeFiles {

    private static final int ATTEMPTS = 20;
    private static final long RETRY_MILLIS = 10L;

    private SafeFiles() {
    }

    /** Reads a state file, retrying transient sharing violations. */
    public static byte[] readAllBytes(Path file) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                return Files.readAllBytes(file);
            } catch (NoSuchFileException exc) {
                throw exc;
            } catch (IOException exc) {
                if (attempt >= ATTEMPTS || !transientFailure(exc)) {
                    throw exc;
                }
                sleep(attempt);
            }
        }
    }

    /** Replaces {@code target} with {@code source}, retrying transient failures. */
    public static void move(Path source, Path target) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                try {
                    Files.move(source, target, StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException exc) {
                    Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
                }
                return;
            } catch (IOException exc) {
                if (attempt >= ATTEMPTS || !transientFailure(exc)) {
                    throw exc;
                }
                sleep(attempt);
            }
        }
    }

    /** Flushes a freshly written temp file before it is published. */
    public static void fsync(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static boolean transientFailure(IOException exc) {
        return !(exc instanceof NoSuchFileException)
                && !(exc instanceof AtomicMoveNotSupportedException);
    }

    private static void sleep(int attempt) throws IOException {
        try {
            Thread.sleep(Math.min(RETRY_MILLIS * attempt, 150L));
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while retrying a state file operation", exc);
        }
    }
}
