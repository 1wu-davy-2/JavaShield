package com.javashield.core.io;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Serializes a local state read-modify-write across threads and processes.
 *
 * <p>{@link FileChannel#tryLock()} is advisory but sufficient for cooperating
 * JavaShield processes sharing one state directory. A JVM-local lock is taken
 * first so two threads in the same JVM do not fight over the same file lock.
 * If the lock cannot be created (for example, a read-only deployment), callers
 * decide whether to continue unlocked or fail closed.</p>
 */
public final class StateLock {

    public static final long DEFAULT_TIMEOUT_MILLIS = 5000L;
    private static final long RETRY_MILLIS = 20L;
    private static final ConcurrentMap<Path, ReentrantLock> LOCAL_LOCKS =
            new ConcurrentHashMap<Path, ReentrantLock>();

    /** Work executed while holding the state lock. */
    public interface Action<T> {
        T run() throws IOException;
    }

    private StateLock() {
    }

    /**
     * Runs {@code action} while holding an exclusive lock on {@code lockFile}.
     *
     * @throws IOException when the lock cannot be created or is not acquired
     *                     within {@code timeoutMillis}
     */
    public static <T> T withLock(Path lockFile, long timeoutMillis, Action<T> action)
            throws IOException {
        if (lockFile == null || action == null) {
            throw new IllegalArgumentException("lock file and action are required");
        }
        Path path = lockFile.toAbsolutePath().normalize();
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        long timeout = Math.max(1L, timeoutMillis);
        ReentrantLock local = localLock(path);
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout);
        boolean acquired;
        try {
            acquired = local.tryLock(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while waiting for state lock: " + path, exc);
        }
        if (!acquired) {
            throw new IOException("timed out waiting for state lock: " + path);
        }
        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            FileLock fileLock = acquire(channel, path, deadline);
            try {
                return action.run();
            } finally {
                release(fileLock);
            }
        } finally {
            local.unlock();
        }
    }

    private static ReentrantLock localLock(Path path) {
        ReentrantLock candidate = new ReentrantLock();
        ReentrantLock existing = LOCAL_LOCKS.putIfAbsent(path, candidate);
        return existing == null ? candidate : existing;
    }

    private static FileLock acquire(FileChannel channel, Path path, long deadline)
            throws IOException {
        while (true) {
            try {
                FileLock lock = channel.tryLock();
                if (lock != null) {
                    return lock;
                }
            } catch (OverlappingFileLockException exc) {
                // Another channel in this JVM owns the file lock; wait for it.
            }
            if (System.nanoTime() >= deadline) {
                throw new IOException("timed out waiting for state lock: " + path);
            }
            sleep();
        }
    }

    private static void release(FileLock lock) {
        if (lock == null) {
            return;
        }
        try {
            lock.release();
        } catch (IOException ignored) {
            // The channel close releases the lock as a fallback.
        }
    }

    private static void sleep() throws IOException {
        try {
            Thread.sleep(RETRY_MILLIS);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while waiting for state lock", exc);
        }
    }
}
