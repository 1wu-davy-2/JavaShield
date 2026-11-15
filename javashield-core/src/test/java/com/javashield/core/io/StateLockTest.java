package com.javashield.core.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StateLockTest {

    @TempDir
    Path temp;

    @Test
    void serializesThreadsAndCreatesParentDirectories() throws Exception {
        Path lock = temp.resolve("nested").resolve("state.lock");
        AtomicInteger inside = new AtomicInteger();
        AtomicInteger maximum = new AtomicInteger();
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    StateLock.withLock(lock, 5000L, new StateLock.Action<Void>() {
                        @Override
                        public Void run() throws IOException {
                            int current = inside.incrementAndGet();
                            maximum.accumulateAndGet(current, Math::max);
                            try {
                                Thread.sleep(120L);
                            } catch (InterruptedException exc) {
                                Thread.currentThread().interrupt();
                            }
                            inside.decrementAndGet();
                            return null;
                        }
                    });
                } catch (IOException exc) {
                    throw new IllegalStateException(exc);
                }
            }
        };
        Thread first = new Thread(task);
        Thread second = new Thread(task);
        first.start();
        second.start();
        first.join(5000L);
        second.join(5000L);
        assertEquals(1, maximum.get());
        assertTrue(Files.isRegularFile(lock));
    }

    @Test
    void returnsTheActionValue() throws Exception {
        String value = StateLock.withLock(temp.resolve("state.lock"), 1000L,
                new StateLock.Action<String>() {
                    @Override
                    public String run() {
                        return "ok";
                    }
                });
        assertEquals("ok", value);
    }

    @Test
    void timesOutWhenTheFileLockIsHeld() throws Exception {
        Path lock = temp.resolve("state.lock");
        try (FileChannel channel = FileChannel.open(lock, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE);
             FileLock held = channel.lock()) {
            assertThrows(IOException.class, () -> StateLock.withLock(lock, 150L,
                    new StateLock.Action<Void>() {
                        @Override
                        public Void run() {
                            return null;
                        }
                    }));
        }
    }
}
