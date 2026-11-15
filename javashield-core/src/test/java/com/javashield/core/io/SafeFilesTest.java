package com.javashield.core.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SafeFilesTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    @TempDir
    Path temp;

    @Test
    void readsAndReplacesFiles() throws Exception {
        Path source = temp.resolve("source.tmp");
        Path target = temp.resolve("target.txt");
        Files.write(source, "new".getBytes(UTF_8));
        Files.write(target, "old".getBytes(UTF_8));

        SafeFiles.fsync(source);
        SafeFiles.move(source, target);

        assertArrayEquals("new".getBytes(UTF_8), SafeFiles.readAllBytes(target));
        assertEquals(false, Files.exists(source));
    }

    @Test
    void missingFileIsNotRetried() {
        assertThrows(NoSuchFileException.class,
                () -> SafeFiles.readAllBytes(temp.resolve("missing.txt")));
    }
}
