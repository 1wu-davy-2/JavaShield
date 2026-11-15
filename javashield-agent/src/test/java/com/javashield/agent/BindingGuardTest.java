package com.javashield.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;
import com.javashield.core.license.LicensePayload;

class BindingGuardTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String BUILD_ID = "0123456789abcdef";
    private static final byte[] BUILD_KEY = new byte[32];

    @TempDir
    Path temp;

    private String previousBinding;
    private Path persistentDir;
    private Path persistentFile;

    @BeforeEach
    void preparePaths() {
        previousBinding = System.getProperty("jshield.binding");
        persistentDir = Paths.get("target", "binding-test",
                UUID.randomUUID().toString()).toAbsolutePath();
        persistentFile = persistentDir.resolve("binding.json");
    }

    @AfterEach
    void cleanup() throws Exception {
        restore("jshield.binding", previousBinding);
        Files.deleteIfExists(persistentFile);
        Files.deleteIfExists(persistentDir);
    }

    @Test
    void rejectsFirstRunBindingInTheSystemTempDirectory() {
        System.setProperty("jshield.binding", temp.resolve("binding.json").toString());

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> BindingGuard.enforce(Paths.get("app.jar"), payload()));
        assertTrue(exc.getMessage().contains("temporary"));
    }

    @Test
    void writesAndReusesAPersistentBinding() throws Exception {
        System.setProperty("jshield.binding", persistentFile.toString());
        BindingGuard.enforce(Paths.get("app.jar"), payload());

        assertTrue(Files.isRegularFile(persistentFile));
        BindingGuard.enforce(Paths.get("app.jar"), payload());

        Map<String, Object> record = Json.parseObject(
                new String(Files.readAllBytes(persistentFile), UTF_8));
        assertEquals(BUILD_ID, String.valueOf(record.get("build_id")));
    }

    @Test
    void rejectsAModifiedRecord() throws Exception {
        System.setProperty("jshield.binding", persistentFile.toString());
        BindingGuard.enforce(Paths.get("app.jar"), payload());

        Map<String, Object> record = Json.parseObject(
                new String(Files.readAllBytes(persistentFile), UTF_8));
        record.put("mac", "00");
        Files.write(persistentFile, (Json.pretty(record) + "\n").getBytes(UTF_8));

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> BindingGuard.enforce(Paths.get("app.jar"), payload()));
        assertTrue(exc.getMessage().contains("modified"));
    }

    @Test
    void rejectsARecordForAnotherMachine() throws Exception {
        System.setProperty("jshield.binding", persistentFile.toString());
        String otherMachine = "ffffffffffffffffffffffffffffffff";
        writeRecord(BUILD_ID, otherMachine);

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> BindingGuard.enforce(Paths.get("app.jar"), payload()));
        assertTrue(exc.getMessage().contains("another machine"));
    }

    @Test
    void rejectsARecordForAnotherBuild() throws Exception {
        System.setProperty("jshield.binding", persistentFile.toString());
        writeRecord("another-build", "ffffffffffffffffffffffffffffffff");

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> BindingGuard.enforce(Paths.get("app.jar"), payload()));
        assertTrue(exc.getMessage().contains("another build"));
    }

    private void writeRecord(String buildId, String fingerprint) throws Exception {
        String boundAt = "2026-11-15T00:00:00Z";
        byte[] key = Envelope.hkdf(BUILD_KEY, "jshield-binding-v1".getBytes(UTF_8),
                BUILD_ID.getBytes(UTF_8), 32);
        String mac = Hex.encode(Envelope.hmacSha256(key,
                (buildId + "|" + fingerprint + "|" + boundAt).getBytes(UTF_8)));
        Map<String, Object> record = new LinkedHashMap<String, Object>();
        record.put("build_id", buildId);
        record.put("fingerprint", fingerprint);
        record.put("bound_at", boundAt);
        record.put("mac", mac);
        Files.createDirectories(persistentDir);
        Files.write(persistentFile, (Json.pretty(record) + "\n").getBytes(UTF_8));
    }

    private LicensePayload payload() {
        LicensePayload payload = new LicensePayload();
        payload.setBuildId(BUILD_ID);
        payload.setBuildKey(BUILD_KEY);
        payload.setBindFirstRun(true);
        return payload;
    }

    private static void restore(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }
}
