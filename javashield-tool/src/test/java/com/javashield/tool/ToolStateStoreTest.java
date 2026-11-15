package com.javashield.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ToolStateStoreTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    @TempDir
    Path temp;

    @Test
    void sealedStateRoundTrips() {
        ToolStateStore store = new ToolStateStore(temp, "machine-a");
        Path file = store.resolve("quota.json");

        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("used", Long.valueOf(2));
        payload.put("month", "2026-11");
        store.writeSealed(file, "quota", payload);

        Map<String, Object> decoded = store.readSealed(file, "quota");
        assertEquals(2L, ((Number) decoded.get("used")).longValue());
        assertEquals("2026-11", decoded.get("month"));
    }

    @Test
    void missingStateReturnsNull() {
        ToolStateStore store = new ToolStateStore(temp, "machine-a");
        assertNull(store.readSealed(store.resolve("missing.json"), "quota"));
    }

    @Test
    void tamperedPayloadIsRejected() throws Exception {
        ToolStateStore store = new ToolStateStore(temp, "machine-a");
        Path file = store.resolve("quota.json");
        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("used", Long.valueOf(2));
        store.writeSealed(file, "quota", payload);

        String text = new String(Files.readAllBytes(file), UTF_8);
        String changed = text.replace("\"used\": 2", "\"used\": 0");
        assertTrue(!changed.equals(text), "the test did not modify the payload");
        Files.write(file, changed.getBytes(UTF_8));

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> store.readSealed(file, "quota"));
        assertEquals(ToolCodes.STATE_INVALID, exc.getCode());
    }

    @Test
    void nonRegularStateIsRejected() throws Exception {
        ToolStateStore store = new ToolStateStore(temp, "machine-a");
        Path file = store.resolve("quota.json");
        Files.createDirectories(file);

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> store.readSealed(file, "quota"));
        assertEquals(ToolCodes.STATE_INVALID, exc.getCode());
    }

    @Test
    void stateIsBoundToItsPurpose() {
        ToolStateStore store = new ToolStateStore(temp, "machine-a");
        Path file = store.resolve("quota.json");
        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("used", Long.valueOf(1));
        store.writeSealed(file, "quota", payload);

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> store.readSealed(file, "trial"));
        assertEquals(ToolCodes.STATE_INVALID, exc.getCode());
    }
}
