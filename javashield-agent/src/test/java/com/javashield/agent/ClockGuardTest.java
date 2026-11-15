package com.javashield.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;

class ClockGuardTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String BUILD_ID = "0123456789abcdef";
    private static final byte[] BUILD_KEY = new byte[32];
    private static final LocalDate TODAY = LocalDate.of(2026, 11, 15);

    @TempDir
    Path temp;

    private String previousStateDir;
    private String previousVolatile;

    @BeforeEach
    void configureStateDirectory() {
        previousStateDir = System.getProperty("jshield.state.dir");
        previousVolatile = System.getProperty("jshield.state.volatile");
        System.setProperty("jshield.state.dir", temp.toString());
        System.clearProperty("jshield.state.volatile");
    }

    @AfterEach
    void restoreProperties() {
        restore("jshield.state.dir", previousStateDir);
        restore("jshield.state.volatile", previousVolatile);
    }

    @Test
    void firstRunWritesBothCopies() {
        ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY);

        assertEquals(TODAY, readSeen(primary()));
        assertEquals(TODAY, readSeen(backup()));
    }

    @Test
    void mismatchedCopiesHealToTheNewerDate() throws Exception {
        writeState(primary(), TODAY.minusDays(1), true);
        writeState(backup(), TODAY, true);

        ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY);

        assertEquals(TODAY, readSeen(primary()));
        assertEquals(TODAY, readSeen(backup()));
    }

    @Test
    void oneCorruptCopyDoesNotBrickStartup() throws Exception {
        writeState(primary(), TODAY.minusDays(1), true);
        Files.write(backup(), "not json".getBytes(UTF_8));

        ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY);

        assertEquals(TODAY, readSeen(primary()));
        assertEquals(TODAY, readSeen(backup()));
    }

    @Test
    void bothCorruptCopiesFailClosed() throws Exception {
        Files.write(primary(), "bad".getBytes(UTF_8));
        Files.write(backup(), "bad".getBytes(UTF_8));

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));
        assertTrue(exc.getMessage().contains("damaged"));
    }

    @Test
    void implausibleFutureStateIsRejected() throws Exception {
        writeState(primary(), TODAY.plusDays(30), true);
        writeState(backup(), TODAY.plusDays(30), true);

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));
        assertTrue(exc.getMessage().contains("future"));
    }

    @Test
    void clockRollbackIsRejected() throws Exception {
        writeState(primary(), TODAY.plusDays(3), true);
        writeState(backup(), TODAY.plusDays(3), true);

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));
        assertTrue(exc.getMessage().contains("backwards"));
    }

    @Test
    void tamperedMacIsRejectedWhenNoValidCopyRemains() throws Exception {
        writeState(primary(), TODAY.minusDays(1), false);
        writeState(backup(), TODAY.minusDays(1), false);

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));
        assertTrue(exc.getMessage().contains("damaged"));
    }

    @Test
    void nonRegularStatePathFailsClosed() throws Exception {
        Files.createDirectories(primary());
        Files.createDirectories(backup());

        IllegalStateException exc = assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));
        assertTrue(exc.getMessage().contains("damaged"));
    }

    @Test
    void readOnlyStateFailsClosedUnlessVolatileIsAllowed() throws Exception {
        Path blocked = temp.resolve("blocked");
        Files.write(blocked, new byte[]{1});
        System.setProperty("jshield.state.dir", blocked.toString());

        assertThrows(IllegalStateException.class,
                () -> ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY));

        System.setProperty("jshield.state.volatile", "true");
        ClockGuard.check(BUILD_ID, BUILD_KEY, TODAY);
    }

    private Path primary() {
        return temp.resolve(BUILD_ID + ".state");
    }

    private Path backup() {
        return temp.resolve(BUILD_ID + ".state.bak");
    }

    private void writeState(Path file, LocalDate seen, boolean validMac) throws Exception {
        Map<String, Object> record = new LinkedHashMap<String, Object>();
        record.put("build_id", BUILD_ID);
        record.put("last_seen", seen.toString());
        String mac = Hex.encode(Envelope.hmacSha256(stateKey(),
                (BUILD_ID + "|" + seen).getBytes(UTF_8)));
        record.put("mac", validMac ? mac : "00");
        Files.write(file, (Json.pretty(record) + "\n").getBytes(UTF_8));
    }

    private LocalDate readSeen(Path file) {
        try {
            Map<String, Object> record = Json.parseObject(
                    new String(Files.readAllBytes(file), UTF_8));
            return LocalDate.parse(String.valueOf(record.get("last_seen")));
        } catch (Exception exc) {
            throw new AssertionError(exc);
        }
    }

    private byte[] stateKey() {
        return Envelope.hkdf(BUILD_KEY, "jshield-state-v1".getBytes(UTF_8),
                BUILD_ID.getBytes(UTF_8), 32);
    }

    private static void restore(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }
}
