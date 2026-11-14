package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;

/**
 * Detects an obvious system clock rollback by remembering the last seen date in
 * a MAC protected state file.
 *
 * <p>This is best effort: deleting the state file resets the history. It raises
 * the cost of "set the clock back a year" without pretending to be DRM.
 */
final class ClockGuard {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private ClockGuard() {
    }

    static void check(String buildId, byte[] buildKey) {
        try {
            Path dir = stateDir();
            Path file = dir.resolve(buildId + ".state");
            byte[] key = Envelope.hkdf(buildKey, ascii("jshield-state-v1"), ascii(buildId), 32);
            LocalDate today = LocalDate.now(ZoneOffset.UTC);

            if (Files.isRegularFile(file)) {
                Map<String, Object> record = Json.parseObject(
                        new String(Files.readAllBytes(file), UTF_8));
                String recordedBuild = string(record.get("build_id"));
                String lastSeen = string(record.get("last_seen"));
                String mac = string(record.get("mac"));
                if (!buildId.equals(recordedBuild) || !mac(key, recordedBuild, lastSeen).equalsIgnoreCase(mac)) {
                    throw new IllegalStateException("clock state file was modified");
                }
                LocalDate seen = LocalDate.parse(lastSeen);
                if (today.isBefore(seen.minusDays(1))) {
                    throw new IllegalStateException("system clock moved backwards (last run " + seen + ")");
                }
                if (today.isAfter(seen)) {
                    write(file, buildId, today.toString(), key);
                }
                return;
            }
            Files.createDirectories(dir);
            write(file, buildId, today.toString(), key);
        } catch (IOException exc) {
            // A read only deployment must still start; the licence still has a hard expiry.
        }
    }

    private static void write(Path file, String buildId, String lastSeen, byte[] key) throws IOException {
        Map<String, Object> record = new LinkedHashMap<String, Object>();
        record.put("build_id", buildId);
        record.put("last_seen", lastSeen);
        record.put("mac", mac(key, buildId, lastSeen));
        Path parent = file.toAbsolutePath().getParent();
        Path temp = Files.createTempFile(parent, "jshield-state", ".tmp");
        Files.write(temp, (Json.pretty(record) + "\n").getBytes(UTF_8));
        try {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException exc) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String mac(byte[] key, String buildId, String lastSeen) {
        return Hex.encode(Envelope.hmacSha256(key,
                (buildId + "|" + lastSeen).getBytes(UTF_8)));
    }

    private static Path stateDir() {
        String explicit = System.getProperty("jshield.state.dir");
        if (explicit != null && !explicit.trim().isEmpty()) {
            return Paths.get(explicit.trim()).toAbsolutePath();
        }
        return Paths.get(System.getProperty("user.home", "."), ".jshield").toAbsolutePath();
    }

    private static byte[] ascii(String text) {
        return text.getBytes(UTF_8);
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
