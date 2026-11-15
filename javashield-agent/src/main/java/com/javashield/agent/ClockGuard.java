package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.io.SafeFiles;
import com.javashield.core.io.StateLock;
import com.javashield.core.json.Json;

/**
 * Detects an obvious system clock rollback by remembering the last seen date in
 * a MAC protected state file.
 *
 * <p>The state is kept in two copies. A crash or a sharing violation between
 * the two writes is repaired from the newer valid copy instead of bricking the
 * application. Deleting both copies resets the history; this is a speed bump,
 * not DRM.</p>
 */
final class ClockGuard {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final int MAX_FUTURE_DAYS = 7;
    private static final int ROLLBACK_TOLERANCE_DAYS = 1;
    private static final long LOCK_TIMEOUT_MILLIS = StateLock.DEFAULT_TIMEOUT_MILLIS;
    private static final String VOLATILE_PROPERTY = "jshield.state.volatile";
    private static final String VOLATILE_ENVIRONMENT = "JSHIELD_ALLOW_VOLATILE_STATE";

    private ClockGuard() {
    }

    static void check(String buildId, byte[] buildKey) {
        check(buildId, buildKey, LocalDate.now(ZoneOffset.UTC));
    }

    static void check(final String buildId, final byte[] buildKey, final LocalDate today) {
        if (buildId == null || buildId.trim().isEmpty() || buildKey == null) {
            throw new IllegalArgumentException("build id and build key are required");
        }
        final Path dir = stateDir();
        final Path primary = dir.resolve(buildId + ".state");
        final Path backup = dir.resolve(buildId + ".state.bak");
        final Path lockFile = dir.resolve(buildId + ".state.lock");
        try {
            StateLock.withLock(lockFile, LOCK_TIMEOUT_MILLIS, new StateLock.Action<Void>() {
                @Override
                public Void run() throws IOException {
                    checkLocked(buildId, buildKey, today, primary, backup);
                    return null;
                }
            });
        } catch (IOException exc) {
            if (!allowVolatileState()) {
                throw new IllegalStateException("cannot lock clock state (" + lockFile + "): "
                        + exc.getMessage()
                        + "; make the directory writable or set -D" + VOLATILE_PROPERTY
                        + "=true for a read-only deployment", exc);
            }
            checkLocked(buildId, buildKey, today, primary, backup);
        }
    }

    private static void checkLocked(String buildId, byte[] buildKey, LocalDate today,
                                    Path primary, Path backup) {
        byte[] key = Envelope.hkdf(buildKey, ascii("jshield-state-v1"), ascii(buildId), 32);
        ReadResult primaryResult = read(primary, buildId, key);
        ReadResult backupResult = read(backup, buildId, key);

        if (primaryResult.date == null && backupResult.date == null) {
            if (primaryResult.problem != null || backupResult.problem != null) {
                throw new IllegalStateException("clock state is damaged: "
                        + describe(primary, primaryResult) + "; "
                        + describe(backup, backupResult)
                        + ". Restore a backup or remove both files to re-anchor.");
            }
            writeBoth(primary, backup, buildId, today, key);
            return;
        }

        LocalDate seen = newer(primaryResult.date, backupResult.date);
        if (seen.isAfter(today.plusDays(MAX_FUTURE_DAYS))) {
            throw new IllegalStateException("clock state contains an implausible future date "
                    + seen + "; correct the system clock or remove both state files to re-anchor");
        }
        if (today.isBefore(seen.minusDays(ROLLBACK_TOLERANCE_DAYS))) {
            throw new IllegalStateException("system clock moved backwards (last run " + seen
                    + "); correct the system clock or remove both state files to re-anchor");
        }

        boolean repair = primaryResult.date == null
                || backupResult.date == null
                || primaryResult.problem != null
                || backupResult.problem != null
                || !seen.equals(primaryResult.date)
                || !seen.equals(backupResult.date);
        if (today.isAfter(seen)) {
            seen = today;
            repair = true;
        }
        if (repair) {
            writeBoth(primary, backup, buildId, seen, key);
        }
    }

    private static ReadResult read(Path file, String buildId, byte[] key) {
        try {
            if (Files.notExists(file)) {
                return ReadResult.absent();
            }
            if (!Files.isRegularFile(file)) {
                return ReadResult.problem("not a regular file");
            }
            byte[] data;
            try {
                data = SafeFiles.readAllBytes(file);
            } catch (NoSuchFileException exc) {
                return ReadResult.absent();
            } catch (IOException exc) {
                return ReadResult.problem("cannot be read: " + exc.getMessage());
            }
            Map<String, Object> record;
            try {
                record = Json.parseObject(new String(data, UTF_8));
            } catch (RuntimeException exc) {
                return ReadResult.problem("not valid JSON");
            }
            String recordedBuild = string(record.get("build_id"));
            String lastSeen = string(record.get("last_seen"));
            String mac = string(record.get("mac"));
            if (!buildId.equals(recordedBuild)) {
                return ReadResult.problem("belongs to another build");
            }
            if (!macMatches(mac(key, recordedBuild, lastSeen), mac)) {
                return ReadResult.problem("MAC is invalid");
            }
            try {
                return ReadResult.valid(LocalDate.parse(lastSeen));
            } catch (DateTimeParseException exc) {
                return ReadResult.problem("last_seen is invalid");
            }
        } catch (RuntimeException exc) {
            return ReadResult.problem("cannot be validated: " + exc.getMessage());
        }
    }

    private static void writeBoth(Path primary, Path backup, String buildId,
                                  LocalDate lastSeen, byte[] key) {
        int written = 0;
        IOException failure = null;
        for (Path file : new Path[]{primary, backup}) {
            try {
                write(file, buildId, lastSeen.toString(), key);
                written++;
            } catch (IOException exc) {
                failure = exc;
            }
        }
        if (written == 0 && !allowVolatileState()) {
            throw new IllegalStateException("cannot record clock state in "
                    + primary.getParent() + " (" + message(failure) + "); make the directory "
                    + "writable or set -D" + VOLATILE_PROPERTY + "=true for a read-only deployment",
                    failure);
        }
    }

    private static void write(Path file, String buildId, String lastSeen, byte[] key)
            throws IOException {
        Map<String, Object> record = new LinkedHashMap<String, Object>();
        record.put("build_id", buildId);
        record.put("last_seen", lastSeen);
        record.put("mac", mac(key, buildId, lastSeen));
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, "jshield-state", ".tmp");
        try {
            Files.write(temp, (Json.pretty(record) + "\n").getBytes(UTF_8));
            SafeFiles.fsync(temp);
            SafeFiles.move(temp, file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static LocalDate newer(LocalDate first, LocalDate second) {
        if (first == null) {
            return second;
        }
        if (second == null) {
            return first;
        }
        return first.isAfter(second) ? first : second;
    }

    private static String describe(Path file, ReadResult result) {
        return file + " (" + (result.problem == null ? "missing" : result.problem) + ")";
    }

    private static String message(IOException exc) {
        return exc == null || exc.getMessage() == null ? "unknown error" : exc.getMessage();
    }

    private static boolean macMatches(String expected, String actual) {
        try {
            return MessageDigest.isEqual(Hex.decode(expected), Hex.decode(actual));
        } catch (IllegalArgumentException exc) {
            return false;
        }
    }

    private static String mac(byte[] key, String buildId, String lastSeen) {
        return Hex.encode(Envelope.hmacSha256(key,
                (buildId + "|" + lastSeen).getBytes(UTF_8)));
    }

    private static boolean allowVolatileState() {
        return truthy(System.getProperty(VOLATILE_PROPERTY))
                || truthy(System.getenv(VOLATILE_ENVIRONMENT));
    }

    private static boolean truthy(String value) {
        if (value == null) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return "1".equals(normalized) || "true".equals(normalized)
                || "yes".equals(normalized) || "on".equals(normalized);
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

    private static final class ReadResult {
        private final LocalDate date;
        private final String problem;

        private ReadResult(LocalDate date, String problem) {
            this.date = date;
            this.problem = problem;
        }

        private static ReadResult absent() {
            return new ReadResult(null, null);
        }

        private static ReadResult valid(LocalDate date) {
            return new ReadResult(date, null);
        }

        private static ReadResult problem(String problem) {
            return new ReadResult(null, problem);
        }
    }
}
