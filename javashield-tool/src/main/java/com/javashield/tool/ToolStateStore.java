package com.javashield.tool;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.javashield.core.Fingerprint;
import com.javashield.core.crypto.Hex;
import com.javashield.core.io.SafeFiles;
import com.javashield.core.json.Json;

/**
 * Machine-local tool licence state.
 *
 * <p>Trial and quota counters are sealed with an HMAC key derived from the
 * machine id. This is tamper evidence and copy protection, not a substitute
 * for a server: a determined user can always delete the files to start over.
 * Offline revocation and server-side binding arrive in a later milestone.</p>
 */
public final class ToolStateStore {

    public static final String TOOL_LICENSE_FILE = "tool-license.json";
    public static final String TRIAL_FILE = "trial.json";
    public static final String QUOTA_FILE = "quota.json";
    public static final String INSTALL_FILE = "install.json";
    public static final String REVOCATIONS_FILE = "revocations.json";
    public static final String STATE_LOCK_FILE = "state.lock";

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String STATE_FORMAT = "jshield-state/1";
    private static final String STATE_PREFIX = "jshield-state-v1:";
    private static final String KEY_PREFIX = "jshield-state-key-v1|";

    private final Path home;
    private final String machine;

    public ToolStateStore(Path home) {
        this(home, Fingerprint.machineId());
    }

    public ToolStateStore(Path home, String machine) {
        if (home == null) {
            throw new IllegalArgumentException("state home is required");
        }
        this.home = home.toAbsolutePath();
        this.machine = machine == null || machine.trim().isEmpty()
                ? Fingerprint.machineId() : machine.trim();
    }

    /**
     * Resolves the state directory: {@code javashield.home}, then
     * {@code JAVASHIELD_HOME}, then {@code %APPDATA%\JavaShield} on Windows and
     * {@code ~/.javashield} elsewhere.
     */
    public static Path defaultHome() {
        String property = System.getProperty("javashield.home");
        if (property != null && !property.trim().isEmpty()) {
            return Paths.get(property.trim()).toAbsolutePath();
        }
        String environment = System.getenv("JAVASHIELD_HOME");
        if (environment != null && !environment.trim().isEmpty()) {
            return Paths.get(environment.trim()).toAbsolutePath();
        }
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            String appData = System.getenv("APPDATA");
            if (appData != null && !appData.trim().isEmpty()) {
                return Paths.get(appData.trim(), "JavaShield").toAbsolutePath();
            }
        }
        return Paths.get(System.getProperty("user.home", "."), ".javashield")
                .toAbsolutePath();
    }

    public Path home() {
        return home;
    }

    public String machine() {
        return machine;
    }

    public Path resolve(String name) {
        return home.resolve(name);
    }

    /** Lock file that serializes trial, quota and activation state updates. */
    public Path lockFile() {
        return resolve(STATE_LOCK_FILE);
    }

    /**
     * Reads a sealed state file.
     *
     * @return the payload, or {@code null} when the file does not exist
     * @throws ToolLicenseException when the file exists but its seal is broken
     */
    public Map<String, Object> readSealed(Path file, String purpose) {
        if (Files.notExists(file)) {
            return null;
        }
        if (!Files.isRegularFile(file)) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state is not a regular file: " + file);
        }
        Map<String, Object> document;
        try {
            document = Json.parseObject(new String(SafeFiles.readAllBytes(file), UTF_8));
        } catch (NoSuchFileException exc) {
            return null;
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot read tool state: " + file, exc);
        } catch (RuntimeException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state is not valid JSON: " + file, exc);
        }
        if (!STATE_FORMAT.equals(ToolValues.string(document.get("format"), null))) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "unsupported tool state format: " + file);
        }
        if (!purpose.equals(ToolValues.string(document.get("purpose"), null))) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state purpose mismatch: " + file);
        }
        Map<String, Object> payload = ToolValues.map(document.get("payload"));
        if (payload == null) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state has no payload: " + file);
        }
        String encoded = ToolValues.string(document.get("signature"), null);
        if (encoded == null) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state has no signature: " + file);
        }
        byte[] expected;
        try {
            expected = Hex.decode(encoded);
        } catch (IllegalArgumentException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state signature is malformed: " + file, exc);
        }
        byte[] actual = sign(purpose, payload);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new ToolLicenseException(ToolCodes.STATE_INVALID,
                    "tool state signature is invalid: " + file);
        }
        return payload;
    }

    public void writeSealed(Path file, String purpose, Map<String, Object> payload) {
        if (file == null || purpose == null || payload == null) {
            throw new IllegalArgumentException("file, purpose and payload are required");
        }
        Map<String, Object> document = new LinkedHashMap<String, Object>();
        document.put("format", STATE_FORMAT);
        document.put("purpose", purpose);
        document.put("payload", payload);
        document.put("signature", Hex.encode(sign(purpose, payload)));
        writePrivateFile(file, Json.pretty(document) + "\n");
    }

    public static void writePrivateFile(Path file, String text) {
        writeAtomic(file, text.getBytes(UTF_8), true);
    }

    public static void writeFile(Path file, String text) {
        writeAtomic(file, text.getBytes(UTF_8), false);
    }

    public static void copyPrivate(Path source, Path target) {
        try {
            writeAtomic(target, Files.readAllBytes(source), true);
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot copy " + source + " to " + target, exc);
        }
    }

    public static void delete(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot delete tool state: " + file, exc);
        }
    }

    private byte[] sign(String purpose, Map<String, Object> payload) {
        try {
            byte[] key = sha256((KEY_PREFIX + purpose + "|" + machine).getBytes(UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] message = (STATE_PREFIX + purpose + "|" + Json.canonical(payload))
                    .getBytes(UTF_8);
            return mac.doFinal(message);
        } catch (Exception exc) {
            throw new IllegalStateException("HmacSHA256 is not available", exc);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException("SHA-256 is not available", exc);
        }
    }

    private static void writeAtomic(Path file, byte[] data, boolean restrict) {
        Path absolute = file.toAbsolutePath();
        Path parent = absolute.getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temporary = Files.createTempFile(parent, ".jshield-", ".tmp");
            try {
                Files.write(temporary, data);
                if (restrict) {
                    restrictPermissions(temporary);
                }
                SafeFiles.fsync(temporary);
                SafeFiles.move(temporary, absolute);
            } finally {
                Files.deleteIfExists(temporary);
            }
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot write tool state: " + absolute, exc);
        }
    }

    private static void restrictPermissions(Path path) {
        try {
            Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, permissions);
        } catch (Exception ignored) {
            // Windows and some file systems do not support POSIX permissions.
        }
    }
}
