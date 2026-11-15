package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import com.javashield.core.Fingerprint;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.io.SafeFiles;
import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;
import com.javashield.core.license.LicensePayload;

/**
 * Optional first-run binding.
 *
 * <p>When the licence is issued before the customer machine is known, the first
 * start writes a MAC protected record next to the jar. Copying the whole folder
 * to another machine then fails, because the record and the licence both name
 * the original machine. Deleting the record still resets the binding; this is
 * an offline speed bump, not a substitute for a vendor-signed activation.</p>
 */
final class BindingGuard {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String FILE_NAME = ".jshield-binding.json";

    private BindingGuard() {
    }

    static void enforce(Path appJar, LicensePayload payload) throws IOException {
        if (!payload.isBindFirstRun()) {
            return;
        }
        Path file = bindingFile(appJar);
        if (volatilePath(file)) {
            throw new IllegalStateException("first-run binding is not supported in a temporary "
                    + "directory (" + file + "); use a fixed fingerprint or set "
                    + "-Djshield.binding to a persistent path");
        }
        String fingerprint = Fingerprint.machineId();
        byte[] key = Envelope.hkdf(payload.getBuildKey(), ascii("jshield-binding-v1"),
                ascii(payload.getBuildId()), 32);

        if (Files.isRegularFile(file)) {
            Map<String, Object> record;
            try {
                record = Json.parseObject(new String(SafeFiles.readAllBytes(file), UTF_8));
            } catch (NoSuchFileException exc) {
                record = null;
            } catch (IOException exc) {
                throw new IllegalStateException("binding record cannot be read: " + file, exc);
            } catch (RuntimeException exc) {
                throw new IllegalStateException("binding record is not valid JSON: " + file, exc);
            }
            if (record != null) {
                verify(record, file, payload, fingerprint, key);
                return;
            }
        } else if (Files.exists(file)) {
            throw new IllegalStateException("binding path is not a regular file: " + file);
        }

        Map<String, Object> record = new LinkedHashMap<String, Object>();
        String boundAt = Dates.now();
        record.put("build_id", payload.getBuildId());
        record.put("fingerprint", fingerprint);
        record.put("bound_at", boundAt);
        record.put("mac", mac(key, payload.getBuildId(), fingerprint, boundAt));
        writeAtomically(file, Json.pretty(record) + "\n");
    }

    private static void verify(Map<String, Object> record, Path file, LicensePayload payload,
                               String fingerprint, byte[] key) {
        String recordedBuild = string(record.get("build_id"));
        String recordedMachine = string(record.get("fingerprint"));
        String recordedAt = string(record.get("bound_at"));
        String recordedMac = string(record.get("mac"));
        if (!payload.getBuildId().equals(recordedBuild)) {
            throw new IllegalStateException("binding record belongs to another build");
        }
        if (!macMatches(mac(key, recordedBuild, recordedMachine, recordedAt), recordedMac)) {
            throw new IllegalStateException("binding record was modified");
        }
        if (!fingerprint.equalsIgnoreCase(recordedMachine)) {
            throw new IllegalStateException("this package is bound to another machine");
        }
    }

    private static Path bindingFile(Path appJar) {
        String explicit = System.getProperty("jshield.binding");
        if (explicit != null && !explicit.trim().isEmpty()) {
            return Paths.get(explicit.trim()).toAbsolutePath();
        }
        if (appJar != null && appJar.getParent() != null) {
            return appJar.getParent().resolve(FILE_NAME);
        }
        return Paths.get(System.getProperty("user.dir", ".")).resolve(FILE_NAME).toAbsolutePath();
    }

    /**
     * A binding record inside the system temp directory or a bootloader
     * extraction directory disappears between runs, so the next launch would
     * silently re-bind to whichever machine runs it next.
     */
    private static boolean volatilePath(Path file) {
        Path absolute = file.toAbsolutePath().normalize();
        for (Path part : absolute) {
            String name = part.toString().toLowerCase(Locale.ROOT);
            if (name.startsWith("_mei")) {
                return true;
            }
        }
        String temp = System.getProperty("java.io.tmpdir");
        if (temp != null && !temp.trim().isEmpty()) {
            Path temporary = Paths.get(temp.trim()).toAbsolutePath().normalize();
            if (absolute.startsWith(temporary)) {
                return true;
            }
        }
        return false;
    }

    private static boolean macMatches(String expected, String actual) {
        try {
            return MessageDigest.isEqual(Hex.decode(expected), Hex.decode(actual));
        } catch (IllegalArgumentException exc) {
            return false;
        }
    }

    private static String mac(byte[] key, String buildId, String fingerprint, String boundAt) {
        byte[] message = (buildId + "|" + fingerprint + "|" + boundAt).getBytes(UTF_8);
        return Hex.encode(Envelope.hmacSha256(key, message));
    }

    private static void writeAtomically(Path file, String text) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, "jshield-binding", ".tmp");
        try {
            Files.write(temp, text.getBytes(UTF_8));
            SafeFiles.fsync(temp);
            SafeFiles.move(temp, file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static byte[] ascii(String text) {
        return text.getBytes(UTF_8);
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
