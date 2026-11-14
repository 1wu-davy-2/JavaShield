package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

import com.javashield.core.Fingerprint;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;
import com.javashield.core.license.LicensePayload;

/**
 * Optional first-run binding.
 *
 * <p>When the licence is issued before the customer machine is known, the first
 * start writes a MAC protected record next to the jar. Copying the whole folder
 * to another machine then fails, because the record and the licence both name
 * the original machine.
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
        String fingerprint = Fingerprint.machineId();
        byte[] key = Envelope.hkdf(payload.getBuildKey(), ascii("jshield-binding-v1"),
                ascii(payload.getBuildId()), 32);

        if (Files.isRegularFile(file)) {
            String text = new String(Files.readAllBytes(file), UTF_8);
            Map<String, Object> record = Json.parseObject(text);
            String recordedBuild = string(record.get("build_id"));
            String recordedMachine = string(record.get("fingerprint"));
            String recordedAt = string(record.get("bound_at"));
            String mac = string(record.get("mac"));
            if (!payload.getBuildId().equals(recordedBuild)) {
                throw new IllegalStateException("binding record belongs to another build");
            }
            String expected = mac(key, recordedBuild, recordedMachine, recordedAt);
            if (!expected.equalsIgnoreCase(mac)) {
                throw new IllegalStateException("binding record was modified");
            }
            if (!fingerprint.equalsIgnoreCase(recordedMachine)) {
                throw new IllegalStateException("this package is bound to another machine");
            }
            return;
        }

        Map<String, Object> record = new LinkedHashMap<String, Object>();
        String boundAt = Dates.now();
        record.put("build_id", payload.getBuildId());
        record.put("fingerprint", fingerprint);
        record.put("bound_at", boundAt);
        record.put("mac", mac(key, payload.getBuildId(), fingerprint, boundAt));
        writeAtomically(file, Json.pretty(record) + "\n");
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
        Files.write(temp, text.getBytes(UTF_8));
        try {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException exc) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static byte[] ascii(String text) {
        return text.getBytes(UTF_8);
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
