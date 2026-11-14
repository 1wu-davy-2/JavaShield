package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;
import com.javashield.core.manifest.Manifest;

/** Verifies the signed manifest and every protected entry before decryption. */
public final class Integrity {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private Integrity() {
    }

    public static Map<String, Object> verify(PayloadSource source, AgentConfig config) throws IOException {
        byte[] raw = source.read(config.getManifestEntry());
        Map<String, Object> manifest = Manifest.parse(new String(raw, UTF_8));

        if (!Manifest.verifySignature(manifest, config.getPublicKey())) {
            throw new IllegalStateException("manifest signature is invalid");
        }
        Object buildId = manifest.get("build_id");
        if (!config.getBuildId().equals(String.valueOf(buildId))) {
            throw new IllegalStateException("manifest belongs to another build");
        }

        Map<String, Object> classes = Manifest.classes(manifest);
        String mode = String.valueOf(manifest.get("integrity"));
        if ("off".equalsIgnoreCase(mode)) {
            return manifest;
        }
        for (Map.Entry<String, Object> entry : classes.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                throw new IllegalStateException("manifest entry is invalid: " + entry.getKey());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> info = (Map<String, Object>) entry.getValue();
            String stub = String.valueOf(info.get("stub"));
            String payload = String.valueOf(info.get("payload"));
            verifyHash(source, stub, String.valueOf(info.get("stub_sha256")), entry.getKey());
            verifyHash(source, payload, String.valueOf(info.get("payload_sha256")), entry.getKey());
        }
        if ("full".equalsIgnoreCase(mode)) {
            verifyDataFiles(source, manifest);
        }
        return manifest;
    }

    @SuppressWarnings("unchecked")
    private static void verifyDataFiles(PayloadSource source, Map<String, Object> manifest)
            throws IOException {
        Object value = manifest.get("files");
        if (!(value instanceof Map)) {
            return;
        }
        for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                throw new IllegalStateException("manifest file entry is invalid: " + entry.getKey());
            }
            Map<String, Object> info = (Map<String, Object>) entry.getValue();
            byte[] data = source.read(entry.getKey());
            long expectedSize = Json.asLong(info.get("size"));
            if (data.length != expectedSize) {
                throw new IllegalStateException("file integrity check failed: " + entry.getKey());
            }
            String actual = Hex.encode(Envelope.sha256(data));
            if (!actual.equalsIgnoreCase(String.valueOf(info.get("sha256")))) {
                throw new IllegalStateException("file integrity check failed: " + entry.getKey());
            }
        }
    }

    private static void verifyHash(PayloadSource source, String path, String expected, String className)
            throws IOException {
        byte[] data = source.read(path);
        String actual = Hex.encode(Envelope.sha256(data));
        if (!actual.equalsIgnoreCase(expected)) {
            throw new IllegalStateException("class integrity check failed: " + className);
        }
    }

    /** Exposed for diagnostics: returns true when the manifest parses and verifies. */
    public static boolean check(PayloadSource source, AgentConfig config) {
        try {
            verify(source, config);
            return true;
        } catch (RuntimeException exc) {
            return false;
        } catch (IOException exc) {
            return false;
        }
    }
}
