package com.javashield.cli.builder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.javashield.core.BuildSecret;
import com.javashield.core.Product;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;

/** Offline verification of a delivered package. */
public final class JarVerifier {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private JarVerifier() {
    }

    public static List<String> verify(Path jarPath, BuildSecret secret) throws IOException {
        List<String> failures = new ArrayList<String>();
        try (JarFile jar = new JarFile(jarPath.toFile(), false)) {
            JarEntry manifestEntry = jar.getJarEntry(Product.MANIFEST_ENTRY);
            if (manifestEntry == null) {
                failures.add("manifest is missing: " + Product.MANIFEST_ENTRY);
                return failures;
            }
            String text = new String(readAll(jar.getInputStream(manifestEntry)), UTF_8);
            Map<String, Object> manifest;
            try {
                manifest = com.javashield.core.manifest.Manifest.parse(text);
            } catch (RuntimeException exc) {
                failures.add("manifest is invalid: " + exc.getMessage());
                return failures;
            }
            if (!com.javashield.core.manifest.Manifest.verifySignature(manifest, secret.getPublicKey())) {
                failures.add("manifest signature is invalid");
                return failures;
            }
            if (!secret.getBuildId().equals(String.valueOf(manifest.get("build_id")))) {
                failures.add("manifest belongs to build " + manifest.get("build_id")
                        + ", secret is for " + secret.getBuildId());
            }
            for (Map.Entry<String, Object> entry
                    : com.javashield.core.manifest.Manifest.classes(manifest).entrySet()) {
                if (!(entry.getValue() instanceof Map)) {
                    failures.add("invalid entry: " + entry.getKey());
                    continue;
                }
                Map<?, ?> info = (Map<?, ?>) entry.getValue();
                check(jar, failures, entry.getKey(), String.valueOf(info.get("stub")),
                        String.valueOf(info.get("stub_sha256")));
                check(jar, failures, entry.getKey(), String.valueOf(info.get("payload")),
                        String.valueOf(info.get("payload_sha256")));
            }
            if ("full".equalsIgnoreCase(String.valueOf(manifest.get("integrity")))) {
                verifyDataFiles(jar, manifest, failures);
            }
        }
        return failures;
    }

    private static void verifyDataFiles(JarFile jar, Map<String, Object> manifest,
                                        List<String> failures) throws IOException {
        Object value = manifest.get("files");
        if (!(value instanceof Map)) {
            return;
        }
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
            String path = String.valueOf(entry.getKey());
            if (!(entry.getValue() instanceof Map)) {
                failures.add("invalid file entry: " + path);
                continue;
            }
            Map<?, ?> info = (Map<?, ?>) entry.getValue();
            JarEntry jarEntry = jar.getJarEntry(path);
            if (jarEntry == null) {
                failures.add("missing data file: " + path);
                continue;
            }
            byte[] data = readAll(jar.getInputStream(jarEntry));
            if (data.length != Json.asLong(info.get("size"))) {
                failures.add("size mismatch on " + path);
                continue;
            }
            if (!Hex.encode(Envelope.sha256(data)).equalsIgnoreCase(String.valueOf(info.get("sha256")))) {
                failures.add("hash mismatch on " + path);
            }
        }
    }

    private static void check(JarFile jar, List<String> failures, String className,
                              String path, String expected) throws IOException {
        JarEntry entry = jar.getJarEntry(path);
        if (entry == null) {
            failures.add(className + ": missing " + path);
            return;
        }
        String actual = Hex.encode(Envelope.sha256(readAll(jar.getInputStream(entry))));
        if (!actual.equalsIgnoreCase(expected)) {
            failures.add(className + ": hash mismatch on " + path);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(8192);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /** Reads a manifest without a secret, for inspection only. */
    public static Map<String, Object> readManifest(Path jarPath) throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile(), false)) {
            JarEntry entry = jar.getJarEntry(Product.MANIFEST_ENTRY);
            if (entry == null) {
                throw new IOException("not a JavaShield package: " + jarPath);
            }
            return Json.parseObject(new String(readAll(jar.getInputStream(entry)), UTF_8));
        }
    }
}
