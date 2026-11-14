package com.javashield.core.manifest;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.javashield.core.Product;
import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Hex;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.json.Json;

/**
 * Signed inventory of everything the runtime must find unchanged.
 *
 * <p>The manifest lives inside the protected jar as
 * {@code META-INF/jshield-manifest.json}. The agent verifies the signature with
 * the embedded public key and then checks each recorded hash before it installs
 * the decryption transformer.
 */
public final class Manifest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private Manifest() {
    }

    public static Map<String, Object> create(String buildId, String cipher, String integrity) {
        Map<String, Object> manifest = new LinkedHashMap<String, Object>();
        manifest.put("format", Long.valueOf(Product.MANIFEST_FORMAT));
        manifest.put("tool", Product.TOOL);
        manifest.put("build_id", buildId);
        manifest.put("cipher", cipher);
        manifest.put("integrity", integrity);
        manifest.put("classes", new LinkedHashMap<String, Object>());
        manifest.put("files", new LinkedHashMap<String, Object>());
        return manifest;
    }

    @SuppressWarnings("unchecked")
    public static void putClass(Map<String, Object> manifest, String internalName,
                                String stubPath, String payloadPath,
                                String stubSha256, String payloadSha256, String plainSha256) {
        Map<String, Object> entry = new LinkedHashMap<String, Object>();
        entry.put("stub", stubPath);
        entry.put("payload", payloadPath);
        entry.put("stub_sha256", stubSha256);
        entry.put("payload_sha256", payloadSha256);
        entry.put("plain_sha256", plainSha256);
        Map<String, Object> classes = (Map<String, Object>) manifest.get("classes");
        classes.put(internalName, entry);
    }

    @SuppressWarnings("unchecked")
    public static void putFile(Map<String, Object> manifest, String path, String sha256, long size) {
        Map<String, Object> entry = new LinkedHashMap<String, Object>();
        entry.put("sha256", sha256);
        entry.put("size", Long.valueOf(size));
        Map<String, Object> files = (Map<String, Object>) manifest.get("files");
        files.put(path, entry);
    }

    public static Map<String, Object> sign(Map<String, Object> manifest, byte[] signingKey) {
        Map<String, Object> unsigned = new LinkedHashMap<String, Object>(manifest);
        unsigned.remove("signature");
        byte[] message = (Product.MANIFEST_PREFIX + Json.canonical(unsigned)).getBytes(UTF_8);
        byte[] signature = Ed25519.sign(signingKey, message);
        Map<String, Object> signed = new LinkedHashMap<String, Object>(unsigned);
        signed.put("signature", Base64.getEncoder().encodeToString(signature));
        return signed;
    }

    public static boolean verifySignature(Map<String, Object> manifest, byte[] publicKey) {
        Object value = manifest.get("signature");
        if (!(value instanceof String) || ((String) value).isEmpty()) {
            return false;
        }
        Map<String, Object> unsigned = new LinkedHashMap<String, Object>(manifest);
        unsigned.remove("signature");
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode((String) value);
        } catch (IllegalArgumentException exc) {
            return false;
        }
        byte[] message = (Product.MANIFEST_PREFIX + Json.canonical(unsigned)).getBytes(UTF_8);
        return Ed25519.verify(publicKey, message, signature);
    }

    public static Map<String, Object> parse(String text) {
        Map<String, Object> manifest = Json.parseObject(text);
        if (Json.asLong(manifest.get("format")) != Long.parseLong(Product.MANIFEST_FORMAT)) {
            throw new IllegalArgumentException("unsupported manifest format");
        }
        if (!(manifest.get("classes") instanceof Map)) {
            throw new IllegalArgumentException("manifest has no class list");
        }
        return manifest;
    }

    public static String serialize(Map<String, Object> manifest) {
        return Json.pretty(manifest) + "\n";
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> classes(Map<String, Object> manifest) {
        Object classes = manifest.get("classes");
        return classes instanceof Map ? (Map<String, Object>) classes : new LinkedHashMap<String, Object>();
    }

    @SuppressWarnings("unchecked")
    public static List<String> classNames(Map<String, Object> manifest) {
        return new ArrayList<String>(classes(manifest).keySet());
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> classEntry(Map<String, Object> manifest, String internalName) {
        Object entry = classes(manifest).get(internalName);
        return entry instanceof Map ? (Map<String, Object>) entry : null;
    }

    public static String sha256Hex(byte[] data) {
        return Hex.encode(Envelope.sha256(data));
    }
}
