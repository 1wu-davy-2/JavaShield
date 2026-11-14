package com.javashield.tool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Hex;
import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;

/**
 * Signed tool licence documents and root-key helpers.
 *
 * <p>Document shape:</p>
 * <pre>
 * {
 *   "format": "jshield-tool-license/1",
 *   "payload": { ... },
 *   "signature": "base64(ed25519(prefix + canonical(payload)))"
 * }
 * </pre>
 */
public final class ToolLicense {

    public static final String PRODUCT = "javashield";
    public static final String FORMAT = "jshield-tool-license/1";
    public static final String SIGNATURE_PREFIX = "jshield-tool-license-v1:";
    public static final String ROOT_KEY_FORMAT = "jshield-root-key/1";
    public static final String PUBLIC_KEY_PREFIX = "jshield-tool-public-key:";
    public static final String REVOCATIONS_FORMAT = "jshield-revocations/1";
    public static final String REVOCATIONS_PREFIX = "jshield-revocations-v1:";

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String PUBLIC_KEY_RESOURCE = "/com/javashield/tool/root.pub";

    private ToolLicense() {
    }

    public static Map<String, Object> signDocument(String format, String prefix,
                                                   Map<String, Object> payload, byte[] seed) {
        if (format == null || prefix == null || payload == null || seed == null) {
            throw new IllegalArgumentException("format, prefix, payload and seed are required");
        }
        if (seed.length != Ed25519.SEED_LENGTH) {
            throw new IllegalArgumentException("tool signing seed must be 32 bytes");
        }
        Map<String, Object> copy = new LinkedHashMap<String, Object>(payload);
        byte[] message = (prefix + Json.canonical(copy)).getBytes(UTF_8);
        byte[] signature = Ed25519.sign(seed, message);
        Map<String, Object> document = new LinkedHashMap<String, Object>();
        document.put("format", format);
        document.put("payload", copy);
        document.put("signature", Base64.getEncoder().encodeToString(signature));
        return document;
    }

    /**
     * Validates the document envelope and, when a public key is supplied,
     * verifies the signature.
     *
     * @return the payload map
     */
    public static Map<String, Object> verifyDocument(Map<String, Object> document,
                                                     String format, String prefix,
                                                     byte[] publicKey) {
        if (document == null) {
            throw invalid("tool document is not a JSON object");
        }
        if (!format.equals(ToolValues.string(document.get("format"), null))) {
            throw invalid("unsupported tool document format");
        }
        Map<String, Object> payload = ToolValues.map(document.get("payload"));
        if (payload == null) {
            throw invalid("tool document has no payload");
        }
        if (publicKey == null) {
            return payload;
        }
        if (publicKey.length != Ed25519.PUBLIC_KEY_LENGTH) {
            throw invalid("tool public key must be 32 bytes");
        }
        String encoded = ToolValues.string(document.get("signature"), null);
        if (encoded == null || encoded.trim().isEmpty()) {
            throw invalid("tool document has no signature");
        }
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exc) {
            throw invalid("tool document signature is not valid Base64");
        }
        byte[] message = (prefix + Json.canonical(payload)).getBytes(UTF_8);
        if (!Ed25519.verify(publicKey, message, signature)) {
            throw invalid("tool document signature is invalid");
        }
        return payload;
    }

    public static ToolEntitlement parse(Map<String, Object> document, byte[] publicKey) {
        Map<String, Object> payload = verifyDocument(document, FORMAT, SIGNATURE_PREFIX, publicKey);
        ToolEntitlement entitlement = ToolEntitlement.fromPayload(payload);
        entitlement.setVerified(publicKey != null);
        return entitlement;
    }

    public static ToolEntitlement read(Path path, byte[] publicKey) {
        Map<String, Object> document;
        try {
            document = Json.parseObject(new String(Files.readAllBytes(path), UTF_8));
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot read tool licence: " + path, exc);
        } catch (IllegalArgumentException exc) {
            throw invalid("tool licence is not valid JSON: " + path);
        }
        return parse(document, publicKey);
    }

    public static void writeDocument(Path path, Map<String, Object> document) {
        ToolStateStore.writePrivateFile(path, Json.pretty(document) + "\n");
    }

    /**
     * Loads the trust root for tool licences.
     *
     * <p>An embedded key wins over the environment on purpose: an official
     * build must not let an attacker replace its trust root. Source builds can
     * supply a key through {@code -Djavashield.tool.publicKey} or
     * {@code JAVASHIELD_TOOL_PUBLIC_KEY}.</p>
     *
     * @return the 32 byte public key, or {@code null} when no key is configured
     */
    public static byte[] loadPublicKey() {
        byte[] embedded = embeddedPublicKey();
        if (embedded != null) {
            return embedded;
        }
        String property = System.getProperty("javashield.tool.publicKey");
        if (property != null && !property.trim().isEmpty()) {
            return decodePublicKey(property);
        }
        String environment = System.getenv("JAVASHIELD_TOOL_PUBLIC_KEY");
        if (environment != null && !environment.trim().isEmpty()) {
            return decodePublicKey(environment);
        }
        return null;
    }

    /**
     * True only when development mode is requested and no public key is
     * embedded. Official builds therefore cannot be unlocked with an
     * environment variable.
     */
    public static boolean devMode() {
        String value = System.getProperty("javashield.dev");
        if (value == null) {
            value = System.getenv("JAVASHIELD_DEV");
        }
        if (!truthy(value)) {
            return false;
        }
        return embeddedPublicKey() == null;
    }

    private static boolean truthy(String value) {
        if (value == null) {
            return false;
        }
        String text = value.trim();
        return "1".equals(text) || "true".equalsIgnoreCase(text)
                || "yes".equalsIgnoreCase(text) || "on".equalsIgnoreCase(text);
    }

    private static byte[] embeddedPublicKey() {
        InputStream in = ToolLicense.class.getResourceAsStream(PUBLIC_KEY_RESOURCE);
        if (in == null) {
            return null;
        }
        try {
            String text = new String(readAll(in), UTF_8).trim();
            if (text.isEmpty() || text.contains("${")) {
                return null;
            }
            return decodePublicKey(text);
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private static byte[] readAll(InputStream in) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(256);
            byte[] buffer = new byte[256];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot read the embedded tool public key", exc);
        }
    }

    /**
     * Accepts a raw Base64 public key, a {@code jshield-tool-public-key:}
     * prefixed value, a 64 character hex key, or a root-key JSON document.
     */
    public static byte[] decodePublicKey(String text) {
        if (text == null || text.trim().isEmpty()) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool public key is empty");
        }
        String value = text.trim();
        if (value.startsWith("{")) {
            Map<String, Object> document;
            try {
                document = Json.parseObject(value);
            } catch (IllegalArgumentException exc) {
                throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                        "tool public key document is not valid JSON", exc);
            }
            if (!ROOT_KEY_FORMAT.equals(ToolValues.string(document.get("format"), null))) {
                throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                        "unsupported root key format");
            }
            value = ToolValues.string(document.get("public_key"), null);
            if (value == null) {
                throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                        "root key document has no public_key");
            }
        }
        if (value.startsWith(PUBLIC_KEY_PREFIX)) {
            value = value.substring(PUBLIC_KEY_PREFIX.length());
        }
        value = value.replaceAll("\\s+", "");
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length == Ed25519.PUBLIC_KEY_LENGTH) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // fall through to hex
        }
        if (value.length() == Ed25519.PUBLIC_KEY_LENGTH * 2) {
            try {
                byte[] decoded = Hex.decode(value);
                if (decoded.length == Ed25519.PUBLIC_KEY_LENGTH) {
                    return decoded;
                }
            } catch (IllegalArgumentException ignored) {
                // fall through
            }
        }
        throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                "tool public key must be 32 bytes encoded as Base64 or hex");
    }

    public static String encodePublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != Ed25519.PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("tool public key must be 32 bytes");
        }
        return Base64.getEncoder().encodeToString(publicKey);
    }

    public static Map<String, Object> rootKeyDocument(byte[] seed) {
        if (seed == null || seed.length != Ed25519.SEED_LENGTH) {
            throw new IllegalArgumentException("root seed must be 32 bytes");
        }
        Map<String, Object> document = new LinkedHashMap<String, Object>();
        document.put("format", ROOT_KEY_FORMAT);
        document.put("seed", Base64.getEncoder().encodeToString(seed));
        document.put("public_key", encodePublicKey(Ed25519.publicKeyFromSeed(seed)));
        document.put("created", Dates.now());
        return document;
    }

    public static byte[] readRootSeed(Path path) {
        String text;
        try {
            text = new String(Files.readAllBytes(path), UTF_8).trim();
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot read root key: " + path, exc);
        }
        if (text.startsWith("{")) {
            Map<String, Object> document;
            try {
                document = Json.parseObject(text);
            } catch (IllegalArgumentException exc) {
                throw invalid("root key is not valid JSON: " + path);
            }
            if (!ROOT_KEY_FORMAT.equals(ToolValues.string(document.get("format"), null))) {
                throw invalid("unsupported root key format: " + path);
            }
            text = ToolValues.string(document.get("seed"), null);
            if (text == null) {
                throw invalid("root key has no seed: " + path);
            }
        }
        try {
            byte[] seed = Base64.getDecoder().decode(text.replaceAll("\\s+", ""));
            if (seed.length != Ed25519.SEED_LENGTH) {
                throw invalid("root seed must be 32 bytes");
            }
            return seed;
        } catch (IllegalArgumentException exc) {
            throw invalid("root seed is not valid Base64: " + path);
        }
    }

    public static Map<String, Object> revocationsDocument(byte[] seed,
                                                          List<String> revoked,
                                                          long epoch, String updated) {
        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("revoked", new ArrayList<String>(new TreeSet<String>(revoked)));
        payload.put("epoch", Long.valueOf(epoch));
        payload.put("updated", updated);
        return signDocument(REVOCATIONS_FORMAT, REVOCATIONS_PREFIX, payload, seed);
    }

    public static Set<String> verifyRevocations(Map<String, Object> document, byte[] publicKey) {
        if (publicKey == null) {
            throw invalid("a tool public key is required to verify revocations");
        }
        Map<String, Object> payload = verifyDocument(
                document, REVOCATIONS_FORMAT, REVOCATIONS_PREFIX, publicKey);
        return new LinkedHashSet<String>(ToolValues.strings(payload.get("revoked")));
    }

    public static Set<String> readRevocations(Path path, byte[] publicKey) {
        Map<String, Object> document;
        try {
            document = Json.parseObject(new String(Files.readAllBytes(path), UTF_8));
        } catch (IOException exc) {
            throw new ToolLicenseException(ToolCodes.STATE_IO,
                    "cannot read revocation list: " + path, exc);
        } catch (IllegalArgumentException exc) {
            throw invalid("revocation list is not valid JSON: " + path);
        }
        return verifyRevocations(document, publicKey);
    }

    private static ToolLicenseException invalid(String message) {
        return new ToolLicenseException(ToolCodes.LICENSE_INVALID, message);
    }
}
