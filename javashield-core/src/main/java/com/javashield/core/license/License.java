package com.javashield.core.license;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.javashield.core.Product;
import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.ShieldCryptoException;
import com.javashield.core.json.Json;

/**
 * Licence encoding: sign the canonical payload with Ed25519, then encrypt the
 * signed document with a build specific key.
 *
 * <p>Layering matters. The signature stops an attacker who extracted the
 * symmetric master key from the agent from forging a licence; the encryption
 * stops casual inspection of customer names and dates.
 */
public final class License {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final byte[] AAD_PREFIX = "jshield:license:".getBytes(UTF_8);

    private License() {
    }

    /** Returns a copy of {@code payload} with a valid signature attached. */
    public static Map<String, Object> sign(Map<String, Object> payload, byte[] signingKey) {
        Map<String, Object> unsigned = new LinkedHashMap<String, Object>(payload);
        unsigned.remove("signature");
        byte[] message = (Product.LICENSE_PREFIX + Json.canonical(unsigned)).getBytes(UTF_8);
        byte[] signature = Ed25519.sign(signingKey, message);
        Map<String, Object> signed = new LinkedHashMap<String, Object>(unsigned);
        signed.put("signature", Base64.getEncoder().encodeToString(signature));
        return signed;
    }

    public static boolean verifySignature(Map<String, Object> payload, byte[] publicKey) {
        Object signatureValue = payload.get("signature");
        if (!(signatureValue instanceof String) || ((String) signatureValue).isEmpty()) {
            return false;
        }
        Map<String, Object> unsigned = new LinkedHashMap<String, Object>(payload);
        unsigned.remove("signature");
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode((String) signatureValue);
        } catch (IllegalArgumentException exc) {
            return false;
        }
        byte[] message = (Product.LICENSE_PREFIX + Json.canonical(unsigned)).getBytes(UTF_8);
        return Ed25519.verify(publicKey, message, signature);
    }

    /** Encodes a licence into a Base64 text body. */
    public static String encode(LicensePayload payload, byte[] masterKey, byte[] signingKey) {
        if (payload.getBuildId() == null || payload.getBuildId().isEmpty()) {
            throw new IllegalArgumentException("licence has no build id");
        }
        Map<String, Object> signed = sign(payload.toMap(), signingKey);
        byte[] plain = Json.canonical(signed).getBytes(UTF_8);
        byte[] key = Envelope.deriveLicenseKey(masterKey, payload.getBuildId());
        byte[] sealed = Envelope.seal(key, plain, aad(payload.getBuildId()), Envelope.AUTO);
        return Base64.getEncoder().encodeToString(sealed);
    }

    /**
     * Decodes and verifies a licence body.
     *
     * @param text            Base64 body
     * @param masterKey       the 32 byte master key embedded in the agent
     * @param expectedBuildId the build id the caller expects
     * @param publicKey       the Ed25519 public key embedded in the agent
     * @throws ShieldCryptoException    when the envelope cannot be opened
     * @throws IllegalArgumentException when the signature is invalid
     */
    public static LicensePayload decode(String text, byte[] masterKey,
                                        String expectedBuildId, byte[] publicKey) {
        byte[] sealed;
        try {
            sealed = Base64.getMimeDecoder().decode(text);
        } catch (IllegalArgumentException exc) {
            throw new IllegalArgumentException("licence is not valid Base64", exc);
        }
        byte[] key = Envelope.deriveLicenseKey(masterKey, expectedBuildId);
        byte[] plain = Envelope.open(key, sealed, aad(expectedBuildId));
        Map<String, Object> map = Json.parseObject(new String(plain, UTF_8));
        if (!verifySignature(map, publicKey)) {
            throw new IllegalArgumentException("licence signature is invalid");
        }
        LicensePayload payload = LicensePayload.fromMap(map);
        if (!expectedBuildId.equals(payload.getBuildId())) {
            throw new IllegalArgumentException("licence belongs to another build");
        }
        return payload;
    }

    public static void write(Path path, LicensePayload payload,
                             byte[] masterKey, byte[] signingKey) throws IOException {
        String body = encode(payload, masterKey, signingKey);
        StringBuilder text = new StringBuilder();
        int index = 0;
        while (index < body.length()) {
            int end = Math.min(index + 76, body.length());
            text.append(body, index, end).append('\n');
            index = end;
        }
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(path, text.toString().getBytes(UTF_8));
    }

    public static LicensePayload read(Path path, byte[] masterKey,
                                      String expectedBuildId, byte[] publicKey) throws IOException {
        String text = new String(Files.readAllBytes(path), UTF_8);
        return decode(text, masterKey, expectedBuildId, publicKey);
    }

    private static byte[] aad(String buildId) {
        byte[] suffix = buildId.getBytes(UTF_8);
        byte[] out = new byte[AAD_PREFIX.length + suffix.length];
        System.arraycopy(AAD_PREFIX, 0, out, 0, AAD_PREFIX.length);
        System.arraycopy(suffix, 0, out, AAD_PREFIX.length, suffix.length);
        return out;
    }
}
