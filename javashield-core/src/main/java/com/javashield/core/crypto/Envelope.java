package com.javashield.core.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Authenticated encryption envelope shared by the builder and the runtime agent.
 *
 * <pre>
 * MAGIC (4) | version (1) | cipher (1) | nonce_len (1) | tag_len (1)
 *           | nonce (12) | ciphertext (N) | tag (16 or 32)
 * </pre>
 *
 * <p>The header and caller supplied associated data are authenticated, so a
 * ciphertext cannot be moved between builds or between classes.
 *
 * <p>Cipher 1 is AES-256-GCM, cipher 3 is ChaCha20-Poly1305 (both through JCA),
 * cipher 2 is a zero-dependency ChaCha20 + HMAC-SHA256 construction used when
 * the JRE offers neither AEAD.
 */
public final class Envelope {

    public static final byte[] MAGIC = {'J', 'S', 'X', '1'};
    public static final int VERSION = 1;

    public static final int CIPHER_AES_GCM = 1;
    public static final int CIPHER_CHACHA_HMAC = 2;
    public static final int CIPHER_CHACHA_POLY = 3;

    public static final String AUTO = "auto";
    public static final String AES_GCM = "aesgcm";
    public static final String CHACHA = "chacha";
    public static final String CHACHA_POLY = "chacha20poly1305";
    public static final String CHACHA_PURE = "chacha-pure";

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final int NONCE_LENGTH = 12;
    private static final int HEADER_LENGTH = 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] ENVELOPE_SALT = ascii("jshield-envelope-v1");
    private static final byte[] ENVELOPE_INFO = ascii("encryption");
    private static final byte[] MODULE_SALT_PREFIX = ascii("jshield-class-v1");
    private static final byte[] MODULE_INFO = ascii("jshield-class-key");
    private static final byte[] AAD_PREFIX = ascii("jshield:class:");

    private static final Boolean AES_AVAILABLE = probe("AES/GCM/NoPadding", "AES", 32);
    private static final Boolean CHACHA_POLY_AVAILABLE = probe("ChaCha20-Poly1305", "ChaCha20", 32);

    private Envelope() {
    }

    // ------------------------------------------------------------------
    // Primitive helpers
    // ------------------------------------------------------------------

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception exc) {
            throw new IllegalStateException("SHA-256 is unavailable", exc);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[]... chunks) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] chunk : chunks) {
                mac.update(chunk);
            }
            return mac.doFinal();
        } catch (Exception exc) {
            throw new IllegalStateException("HmacSHA256 is unavailable", exc);
        }
    }

    /** HKDF-SHA256 (RFC 5869) extract-and-expand. */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (ikm == null || length <= 0) {
            throw new IllegalArgumentException("ikm and length are required");
        }
        byte[] realSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        byte[] prk = hmacSha256(realSalt, ikm);

        byte[] out = new byte[length];
        byte[] block = new byte[0];
        int copied = 0;
        int counter = 1;
        while (copied < length) {
            byte[] input = new byte[block.length + info.length + 1];
            System.arraycopy(block, 0, input, 0, block.length);
            System.arraycopy(info, 0, input, block.length, info.length);
            input[input.length - 1] = (byte) counter;
            block = hmacSha256(prk, input);
            int span = Math.min(block.length, length - copied);
            System.arraycopy(block, 0, out, copied, span);
            copied += span;
            counter++;
        }
        return out;
    }

    /** Per-class key: one leaked class does not expose the rest of the build. */
    public static byte[] deriveClassKey(byte[] buildKey, String internalName) {
        byte[] salt = sha256(concat(MODULE_SALT_PREFIX, ascii(internalName)));
        return hkdf(buildKey, salt, MODULE_INFO, 32);
    }

    /** AAD binds the ciphertext to one build and one class name. */
    public static byte[] classAad(String buildId, String internalName) {
        return concat(AAD_PREFIX, ascii(buildId + ":" + internalName));
    }

    public static byte[] deriveLicenseKey(byte[] masterKey, String buildId) {
        byte[] salt = sha256(concat(ascii("jshield-license-v1"), ascii(buildId)));
        return hkdf(masterKey, salt, ascii("jshield-license-key"), 32);
    }

    // ------------------------------------------------------------------
    // Cipher selection
    // ------------------------------------------------------------------

    public static boolean isAesGcmAvailable() {
        return AES_AVAILABLE;
    }

    public static boolean isChaChaPolyAvailable() {
        return CHACHA_POLY_AVAILABLE;
    }

    /**
     * Resolves a user supplied cipher name into a concrete, available one.
     *
     * @return one of {@link #AES_GCM}, {@link #CHACHA_POLY}, {@link #CHACHA_PURE}
     */
    public static String resolveCipher(String requested) {
        String value = (requested == null || requested.trim().isEmpty()) ? AUTO : requested.trim();
        if (AUTO.equals(value)) {
            if (AES_AVAILABLE) {
                return AES_GCM;
            }
            return CHACHA_POLY_AVAILABLE ? CHACHA_POLY : CHACHA_PURE;
        }
        if (AES_GCM.equals(value)) {
            if (!AES_AVAILABLE) {
                throw new IllegalArgumentException("AES-256-GCM is not available on this JRE");
            }
            return AES_GCM;
        }
        if (CHACHA_POLY.equals(value) || CHACHA.equals(value)) {
            if (CHACHA_POLY_AVAILABLE) {
                return CHACHA_POLY;
            }
            if (CHACHA_POLY.equals(value)) {
                throw new IllegalArgumentException("ChaCha20-Poly1305 requires JDK 11 or newer");
            }
            return CHACHA_PURE;
        }
        if (CHACHA_PURE.equals(value)) {
            return CHACHA_PURE;
        }
        throw new IllegalArgumentException("unknown cipher: " + requested);
    }

    public static boolean isEnvelope(byte[] data) {
        if (data == null || data.length < HEADER_LENGTH + NONCE_LENGTH + 16) {
            return false;
        }
        return data[0] == MAGIC[0] && data[1] == MAGIC[1]
                && data[2] == MAGIC[2] && data[3] == MAGIC[3];
    }

    // ------------------------------------------------------------------
    // Seal / open
    // ------------------------------------------------------------------

    public static byte[] seal(byte[] key, byte[] plaintext, byte[] aad, String cipher) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
        String resolved = resolveCipher(cipher);
        byte[] material = hkdf(key, ENVELOPE_SALT, ENVELOPE_INFO, 64);
        byte[] encryptionKey = Arrays.copyOfRange(material, 0, 32);
        byte[] macKey = Arrays.copyOfRange(material, 32, 64);

        int cipherId;
        int tagLength;
        if (AES_GCM.equals(resolved)) {
            cipherId = CIPHER_AES_GCM;
            tagLength = 16;
        } else if (CHACHA_POLY.equals(resolved)) {
            cipherId = CIPHER_CHACHA_POLY;
            tagLength = 16;
        } else {
            cipherId = CIPHER_CHACHA_HMAC;
            tagLength = 32;
        }

        byte[] nonce = randomBytes(NONCE_LENGTH);
        byte[] header = new byte[]{
                MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3],
                (byte) VERSION, (byte) cipherId, (byte) NONCE_LENGTH, (byte) tagLength
        };
        byte[] authenticated = concat(header, aad);

        byte[] ciphertext;
        byte[] tag;
        if (cipherId == CIPHER_AES_GCM || cipherId == CIPHER_CHACHA_POLY) {
            byte[] sealed = aead(true, resolved, encryptionKey, nonce, plaintext, authenticated);
            ciphertext = Arrays.copyOfRange(sealed, 0, sealed.length - 16);
            tag = Arrays.copyOfRange(sealed, sealed.length - 16, sealed.length);
        } else {
            ciphertext = ChaCha20.xor(encryptionKey, nonce, plaintext, 1);
            tag = hmacSha256(macKey, authenticated, ciphertext);
        }

        byte[] out = new byte[HEADER_LENGTH + NONCE_LENGTH + ciphertext.length + tagLength];
        System.arraycopy(header, 0, out, 0, HEADER_LENGTH);
        System.arraycopy(nonce, 0, out, HEADER_LENGTH, NONCE_LENGTH);
        System.arraycopy(ciphertext, 0, out, HEADER_LENGTH + NONCE_LENGTH, ciphertext.length);
        System.arraycopy(tag, 0, out, out.length - tagLength, tagLength);
        return out;
    }

    public static byte[] open(byte[] key, byte[] envelope, byte[] aad) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("key must be 32 bytes");
        }
        if (!isEnvelope(envelope)) {
            throw new ShieldCryptoException("invalid or corrupted data");
        }
        int version = envelope[4] & 0xFF;
        int cipherId = envelope[5] & 0xFF;
        int nonceLength = envelope[6] & 0xFF;
        int tagLength = envelope[7] & 0xFF;
        if (version != VERSION || nonceLength != NONCE_LENGTH) {
            throw new ShieldCryptoException("invalid or corrupted data");
        }
        if (cipherId != CIPHER_AES_GCM && cipherId != CIPHER_CHACHA_HMAC && cipherId != CIPHER_CHACHA_POLY) {
            throw new ShieldCryptoException("invalid or corrupted data");
        }
        int expectedTag = cipherId == CIPHER_CHACHA_HMAC ? 32 : 16;
        if (tagLength != expectedTag) {
            throw new ShieldCryptoException("invalid or corrupted data");
        }
        if (envelope.length < HEADER_LENGTH + nonceLength + tagLength) {
            throw new ShieldCryptoException("invalid or corrupted data");
        }

        byte[] header = Arrays.copyOfRange(envelope, 0, HEADER_LENGTH);
        byte[] nonce = Arrays.copyOfRange(envelope, HEADER_LENGTH, HEADER_LENGTH + nonceLength);
        byte[] body = Arrays.copyOfRange(envelope, HEADER_LENGTH + nonceLength, envelope.length - tagLength);
        byte[] tag = Arrays.copyOfRange(envelope, envelope.length - tagLength, envelope.length);
        byte[] authenticated = concat(header, aad);

        byte[] material = hkdf(key, ENVELOPE_SALT, ENVELOPE_INFO, 64);
        byte[] encryptionKey = Arrays.copyOfRange(material, 0, 32);
        byte[] macKey = Arrays.copyOfRange(material, 32, 64);

        try {
            if (cipherId == CIPHER_AES_GCM) {
                if (!AES_AVAILABLE) {
                    throw new ShieldCryptoException("this build uses AES-GCM; install a JRE with AES-256 support");
                }
                return aead(false, AES_GCM, encryptionKey, nonce, concat(body, tag), authenticated);
            }
            if (cipherId == CIPHER_CHACHA_POLY) {
                if (!CHACHA_POLY_AVAILABLE) {
                    throw new ShieldCryptoException("this build uses ChaCha20-Poly1305; JDK 11 or newer is required");
                }
                return aead(false, CHACHA_POLY, encryptionKey, nonce, concat(body, tag), authenticated);
            }
            byte[] expected = hmacSha256(macKey, authenticated, body);
            if (!MessageDigest.isEqual(expected, tag)) {
                throw new ShieldCryptoException("invalid or corrupted data");
            }
            return ChaCha20.xor(encryptionKey, nonce, body, 1);
        } catch (ShieldCryptoException exc) {
            throw exc;
        } catch (RuntimeException exc) {
            throw new ShieldCryptoException("invalid or corrupted data", exc);
        }
    }

    private static byte[] aead(boolean encrypt, String cipher, byte[] key, byte[] nonce,
                               byte[] input, byte[] aad) {
        try {
            boolean aes = AES_GCM.equals(cipher);
            Cipher engine = Cipher.getInstance(aes ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
            SecretKeySpec keySpec = new SecretKeySpec(key, aes ? "AES" : "ChaCha20");
            if (aes) {
                engine.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                        keySpec, new GCMParameterSpec(128, nonce));
            } else {
                engine.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                        keySpec, new IvParameterSpec(nonce));
            }
            engine.updateAAD(aad);
            return engine.doFinal(input);
        } catch (Exception exc) {
            if (encrypt) {
                throw new ShieldCryptoException("encryption failed", exc);
            }
            throw new ShieldCryptoException("invalid or corrupted data", exc);
        }
    }

    // ------------------------------------------------------------------
    // Compression
    // ------------------------------------------------------------------

    public static byte[] deflate(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        try {
            deflater.setInput(data);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 2));
            byte[] buffer = new byte[8192];
            while (!deflater.finished()) {
                int written = deflater.deflate(buffer);
                out.write(buffer, 0, written);
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    public static byte[] inflate(byte[] data) {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length * 2));
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int written = inflater.inflate(buffer);
                if (written == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                }
                out.write(buffer, 0, written);
            }
            return out.toByteArray();
        } catch (DataFormatException exc) {
            throw new ShieldCryptoException("invalid compressed payload", exc);
        } finally {
            inflater.end();
        }
    }

    // ------------------------------------------------------------------
    // Self test
    // ------------------------------------------------------------------

    /**
     * Exercises the RFC 8439 block vector and every available cipher.
     *
     * @return a comma separated list of the ciphers that were verified
     */
    public static String selftest() {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        byte[] nonce = Hex.decode("000000090000004a00000000");
        byte[] block = ChaCha20.blockBytes(key, nonce, 1);
        byte[] expected = Hex.decode(
                "10f1e7e4d13b5915500fdd1fa32071c4"
                        + "c7d1f4c733c068030422aa9ac3d46c4e"
                        + "d2826446079faa0914c2d705d98b02a2"
                        + "b5129cd1de164eb9cbd083e8a2503c4e");
        if (!Arrays.equals(block, expected)) {
            throw new IllegalStateException("ChaCha20 block vector mismatch");
        }

        StringBuilder verified = new StringBuilder();
        String[] ciphers = {CHACHA_PURE, CHACHA_POLY, AES_GCM};
        for (String cipher : ciphers) {
            if ((CHACHA_POLY.equals(cipher) && !CHACHA_POLY_AVAILABLE)
                    || (AES_GCM.equals(cipher) && !AES_AVAILABLE)) {
                continue;
            }
            for (int size : new int[]{0, 1, 14, 63, 64, 65, 4096}) {
                byte[] plain = new byte[size];
                for (int i = 0; i < size; i++) {
                    plain[i] = (byte) ((i * 7 + size) & 0xFF);
                }
                byte[] envelope = seal(key, plain, ascii("class:demo"), cipher);
                if (!Arrays.equals(plain, open(key, envelope, ascii("class:demo")))) {
                    throw new IllegalStateException(cipher + " round trip failed at size " + size);
                }
                try {
                    open(key, envelope, ascii("class:other"));
                    throw new IllegalStateException(cipher + " accepted a wrong aad");
                } catch (ShieldCryptoException expectedFailure) {
                    // expected
                }
                byte[] tampered = envelope.clone();
                tampered[tampered.length - 1] ^= 0x01;
                try {
                    open(key, tampered, ascii("class:demo"));
                    throw new IllegalStateException(cipher + " accepted a tampered tag");
                } catch (ShieldCryptoException expectedFailure) {
                    // expected
                }
            }
            if (verified.length() > 0) {
                verified.append(',');
            }
            verified.append(cipher);
        }
        return verified.toString();
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private static boolean probe(String transformation, String keyAlgorithm, int keyBits) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[keyBits], keyAlgorithm));
            return true;
        } catch (Exception exc) {
            return false;
        }
    }

    private static byte[] ascii(String text) {
        return text.getBytes(UTF_8);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] out = new byte[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }
}
