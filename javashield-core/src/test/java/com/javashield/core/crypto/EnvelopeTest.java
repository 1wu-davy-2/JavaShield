package com.javashield.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class EnvelopeTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final byte[] AAD = "jshield:class:build:com/acme/Foo".getBytes(UTF_8);

    @Test
    void hkdfMatchesRfc5869CaseOne() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        byte[] okm = Envelope.hkdf(ikm, salt, info, 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865",
                Hex.encode(okm));
    }

    @Test
    void chacha20MatchesRfc8439BlockVector() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        byte[] block = ChaCha20.blockBytes(key, Hex.decode("000000090000004a00000000"), 1);
        assertEquals("10f1e7e4d13b5915500fdd1fa32071c4"
                        + "c7d1f4c733c068030422aa9ac3d46c4e"
                        + "d2826446079faa0914c2d705d98b02a2"
                        + "b5129cd1de164eb9cbd083e8a2503c4e",
                Hex.encode(block));
    }

    @Test
    void everyAvailableCipherRoundTrips() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x42);
        String[] ciphers = {Envelope.CHACHA_PURE, Envelope.CHACHA_POLY, Envelope.AES_GCM};
        for (String cipher : ciphers) {
            if (Envelope.CHACHA_POLY.equals(cipher) && !Envelope.isChaChaPolyAvailable()) {
                continue;
            }
            if (Envelope.AES_GCM.equals(cipher) && !Envelope.isAesGcmAvailable()) {
                continue;
            }
            for (int size : new int[]{0, 1, 63, 64, 65, 4096}) {
                byte[] plain = new byte[size];
                for (int i = 0; i < size; i++) {
                    plain[i] = (byte) (i * 13 + size);
                }
                byte[] sealed = Envelope.seal(key, plain, AAD, cipher);
                assertArrayEquals(plain, Envelope.open(key, sealed, AAD),
                        cipher + " failed at size " + size);
            }
        }
    }

    @Test
    void aadPreventsCiphertextTransplant() {
        byte[] key = new byte[32];
        byte[] sealed = Envelope.seal(key, "payload".getBytes(UTF_8), AAD, Envelope.AES_GCM);
        byte[] otherAad = "jshield:class:build:com/acme/Bar".getBytes(UTF_8);
        assertThrows(ShieldCryptoException.class, () -> Envelope.open(key, sealed, otherAad));
    }

    @Test
    void tamperingIsRejected() {
        byte[] key = new byte[32];
        byte[] sealed = Envelope.seal(key, "payload".getBytes(UTF_8), AAD, Envelope.CHACHA_PURE);
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertThrows(ShieldCryptoException.class, () -> Envelope.open(key, tampered, AAD));
    }

    @Test
    void wrongKeyIsRejected() {
        byte[] sealed = Envelope.seal(new byte[32], "payload".getBytes(UTF_8), AAD, Envelope.AES_GCM);
        byte[] otherKey = new byte[32];
        Arrays.fill(otherKey, (byte) 1);
        assertThrows(ShieldCryptoException.class, () -> Envelope.open(otherKey, sealed, AAD));
    }

    @Test
    void deflateRoundTrip() {
        byte[] data = new byte[10_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 7);
        }
        byte[] packed = Envelope.deflate(data);
        assertTrue(packed.length < data.length);
        assertArrayEquals(data, Envelope.inflate(packed));
    }

    @Test
    void selftestCoversAllAvailableCiphers() {
        String result = Envelope.selftest();
        assertTrue(result.contains("chacha-pure"));
        if (Envelope.isAesGcmAvailable()) {
            assertTrue(result.contains("aesgcm"));
            assertFalse(result.isEmpty());
        }
        assertTrue(result.length() > 0);
    }
}
