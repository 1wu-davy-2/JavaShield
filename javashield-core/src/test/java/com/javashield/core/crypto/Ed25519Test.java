package com.javashield.core.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ed25519（RFC 8032）实现测试：官方向量、往返、篡改检测与非法入参。
 */
class Ed25519Test {

    /** RFC 8032 §7.1 TEST 1：空消息。 */
    private static final String SEED_1 =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    private static final String PUBLIC_1 =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private static final String MESSAGE_1 = "";
    private static final String SIGNATURE_1 =
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
                    + "d25bf5f0595bbe24655141438e7a100b";

    /** RFC 8032 §7.1 TEST 2：单字节消息 0x72。 */
    private static final String SEED_2 =
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    private static final String PUBLIC_2 =
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    private static final String MESSAGE_2 = "72";
    private static final String SIGNATURE_2 =
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
                    + "387b2eaeb4302aeeb00d291612bb0c00";

    /** RFC 8032 §7.1 TEST 3：两字节消息 0xaf82。 */
    private static final String SEED_3 =
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    private static final String PUBLIC_3 =
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    private static final String MESSAGE_3 = "af82";
    private static final String SIGNATURE_3 =
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
                    + "4a7c15e9716ed28dc027beceea1ec40a";

    @Test
    void rfc8032Test1() {
        assertVector(SEED_1, PUBLIC_1, hex(MESSAGE_1), SIGNATURE_1);
    }

    @Test
    void rfc8032Test2() {
        assertVector(SEED_2, PUBLIC_2, hex(MESSAGE_2), SIGNATURE_2);
    }

    @Test
    void rfc8032Test3() {
        assertVector(SEED_3, PUBLIC_3, hex(MESSAGE_3), SIGNATURE_3);
    }

    @Test
    void emptyMessageRoundTrip() {
        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] signature = Ed25519.sign(seed, new byte[0]);

        assertEquals(Ed25519.SIGNATURE_LENGTH, signature.length);
        assertTrue(Ed25519.verify(publicKey, new byte[0], signature));
    }

    @Test
    void oneKilobyteMessageRoundTrip() {
        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] message = new byte[1024];
        new Random(0xC0FFEEL).nextBytes(message);

        byte[] signature = Ed25519.sign(seed, message);

        assertArrayEquals(publicKey, Ed25519.publicKeyFromSeed(seed));
        assertTrue(Ed25519.verify(publicKey, message, signature));
    }

    @Test
    void tamperedSignatureIsRejected() {
        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] message = "javashield".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = Ed25519.sign(seed, message);

        for (int bit = 0; bit < Ed25519.SIGNATURE_LENGTH * 8; bit += 37) {
            byte[] tampered = signature.clone();
            tampered[bit / 8] ^= (byte) (1 << (bit % 8));
            assertFalse(Ed25519.verify(publicKey, message, tampered),
                    "篡改签名第 " + bit + " 位后不应通过");
        }
    }

    @Test
    void tamperedMessageIsRejected() {
        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] message = "javashield-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = Ed25519.sign(seed, message);

        byte[] tampered = message.clone();
        tampered[tampered.length - 1] ^= 0x01;

        assertFalse(Ed25519.verify(publicKey, tampered, signature));
    }

    @Test
    void wrongPublicKeyIsRejected() {
        byte[] seed = Ed25519.generateSeed();
        byte[] otherSeed = Ed25519.generateSeed();
        byte[] message = "javashield".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = Ed25519.sign(seed, message);

        assertFalse(Ed25519.verify(Ed25519.publicKeyFromSeed(otherSeed), message, signature));
    }

    @Test
    void illegalSeedLengthIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> Ed25519.publicKeyFromSeed(new byte[Ed25519.SEED_LENGTH - 1]));
        assertThrows(IllegalArgumentException.class,
                () -> Ed25519.sign(new byte[Ed25519.SEED_LENGTH + 1], new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> Ed25519.publicKeyFromSeed(null));
    }

    @Test
    void malformedSignatureReturnsFalse() {
        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] message = new byte[]{1, 2, 3};
        byte[] signature = Ed25519.sign(seed, message);

        assertFalse(Ed25519.verify(publicKey, message, Arrays.copyOf(signature, 63)));
        assertFalse(Ed25519.verify(publicKey, message, null));
        assertFalse(Ed25519.verify(new byte[31], message, signature));
        assertFalse(Ed25519.verify(null, message, signature));
    }

    private static void assertVector(String seedHex, String publicKeyHex, byte[] message,
                                     String signatureHex) {
        byte[] seed = hex(seedHex);
        byte[] expectedPublicKey = hex(publicKeyHex);
        byte[] expectedSignature = hex(signatureHex);

        assertEquals(Ed25519.SEED_LENGTH, seed.length);
        assertEquals(Ed25519.PUBLIC_KEY_LENGTH, expectedPublicKey.length);
        assertEquals(Ed25519.SIGNATURE_LENGTH, expectedSignature.length);
        assertArrayEquals(expectedPublicKey, Ed25519.publicKeyFromSeed(seed));
        assertArrayEquals(expectedSignature, Ed25519.sign(seed, message));
        assertTrue(Ed25519.verify(expectedPublicKey, message, expectedSignature));
    }

    private static byte[] hex(String value) {
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("十六进制字符串长度必须为偶数");
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
