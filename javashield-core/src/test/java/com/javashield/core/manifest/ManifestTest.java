package com.javashield.core.manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.javashield.core.crypto.Ed25519;

class ManifestTest {

    private static final byte[] SIGNING = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            SIGNING[i] = (byte) (i * 3);
        }
    }

    @Test
    void signatureCoversEveryField() {
        Map<String, Object> manifest = Manifest.create("0123456789abcdef", "aesgcm", "protected");
        Manifest.putClass(manifest, "com/acme/Foo", "com/acme/Foo.class",
                "META-INF/jshield/p/abc.bin", "11", "22", "33");
        Manifest.putFile(manifest, "jshield-agent.jar", "44", 1024);

        Map<String, Object> signed = Manifest.sign(manifest, SIGNING);
        assertTrue(Manifest.verifySignature(signed, Ed25519.publicKeyFromSeed(SIGNING)));

        signed.put("build_id", "ffffffffffffffff");
        assertFalse(Manifest.verifySignature(signed, Ed25519.publicKeyFromSeed(SIGNING)));
    }

    @Test
    void serializationRoundTrips() {
        Map<String, Object> manifest = Manifest.create("0123456789abcdef", "chacha-pure", "protected");
        Manifest.putClass(manifest, "com/acme/Foo", "com/acme/Foo.class",
                "META-INF/jshield/p/abc.bin", "11", "22", "33");
        Map<String, Object> signed = Manifest.sign(manifest, SIGNING);

        String text = Manifest.serialize(signed);
        Map<String, Object> parsed = Manifest.parse(text);
        assertEquals("0123456789abcdef", parsed.get("build_id"));
        assertEquals(1, Manifest.classes(parsed).size());
        assertTrue(Manifest.verifySignature(parsed, Ed25519.publicKeyFromSeed(SIGNING)));
    }

    @Test
    void unknownFormatIsRejected() {
        try {
            Manifest.parse("{\"format\":9,\"classes\":{}}");
            throw new AssertionError("expected a parse failure");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("format"));
        }
    }
}
