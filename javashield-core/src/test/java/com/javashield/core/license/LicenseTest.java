package com.javashield.core.license;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;

import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Envelope;

class LicenseTest {

    private static final byte[] MASTER = new byte[32];
    private static final byte[] SIGNING = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            MASTER[i] = (byte) i;
            SIGNING[i] = (byte) (i + 1);
        }
    }

    private LicensePayload payload() {
        LicensePayload payload = new LicensePayload();
        payload.setBuildId("0123456789abcdef");
        payload.setBuildKey(Envelope.randomBytes(32));
        payload.setCipher("aesgcm");
        payload.setCreated(Dates.now());
        payload.setNotBefore("2026-01-01");
        payload.setExpires("2027-12-31");
        payload.setGraceDays(14);
        payload.setCustomer("ACME");
        payload.setEdition("enterprise");
        return payload;
    }

    @Test
    void roundTripKeepsEveryField() {
        LicensePayload original = payload();
        String text = License.encode(original, MASTER, SIGNING);
        LicensePayload decoded = License.decode(text, MASTER, original.getBuildId(),
                Ed25519.publicKeyFromSeed(SIGNING));

        assertEquals(original.getBuildId(), decoded.getBuildId());
        assertEquals("ACME", decoded.getCustomer());
        assertEquals("enterprise", decoded.getEdition());
        assertEquals(14, decoded.getGraceDays());
        assertEquals(original.getExpires(), decoded.getExpires());
        assertEquals(original.getBuildKey().length, decoded.getBuildKey().length);
    }

    @Test
    void tamperedBodyIsRejected() {
        String text = License.encode(payload(), MASTER, SIGNING);
        char[] chars = text.toCharArray();
        int index = chars.length / 2;
        chars[index] = chars[index] == 'A' ? 'B' : 'A';
        assertThrows(RuntimeException.class,
                () -> License.decode(new String(chars), MASTER, "0123456789abcdef",
                        Ed25519.publicKeyFromSeed(SIGNING)));
    }

    @Test
    void anotherMasterKeyCannotOpenTheLicense() {
        String text = License.encode(payload(), MASTER, SIGNING);
        byte[] other = new byte[32];
        other[0] = 9;
        assertThrows(RuntimeException.class,
                () -> License.decode(text, other, "0123456789abcdef",
                        Ed25519.publicKeyFromSeed(SIGNING)));
    }

    @Test
    void signaturePreventsForgeryEvenWithTheMasterKey() {
        LicensePayload original = payload();
        String text = License.encode(original, MASTER, SIGNING);
        LicensePayload decoded = License.decode(text, MASTER, original.getBuildId(),
                Ed25519.publicKeyFromSeed(SIGNING));
        decoded.setExpires("2099-12-31");

        String forged = License.encode(decoded, MASTER, new byte[32]);
        assertThrows(IllegalArgumentException.class,
                () -> License.decode(forged, MASTER, original.getBuildId(),
                        Ed25519.publicKeyFromSeed(SIGNING)));
    }

    @Test
    void expiredLicenseIsRejectedButGraceIsHonoured() {
        LicensePayload payload = payload();
        payload.setExpires("2026-01-01");
        payload.setGraceDays(30);
        LocalDate today = LocalDate.of(2026, 11, 14);

        LicenseStatus strict = LicenseVerifier.verify(payload, payload.getBuildId(), null, today);
        assertFalse(strict.isValid());

        payload.setGraceDays(400);
        LicenseStatus grace = LicenseVerifier.verify(payload, payload.getBuildId(), null, today);
        assertTrue(grace.isValid());
        assertTrue(grace.isInGrace());
    }

    @Test
    void perpetualLicenseNeverExpires() {
        LicensePayload payload = payload();
        payload.setExpires(null);
        LicenseStatus status = LicenseVerifier.verify(payload, payload.getBuildId(), null,
                LocalDate.of(2099, 1, 1));
        assertTrue(status.isValid());
    }

    @Test
    void machineBindingIsEnforced() {
        LicensePayload payload = payload();
        payload.getFingerprints().add("aaaa");
        assertTrue(LicenseVerifier.verify(payload, payload.getBuildId(), "aaaa",
                LocalDate.of(2026, 11, 14)).isValid());
        assertFalse(LicenseVerifier.verify(payload, payload.getBuildId(), "bbbb",
                LocalDate.of(2026, 11, 14)).isValid());
    }

    @Test
    void clockBeforeIssueDateIsRejected() {
        LicensePayload payload = payload();
        payload.setNotBefore("2026-06-01");
        LicenseStatus status = LicenseVerifier.verify(payload, payload.getBuildId(), null,
                LocalDate.of(2026, 1, 1));
        assertFalse(status.isValid());
        assertNotNull(status.getMessage());
    }

    @Test
    void anotherBuildIsRejected() {
        LicensePayload payload = payload();
        assertFalse(LicenseVerifier.verify(payload, "ffffffffffffffff", null,
                LocalDate.of(2026, 11, 14)).isValid());
    }
}
