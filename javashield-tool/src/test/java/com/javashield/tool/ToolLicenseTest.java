package com.javashield.tool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.javashield.core.crypto.Ed25519;
import com.javashield.core.json.Json;

class ToolLicenseTest {

    @TempDir
    Path temp;

    private final byte[] seed = Ed25519.generateSeed();
    private final byte[] publicKey = Ed25519.publicKeyFromSeed(seed);

    private Map<String, Object> payload() {
        ToolEntitlement entitlement = new ToolEntitlement();
        entitlement.setLicenseId("JS-TEST-0001");
        entitlement.setCustomer("Acme");
        entitlement.setEdition("pro");
        entitlement.setFeatures(ToolFeatures.forEdition("pro"));
        entitlement.setMaxBuildsPerMonth(10);
        entitlement.setNotBefore(LocalDate.of(2026, 1, 1));
        entitlement.setExpires(LocalDate.of(2027, 1, 1));
        entitlement.setIssued("2026-01-01T00:00:00Z");
        return entitlement.toPayload();
    }

    private Map<String, Object> signed(Map<String, Object> payload) {
        return ToolLicense.signDocument(ToolLicense.FORMAT,
                ToolLicense.SIGNATURE_PREFIX, payload, seed);
    }

    @Test
    void signedLicenceRoundTrips() {
        ToolEntitlement entitlement = ToolLicense.parse(signed(payload()), publicKey);

        assertEquals("JS-TEST-0001", entitlement.getLicenseId());
        assertEquals("Acme", entitlement.getCustomer());
        assertEquals("pro", entitlement.getEdition());
        assertTrue(entitlement.isVerified());
        assertTrue(entitlement.hasFeature(ToolFeatures.CLI));
        assertTrue(entitlement.hasFeature(ToolFeatures.LICENSE_ISSUANCE));
        assertEquals(LocalDate.of(2027, 1, 1), entitlement.getExpires());
        assertEquals(10, entitlement.getMaxBuildsPerMonth());
    }

    @Test
    void tamperedPayloadIsRejected() {
        Map<String, Object> document = signed(payload());
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) document.get("payload");
        payload.put("customer", "Mallory");

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> ToolLicense.parse(document, publicKey));
        assertEquals(ToolCodes.LICENSE_INVALID, exc.getCode());
    }

    @Test
    void wrongKeyIsRejected() {
        byte[] otherPublicKey = Ed25519.publicKeyFromSeed(Ed25519.generateSeed());
        assertThrows(ToolLicenseException.class,
                () -> ToolLicense.parse(signed(payload()), otherPublicKey));
    }

    @Test
    void missingSignatureIsRejected() {
        Map<String, Object> document = signed(payload());
        document.remove("signature");
        assertThrows(ToolLicenseException.class,
                () -> ToolLicense.parse(document, publicKey));
    }

    @Test
    void licenceCanBeReadUnverifiedWithoutAKey() {
        ToolEntitlement entitlement = ToolLicense.parse(signed(payload()), null);
        assertFalse(entitlement.isVerified());
        assertEquals("JS-TEST-0001", entitlement.getLicenseId());
    }

    @Test
    void explicitEmptyFeatureListStaysEmpty() {
        Map<String, Object> payload = payload();
        payload.put("features", new ArrayList<String>());
        ToolEntitlement entitlement = ToolLicense.parse(signed(payload), publicKey);
        assertFalse(entitlement.hasFeature(ToolFeatures.CLI));
    }

    @Test
    void editionProvidesDefaultFeaturesWhenTheListIsAbsent() {
        Map<String, Object> payload = payload();
        payload.remove("features");
        ToolEntitlement entitlement = ToolLicense.parse(signed(payload), publicKey);
        assertTrue(entitlement.hasFeature(ToolFeatures.CLI));
        assertTrue(entitlement.hasFeature(ToolFeatures.LICENSE_ISSUANCE));
    }

    @Test
    void productMismatchIsRejected() {
        Map<String, Object> payload = payload();
        payload.put("product", "pyshield");
        assertThrows(ToolLicenseException.class, () -> ToolLicense.parse(signed(payload), publicKey));
    }

    @Test
    void wrongDocumentFormatIsRejected() {
        Map<String, Object> document = signed(payload());
        document.put("format", "pyshield-tool-license/1");
        assertThrows(ToolLicenseException.class, () -> ToolLicense.parse(document, publicKey));
    }

    @Test
    void licenceFileRoundTrips() {
        Path file = temp.resolve("tool-license.json");
        ToolLicense.writeDocument(file, signed(payload()));

        ToolEntitlement entitlement = ToolLicense.read(file, publicKey);
        assertEquals("JS-TEST-0001", entitlement.getLicenseId());
    }

    @Test
    void rootKeyDocumentRoundTrips() {
        Path file = temp.resolve("root.key");
        ToolLicense.writeDocument(file, ToolLicense.rootKeyDocument(seed));

        assertArrayEquals(seed, ToolLicense.readRootSeed(file));
        assertArrayEquals(publicKey,
                ToolLicense.decodePublicKey(ToolLicense.encodePublicKey(publicKey)));
        assertArrayEquals(publicKey,
                ToolLicense.decodePublicKey(Json.pretty(ToolLicense.rootKeyDocument(seed))));
    }

    @Test
    void revocationsRoundTrip() {
        List<String> ids = Arrays.asList("JS-1", "JS-2");
        Map<String, Object> document = ToolLicense.revocationsDocument(
                seed, ids, 3, "2026-11-14T00:00:00Z");

        Set<String> revoked = ToolLicense.verifyRevocations(document, publicKey);
        assertTrue(revoked.contains("JS-1"));
        assertTrue(revoked.contains("JS-2"));
        assertEquals(2, revoked.size());
    }

    @Test
    void tamperedRevocationsAreRejected() {
        Map<String, Object> document = ToolLicense.revocationsDocument(
                seed, Arrays.asList("JS-1"), 3, "2026-11-14T00:00:00Z");
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) document.get("payload");
        payload.put("revoked", new ArrayList<String>(Arrays.asList("JS-1", "JS-3")));

        assertThrows(ToolLicenseException.class,
                () -> ToolLicense.verifyRevocations(document, publicKey));
    }
}
