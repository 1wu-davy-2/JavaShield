package com.javashield.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.javashield.core.crypto.Ed25519;

class ToolLicenseCheckerTest {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final LocalDate DAY = LocalDate.of(2026, 11, 14);

    @TempDir
    Path temp;

    private final byte[] seed = Ed25519.generateSeed();
    private final byte[] publicKey = Ed25519.publicKeyFromSeed(seed);

    private ToolStateStore store(String machine) {
        return new ToolStateStore(temp.resolve(machine), machine);
    }

    private ToolLicenseChecker checker(ToolStateStore store, LocalDate today) {
        return new ToolLicenseChecker(store, publicKey, false, today, null, 14, 3);
    }

    private ToolEntitlement licence(String licenseId, String edition) {
        ToolEntitlement entitlement = new ToolEntitlement();
        entitlement.setLicenseId(licenseId);
        entitlement.setCustomer("Acme");
        entitlement.setEdition(edition);
        entitlement.setFeatures(ToolFeatures.forEdition(edition));
        entitlement.setNotBefore(DAY.minusDays(10));
        entitlement.setExpires(DAY.plusDays(365));
        entitlement.setIssued(DAY.minusDays(10).toString());
        return entitlement;
    }

    private void install(ToolStateStore store, ToolEntitlement entitlement) {
        Map<String, Object> document = ToolLicense.signDocument(ToolLicense.FORMAT,
                ToolLicense.SIGNATURE_PREFIX, entitlement.toPayload(), seed);
        ToolLicense.writeDocument(
                store.resolve(ToolStateStore.TOOL_LICENSE_FILE), document);
    }

    @Test
    void developmentModeBypassesLicensingAndDoesNotRecord() {
        ToolStateStore store = store("dev");
        ToolLicenseChecker checker = new ToolLicenseChecker(store, null, true, DAY, null, 14, 3);

        ToolLicenseStatus status = checker.require(ToolFeatures.LICENSE_ISSUANCE);
        assertTrue(status.isAllowed());
        assertTrue(status.isDevelopment());
        assertEquals(ToolCodes.DEVELOPMENT, status.getCode());
        assertSame(status, checker.recordBuild(status));
        assertFalse(Files.exists(store.resolve(ToolStateStore.TRIAL_FILE)));
    }

    @Test
    void freshTrialAllowsThreeBuilds() {
        ToolLicenseStatus status = checker(store("trial"), DAY).check();
        assertTrue(status.isAllowed());
        assertTrue(status.isTrial());
        assertEquals(ToolCodes.TRIAL, status.getCode());
        assertEquals(3, status.getTrialBuildsLeft());
        assertEquals(14, status.getTrialDaysLeft());
    }

    @Test
    void trialStartsOnTheFirstRecordedBuild() {
        ToolStateStore store = store("trial-start");
        ToolLicenseChecker checker = checker(store, DAY);

        checker.check();
        assertFalse(Files.exists(store.resolve(ToolStateStore.TRIAL_FILE)));

        checker.recordBuild(checker.check());
        assertTrue(Files.exists(store.resolve(ToolStateStore.TRIAL_FILE)));
    }

    @Test
    void trialQuotaStopsAfterThreeBuilds() {
        ToolStateStore store = store("trial-quota");
        ToolLicenseChecker checker = checker(store, DAY);
        for (int index = 0; index < 3; index++) {
            ToolLicenseStatus status = checker.require(ToolFeatures.CLI);
            assertTrue(status.isAllowed());
            checker.recordBuild(status);
        }

        ToolLicenseStatus exhausted = checker.check();
        assertFalse(exhausted.isAllowed());
        assertEquals(ToolCodes.TRIAL_EXPIRED, exhausted.getCode());
        assertTrue(exhausted.getMessage().contains("exhausted"));

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> checker.require(ToolFeatures.CLI));
        assertEquals(ToolCodes.TRIAL_EXPIRED, exc.getCode());
    }

    @Test
    void trialExpiresAfterFourteenDays() {
        ToolStateStore store = store("trial-days");
        ToolLicenseChecker first = checker(store, DAY);
        first.recordBuild(first.check());

        ToolLicenseStatus expired = checker(store, DAY.plusDays(14)).check();
        assertFalse(expired.isAllowed());
        assertTrue(expired.isTrial());
        assertEquals(ToolCodes.TRIAL_EXPIRED, expired.getCode());
        assertEquals(0, expired.getTrialDaysLeft());
    }

    @Test
    void trialPolicyRejectsPaidBuildOptions() {
        ToolLicenseStatus trial = checker(store("trial-policy"), DAY).check();
        assertTrue(ToolTrialPolicy.problems(trial, new ToolTrialPolicy.BuildProfile()).isEmpty());

        ToolTrialPolicy.BuildProfile inPlace = new ToolTrialPolicy.BuildProfile();
        inPlace.inPlace = true;
        assertFalse(ToolTrialPolicy.problems(trial, inPlace).isEmpty());

        ToolTrialPolicy.BuildProfile full = new ToolTrialPolicy.BuildProfile();
        full.integrity = "full";
        assertFalse(ToolTrialPolicy.problems(trial, full).isEmpty());

        ToolTrialPolicy.BuildProfile customer = new ToolTrialPolicy.BuildProfile();
        customer.customerWatermark = true;
        assertFalse(ToolTrialPolicy.problems(trial, customer).isEmpty());

        ToolTrialPolicy.BuildProfile binding = new ToolTrialPolicy.BuildProfile();
        binding.explicitBinding = true;
        assertFalse(ToolTrialPolicy.problems(trial, binding).isEmpty());

        ToolTrialPolicy.BuildProfile firstRun = new ToolTrialPolicy.BuildProfile();
        firstRun.bindFirstRun = true;
        assertFalse(ToolTrialPolicy.problems(trial, firstRun).isEmpty());
    }

    @Test
    void signedLicenceGrantsItsFeatures() {
        ToolStateStore store = store("licensed");
        install(store, licence("JS-PRO", "pro"));
        ToolLicenseChecker checker = checker(store, DAY);

        ToolLicenseStatus status = checker.require(ToolFeatures.MAVEN);
        assertTrue(status.isAllowed());
        assertTrue(status.isLicensed());
        assertTrue(status.isVerified());

        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> checker.require(ToolFeatures.NATIVE_RUNTIME));
        assertEquals(ToolCodes.FEATURE_MISSING, exc.getCode());
    }

    @Test
    void signedFeatureListIsAuthoritative() {
        ToolStateStore store = store("feature-list");
        ToolEntitlement entitlement = licence("JS-MAVEN-ONLY", "pro");
        entitlement.setFeatures(new HashSet<String>(Arrays.asList(ToolFeatures.MAVEN)));
        install(store, entitlement);
        ToolLicenseChecker checker = checker(store, DAY);

        assertTrue(checker.require(ToolFeatures.MAVEN).isAllowed());
        ToolLicenseException exc = assertThrows(ToolLicenseException.class,
                () -> checker.require(ToolFeatures.CLI));
        assertEquals(ToolCodes.FEATURE_MISSING, exc.getCode());
    }

    @Test
    void monthlyQuotaIsEnforced() {
        ToolStateStore store = store("quota");
        ToolEntitlement entitlement = licence("JS-QUOTA", "pro");
        entitlement.setMaxBuildsPerMonth(2);
        install(store, entitlement);
        ToolLicenseChecker checker = checker(store, DAY);

        checker.recordBuild(checker.require(ToolFeatures.MAVEN));
        checker.recordBuild(checker.require(ToolFeatures.MAVEN));

        ToolLicenseStatus exhausted = checker.check();
        assertFalse(exhausted.isAllowed());
        assertEquals(ToolCodes.QUOTA_EXHAUSTED, exhausted.getCode());
        assertEquals(2, exhausted.getQuotaLimit());
    }

    @Test
    void quotaResetsInTheNextMonth() {
        ToolStateStore store = store("quota-reset");
        ToolEntitlement entitlement = licence("JS-RESET", "pro");
        entitlement.setNotBefore(DAY.minusDays(60));
        entitlement.setMaxBuildsPerMonth(1);
        install(store, entitlement);

        ToolLicenseChecker october = checker(store, LocalDate.of(2026, 10, 31));
        october.recordBuild(october.require(ToolFeatures.MAVEN));
        assertFalse(october.check().isAllowed());

        ToolLicenseChecker november = checker(store, LocalDate.of(2026, 11, 1));
        assertTrue(november.require(ToolFeatures.MAVEN).isAllowed());
    }

    @Test
    void expiredAndNotYetValidLicencesAreRejected() {
        ToolStateStore expiredStore = store("expired");
        ToolEntitlement expired = licence("JS-EXPIRED", "pro");
        expired.setExpires(DAY.minusDays(1));
        install(expiredStore, expired);
        ToolLicenseStatus expiredStatus = checker(expiredStore, DAY).check();
        assertFalse(expiredStatus.isAllowed());
        assertEquals(ToolCodes.EXPIRED, expiredStatus.getCode());

        ToolStateStore futureStore = store("future");
        ToolEntitlement future = licence("JS-FUTURE", "pro");
        future.setNotBefore(DAY.plusDays(1));
        install(futureStore, future);
        ToolLicenseStatus futureStatus = checker(futureStore, DAY).check();
        assertFalse(futureStatus.isAllowed());
        assertEquals(ToolCodes.NOT_YET_VALID, futureStatus.getCode());
    }

    @Test
    void machineBindingIsEnforced() {
        ToolEntitlement entitlement = licence("JS-BOUND", "pro");
        entitlement.setBindMode("fixed");
        entitlement.setFingerprints(Arrays.asList("machine-b"));

        ToolStateStore wrong = store("machine-a");
        install(wrong, entitlement);
        ToolLicenseStatus denied = checker(wrong, DAY).check();
        assertFalse(denied.isAllowed());
        assertEquals(ToolCodes.MACHINE_MISMATCH, denied.getCode());

        ToolStateStore right = store("machine-b");
        install(right, entitlement);
        assertTrue(checker(right, DAY).require(ToolFeatures.MAVEN).isAllowed());
    }

    @Test
    void activationRequiredNeedsALocalRecord() {
        ToolStateStore store = store("activation");
        ToolEntitlement entitlement = licence("JS-ACTIVATION", "pro");
        entitlement.setActivationRequired(true);
        install(store, entitlement);

        ToolLicenseChecker checker = checker(store, DAY);
        ToolLicenseStatus denied = checker.check();
        assertFalse(denied.isAllowed());
        assertEquals(ToolCodes.ACTIVATION_REQUIRED, denied.getCode());

        checker.activate(entitlement);
        assertTrue(checker.check().isAllowed());
    }

    @Test
    void revokedLicenceIsRejected() {
        ToolStateStore store = store("revoked");
        ToolEntitlement entitlement = licence("JS-REVOKED", "pro");
        install(store, entitlement);
        Map<String, Object> revocations = ToolLicense.revocationsDocument(
                seed, Arrays.asList("JS-REVOKED"), 1, "2026-11-14T00:00:00Z");
        ToolLicense.writeDocument(
                store.resolve(ToolStateStore.REVOCATIONS_FILE), revocations);

        ToolLicenseStatus status = checker(store, DAY).check();
        assertFalse(status.isAllowed());
        assertEquals(ToolCodes.REVOKED, status.getCode());
    }

    @Test
    void tamperedLicenceFileIsRejected() throws Exception {
        ToolStateStore store = store("tampered-licence");
        install(store, licence("JS-TAMPERED", "pro"));
        Path file = store.resolve(ToolStateStore.TOOL_LICENSE_FILE);

        String text = new String(Files.readAllBytes(file), UTF_8);
        String changed = text.replace("\"edition\": \"pro\"", "\"edition\": \"enterprise\"");
        assertNotEquals(text, changed);
        Files.write(file, changed.getBytes(UTF_8));

        ToolLicenseStatus status = checker(store, DAY).check();
        assertFalse(status.isAllowed());
        assertEquals(ToolCodes.LICENSE_INVALID, status.getCode());
    }

    @Test
    void licenceWithoutAConfiguredKeyIsUnverifiedButUsable() {
        ToolStateStore store = store("unverified");
        install(store, licence("JS-UNVERIFIED", "pro"));

        ToolLicenseChecker checker = new ToolLicenseChecker(store, null, false, DAY, null, 14, 3);
        ToolLicenseStatus status = checker.require(ToolFeatures.MAVEN);
        assertTrue(status.isAllowed());
        assertTrue(status.isLicensed());
        assertFalse(status.isVerified());
    }

    @Test
    void tamperedTrialStateIsReported() {
        ToolStateStore store = store("tampered-trial");
        ToolStateStore.writeFile(store.resolve(ToolStateStore.TRIAL_FILE), "{}\n");

        ToolLicenseStatus status = checker(store, DAY).check();
        assertFalse(status.isAllowed());
        assertEquals(ToolCodes.STATE_INVALID, status.getCode());
    }
}
