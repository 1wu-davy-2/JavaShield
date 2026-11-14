package com.javashield.core.license;

import java.time.LocalDate;
import java.util.List;

import com.javashield.core.Product;

/** Applies the licence rules: build, product, dates, grace period, machine. */
public final class LicenseVerifier {

    private static final int MAX_GRACE_DAYS = 3650;

    private LicenseVerifier() {
    }

    public static LicenseStatus verify(LicensePayload payload, String expectedBuildId,
                                       String fingerprint, LocalDate today) {
        if (payload == null) {
            return LicenseStatus.fail("licence is missing", null);
        }
        if (payload.getFormat() != Integer.parseInt(Product.LICENSE_FORMAT)) {
            return LicenseStatus.fail("unsupported licence format", payload);
        }
        if (!Product.NAME.equals(payload.getProduct())) {
            return LicenseStatus.fail("licence is for another product", payload);
        }
        if (expectedBuildId != null && !expectedBuildId.equals(payload.getBuildId())) {
            return LicenseStatus.fail("licence belongs to another build", payload);
        }
        if (payload.getBuildKey() == null || payload.getBuildKey().length != 32) {
            return LicenseStatus.fail("licence has an invalid build key", payload);
        }
        if (payload.getGraceDays() < 0 || payload.getGraceDays() > MAX_GRACE_DAYS) {
            return LicenseStatus.fail("licence has an invalid grace period", payload);
        }

        LocalDate now = today == null ? LocalDate.now() : today;
        try {
            LocalDate notBefore = Dates.parseDate(payload.getNotBefore());
            if (notBefore != null && now.isBefore(notBefore.minusDays(1))) {
                return LicenseStatus.fail("system clock is earlier than the issue date", payload);
            }
            LocalDate expires = Dates.parseDate(payload.getExpires());
            if (expires != null) {
                LocalDate lastDay = expires.plusDays(payload.getGraceDays());
                if (now.isAfter(lastDay)) {
                    return LicenseStatus.fail("licence expired on " + expires, payload);
                }
                boolean inGrace = now.isAfter(expires);
                if (inGrace) {
                    return LicenseStatus.ok(true, payload, "licence is in its grace period until " + lastDay);
                }
            }
        } catch (IllegalArgumentException exc) {
            return LicenseStatus.fail("licence has an invalid date: " + exc.getMessage(), payload);
        }

        List<String> fingerprints = payload.getFingerprints();
        if (fingerprints != null && !fingerprints.isEmpty()) {
            if (fingerprint == null || !containsIgnoreCase(fingerprints, fingerprint)) {
                return LicenseStatus.fail("this machine is not licensed", payload);
            }
        }
        return LicenseStatus.ok(false, payload, "licence is valid");
    }

    private static boolean containsIgnoreCase(List<String> values, String expected) {
        for (String value : values) {
            if (value != null && value.trim().equalsIgnoreCase(expected.trim())) {
                return true;
            }
        }
        return false;
    }
}
