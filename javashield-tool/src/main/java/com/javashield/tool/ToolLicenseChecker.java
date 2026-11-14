package com.javashield.tool;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import com.javashield.core.license.Dates;

/**
 * Checks the builder licence, enforces the trial policy and records builds.
 *
 * <p>The check order mirrors PyShield: development mode, then a signed licence,
 * then the trial. A present-but-invalid licence never silently falls back to
 * the trial.</p>
 */
public final class ToolLicenseChecker {

    public static final int DEFAULT_TRIAL_DAYS = 14;
    public static final int DEFAULT_TRIAL_BUILDS = 3;

    private static final String TRIAL_FORMAT = "jshield-trial/1";
    private static final String QUOTA_FORMAT = "jshield-quota/1";
    private static final String INSTALL_FORMAT = "jshield-install/1";
    private static final String TRIAL_PURPOSE = "trial";
    private static final String QUOTA_PURPOSE = "quota";
    private static final String INSTALL_PURPOSE = "install";
    private static final Object STATE_LOCK = new Object();

    private final ToolStateStore store;
    private final byte[] publicKey;
    private final boolean devMode;
    private final LocalDate today;
    private final Path licensePath;
    private final int trialDays;
    private final int trialBuilds;
    private final String machine;

    public static ToolLicenseChecker createDefault() {
        return createDefault(null);
    }

    /**
     * @param licensePath an explicit licence file, or {@code null} to use the
     *                    installed state directory
     */
    public static ToolLicenseChecker createDefault(Path licensePath) {
        return new ToolLicenseChecker(
                new ToolStateStore(ToolStateStore.defaultHome()),
                ToolLicense.loadPublicKey(),
                ToolLicense.devMode(),
                LocalDate.now(ZoneOffset.UTC),
                licensePath);
    }

    public ToolLicenseChecker(ToolStateStore store, byte[] publicKey, boolean devMode,
                              LocalDate today, Path licensePath) {
        this(store, publicKey, devMode, today, licensePath,
                environmentInt("JAVASHIELD_TRIAL_DAYS", DEFAULT_TRIAL_DAYS),
                environmentInt("JAVASHIELD_TRIAL_BUILDS", DEFAULT_TRIAL_BUILDS));
    }

    public ToolLicenseChecker(ToolStateStore store, byte[] publicKey, boolean devMode,
                              LocalDate today, Path licensePath,
                              int trialDays, int trialBuilds) {
        if (store == null) {
            throw new IllegalArgumentException("tool state store is required");
        }
        this.store = store;
        this.publicKey = publicKey;
        this.devMode = devMode;
        this.today = today == null ? LocalDate.now(ZoneOffset.UTC) : today;
        this.licensePath = licensePath;
        this.trialDays = trialDays <= 0 ? DEFAULT_TRIAL_DAYS : trialDays;
        this.trialBuilds = trialBuilds <= 0 ? DEFAULT_TRIAL_BUILDS : trialBuilds;
        this.machine = store.machine();
    }

    /** Evaluates the current tool licence state without recording a build. */
    public ToolLicenseStatus check() {
        if (devMode) {
            return ToolLicenseStatus.development(machine);
        }
        Path file = licensePath;
        if (file != null && !Files.isRegularFile(file)) {
            return missing(file);
        }
        if (file == null) {
            file = store.resolve(ToolStateStore.TOOL_LICENSE_FILE);
        }
        if (Files.isRegularFile(file)) {
            ToolEntitlement entitlement;
            try {
                entitlement = ToolLicense.read(file, publicKey);
            } catch (ToolLicenseException exc) {
                return denied(ToolCodes.MODE_INVALID, ToolCodes.LICENSE_INVALID,
                        exc.getMessage(), null);
            }
            return checkEntitlement(entitlement);
        }
        return checkTrial();
    }

    private ToolLicenseStatus checkEntitlement(ToolEntitlement entitlement) {
        if (entitlement.getNotBefore() != null && today.isBefore(entitlement.getNotBefore())) {
            return denied(ToolCodes.MODE_INVALID, ToolCodes.NOT_YET_VALID,
                    "tool licence is not valid before " + entitlement.getNotBefore(),
                    entitlement);
        }
        if (entitlement.getExpires() != null) {
            LocalDate last = entitlement.getExpires().plusDays(
                    Math.max(0, entitlement.getGraceDays()));
            if (today.isAfter(last)) {
                String message = "tool licence expired on " + entitlement.getExpires();
                if (entitlement.getGraceDays() > 0) {
                    message += " (grace ended " + last + ")";
                }
                return denied(ToolCodes.MODE_INVALID, ToolCodes.EXPIRED, message, entitlement);
            }
        }
        if (entitlement.isActivationRequired()) {
            Map<String, Object> install;
            try {
                install = store.readSealed(
                        store.resolve(ToolStateStore.INSTALL_FILE), INSTALL_PURPOSE);
            } catch (ToolLicenseException exc) {
                return stateError(exc, entitlement);
            }
            if (install == null
                    || !entitlement.getLicenseId().equals(
                            ToolValues.string(install.get("license_id"), null))) {
                return denied(ToolCodes.MODE_INVALID, ToolCodes.ACTIVATION_REQUIRED,
                        "tool licence must be activated on this machine", entitlement);
            }
            String activatedMachine = ToolValues.string(install.get("machine"), null);
            if (activatedMachine != null && !activatedMachine.equals(machine)) {
                return denied(ToolCodes.MODE_INVALID, ToolCodes.MACHINE_MISMATCH,
                        "tool licence is activated on another machine", entitlement);
            }
        }
        if (!entitlement.machineAllowed(machine)) {
            return denied(ToolCodes.MODE_INVALID, ToolCodes.MACHINE_MISMATCH,
                    "tool licence is bound to another machine", entitlement);
        }
        if (isRevoked(entitlement)) {
            return denied(ToolCodes.MODE_INVALID, ToolCodes.REVOKED,
                    "tool licence has been revoked", entitlement);
        }

        int[] quota;
        try {
            quota = quota(entitlement);
        } catch (ToolLicenseException exc) {
            return stateError(exc, entitlement);
        }
        int limit = entitlement.getMaxBuildsPerMonth();
        if (limit > 0 && quota[0] >= limit) {
            ToolLicenseStatus status = denied(ToolCodes.MODE_INVALID,
                    ToolCodes.QUOTA_EXHAUSTED,
                    "monthly build quota exhausted (" + quota[0] + "/" + limit + ")",
                    entitlement);
            status.setQuotaUsed(quota[0]);
            return status;
        }
        return ToolLicenseStatus.licensed(entitlement, machine, quota[0], quota[1]);
    }

    private ToolLicenseStatus checkTrial() {
        Map<String, Object> state;
        try {
            state = store.readSealed(store.resolve(ToolStateStore.TRIAL_FILE), TRIAL_PURPOSE);
        } catch (ToolLicenseException exc) {
            return stateError(exc, null);
        }

        int days = trialDays;
        int maxBuilds = trialBuilds;
        int builds = 0;
        LocalDate started = today;
        if (state != null) {
            days = positive(ToolValues.integer(state.get("days"), days), days);
            maxBuilds = positive(ToolValues.integer(state.get("max_builds"), maxBuilds),
                    maxBuilds);
            builds = Math.max(0, ToolValues.integer(state.get("builds"), 0));
            LocalDate parsed = parseDate(state.get("started"));
            if (parsed != null) {
                started = parsed;
            }
        }

        long elapsed = ChronoUnit.DAYS.between(started, today);
        if (elapsed < 0) {
            elapsed = 0;
        }
        int daysLeft = (int) Math.max(0, (long) days - elapsed);
        int buildsLeft = Math.max(0, maxBuilds - builds);
        if (daysLeft <= 0 || buildsLeft <= 0) {
            String message = daysLeft <= 0
                    ? "trial period has expired"
                    : "trial build quota is exhausted (" + builds + "/" + maxBuilds + ")";
            return ToolLicenseStatus.trial(ToolCodes.TRIAL_EXPIRED, message, false,
                    machine, daysLeft, buildsLeft, builds, maxBuilds);
        }
        String message = "trial: " + daysLeft + " day(s) and " + buildsLeft
                + " build(s) left";
        return ToolLicenseStatus.trial(ToolCodes.TRIAL, message, true,
                machine, daysLeft, buildsLeft, builds, maxBuilds);
    }

    /**
     * Validates the licence and checks that it grants {@code feature}.
     *
     * @throws ToolLicenseException when the licence is not valid or the feature
     *                              is not included
     */
    public ToolLicenseStatus require(String feature) {
        ToolLicenseStatus status = check();
        if (!status.isAllowed()) {
            throw new ToolLicenseException(status.getCode(), status.getMessage());
        }
        if (feature == null || feature.trim().isEmpty() || status.isDevelopment()) {
            return status;
        }
        if (status.isTrial()) {
            if (!ToolFeatures.trialIncludes(feature)) {
                throw new ToolLicenseException(ToolCodes.FEATURE_MISSING,
                        "trial edition does not include the '" + feature + "' feature");
            }
            return status;
        }
        ToolEntitlement entitlement = status.getEntitlement();
        if (entitlement == null || !entitlement.hasFeature(feature)) {
            throw new ToolLicenseException(ToolCodes.FEATURE_MISSING,
                    "tool licence does not include the '" + feature + "' feature");
        }
        return status;
    }

    /**
     * Consumes one build from the trial or monthly quota.
     *
     * <p>Call this after validation and before starting the build. A failed
     * build is deliberately not refunded.</p>
     */
    public ToolLicenseStatus recordBuild(ToolLicenseStatus status) {
        if (status == null) {
            throw new IllegalArgumentException("tool licence status is required");
        }
        if (!status.isAllowed()) {
            throw new ToolLicenseException(status.getCode(), status.getMessage());
        }
        if (status.isDevelopment()) {
            return status;
        }
        synchronized (STATE_LOCK) {
            if (status.isTrial()) {
                return recordTrialBuild(status);
            }
            if (status.isLicensed()) {
                return recordLicensedBuild(status);
            }
        }
        return status;
    }

    private ToolLicenseStatus recordTrialBuild(ToolLicenseStatus status) {
        Path file = store.resolve(ToolStateStore.TRIAL_FILE);
        Map<String, Object> state = store.readSealed(file, TRIAL_PURPOSE);

        int days = trialDays;
        int maxBuilds = trialBuilds;
        int builds = 0;
        LocalDate started = today;
        if (state != null) {
            days = positive(ToolValues.integer(state.get("days"), days), days);
            maxBuilds = positive(ToolValues.integer(state.get("max_builds"), maxBuilds),
                    maxBuilds);
            builds = Math.max(0, ToolValues.integer(state.get("builds"), 0));
            LocalDate parsed = parseDate(state.get("started"));
            if (parsed != null) {
                started = parsed;
            }
        }
        long elapsed = ChronoUnit.DAYS.between(started, today);
        if (elapsed < 0) {
            elapsed = 0;
        }
        int daysLeft = (int) Math.max(0, (long) days - elapsed);
        if (daysLeft <= 0) {
            throw new ToolLicenseException(ToolCodes.TRIAL_EXPIRED,
                    "trial period has expired");
        }
        if (builds >= maxBuilds) {
            throw new ToolLicenseException(ToolCodes.TRIAL_EXPIRED,
                    "trial build quota is exhausted (" + builds + "/" + maxBuilds + ")");
        }

        Map<String, Object> next = state == null
                ? new LinkedHashMap<String, Object>() : state;
        next.put("format", TRIAL_FORMAT);
        next.put("started", started.toString());
        next.put("builds", Long.valueOf(builds + 1L));
        next.put("days", Long.valueOf(days));
        next.put("max_builds", Long.valueOf(maxBuilds));
        next.put("machine", machine);
        next.put("last_build", today.toString());
        store.writeSealed(file, TRIAL_PURPOSE, next);

        int left = maxBuilds - builds - 1;
        status.setTrialBuildsUsed(builds + 1);
        status.setTrialBuildsLeft(left);
        status.setTrialDaysLeft(daysLeft);
        status.setTrialMaxBuilds(maxBuilds);
        status.setMessage("trial: " + daysLeft + " day(s) and " + left + " build(s) left");
        return status;
    }

    private ToolLicenseStatus recordLicensedBuild(ToolLicenseStatus status) {
        ToolEntitlement entitlement = status.getEntitlement();
        if (entitlement == null) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool licence state is missing");
        }
        Path file = store.resolve(ToolStateStore.QUOTA_FILE);
        Map<String, Object> state = store.readSealed(file, QUOTA_PURPOSE);
        int limit = entitlement.getMaxBuildsPerMonth();
        int used = 0;
        if (state != null
                && entitlement.getLicenseId().equals(
                        ToolValues.string(state.get("license_id"), null))
                && month(today).equals(ToolValues.string(state.get("month"), null))) {
            used = Math.max(0, ToolValues.integer(state.get("used"), 0));
        }
        if (limit > 0 && used >= limit) {
            throw new ToolLicenseException(ToolCodes.QUOTA_EXHAUSTED,
                    "monthly build quota exhausted (" + used + "/" + limit + ")");
        }

        Map<String, Object> next = new LinkedHashMap<String, Object>();
        next.put("format", QUOTA_FORMAT);
        next.put("license_id", entitlement.getLicenseId());
        next.put("month", month(today));
        next.put("used", Long.valueOf(used + 1L));
        next.put("machine", machine);
        next.put("updated", Dates.now());
        store.writeSealed(file, QUOTA_PURPOSE, next);

        status.setQuotaUsed(used + 1);
        status.setQuotaLimit(limit);
        status.setMessage(limit > 0
                ? "tool licence valid (" + (used + 1) + "/" + limit + " builds this month)"
                : "tool licence valid (unlimited builds)");
        return status;
    }

    /** Writes the local activation record for a licence that requires one. */
    public void activate(ToolEntitlement entitlement) {
        if (entitlement == null) {
            throw new IllegalArgumentException("tool entitlement is required");
        }
        Map<String, Object> state = new LinkedHashMap<String, Object>();
        state.put("format", INSTALL_FORMAT);
        state.put("license_id", entitlement.getLicenseId());
        state.put("machine", machine);
        state.put("activated", Dates.now());
        store.writeSealed(store.resolve(ToolStateStore.INSTALL_FILE),
                INSTALL_PURPOSE, state);
    }

    /** Removes the installed licence and its activation record. */
    public void deactivate() {
        ToolStateStore.delete(store.resolve(ToolStateStore.TOOL_LICENSE_FILE));
        ToolStateStore.delete(store.resolve(ToolStateStore.INSTALL_FILE));
    }

    public ToolStateStore getStore() {
        return store;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    private int[] quota(ToolEntitlement entitlement) {
        Map<String, Object> state = store.readSealed(
                store.resolve(ToolStateStore.QUOTA_FILE), QUOTA_PURPOSE);
        int limit = entitlement.getMaxBuildsPerMonth();
        if (state == null) {
            return new int[] {0, limit};
        }
        if (!entitlement.getLicenseId().equals(
                        ToolValues.string(state.get("license_id"), null))
                || !month(today).equals(ToolValues.string(state.get("month"), null))) {
            return new int[] {0, limit};
        }
        int used = Math.max(0, ToolValues.integer(state.get("used"), 0));
        return new int[] {used, limit};
    }

    private boolean isRevoked(ToolEntitlement entitlement) {
        if (publicKey == null) {
            return false;
        }
        Path file = store.resolve(ToolStateStore.REVOCATIONS_FILE);
        if (!Files.isRegularFile(file)) {
            return false;
        }
        try {
            Set<String> revoked = ToolLicense.readRevocations(file, publicKey);
            return revoked.contains(entitlement.getLicenseId());
        } catch (RuntimeException ignored) {
            // A broken revocation list must not become a denial-of-service tool.
            return false;
        }
    }

    private ToolLicenseStatus missing(Path file) {
        ToolLicenseStatus status = ToolLicenseStatus.of(ToolCodes.MODE_INVALID,
                ToolCodes.LICENSE_INVALID, "tool licence not found: " + file, false);
        status.setMachine(machine);
        return status;
    }

    private ToolLicenseStatus denied(String mode, String code, String message,
                                     ToolEntitlement entitlement) {
        ToolLicenseStatus status = ToolLicenseStatus.of(mode, code, message, false);
        status.setMachine(machine);
        if (entitlement != null) {
            status.setEntitlement(entitlement);
            status.setVerified(entitlement.isVerified());
            status.setLicenseId(entitlement.getLicenseId());
            status.setCustomer(entitlement.getCustomer());
            status.setEdition(entitlement.getEdition());
            status.setExpires(entitlement.getExpires());
            status.setQuotaLimit(entitlement.getMaxBuildsPerMonth());
        }
        return status;
    }

    private ToolLicenseStatus stateError(ToolLicenseException exc,
                                         ToolEntitlement entitlement) {
        return denied(ToolCodes.MODE_INVALID, ToolCodes.STATE_INVALID,
                exc.getMessage(), entitlement);
    }

    private static int positive(int value, int fallback) {
        return value > 0 ? value : fallback;
    }

    private static LocalDate parseDate(Object value) {
        String text = ToolValues.string(value, null);
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        try {
            return Dates.parseDate(text);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static String month(LocalDate date) {
        return YearMonth.from(date).toString();
    }

    private static int environmentInt(String name, int fallback) {
        String value = System.getenv(name);
        if (value != null && !value.trim().isEmpty()) {
            try {
                int parsed = Integer.parseInt(value.trim());
                if (parsed > 0) {
                    return parsed;
                }
            } catch (NumberFormatException ignored) {
                // fall back to the default
            }
        }
        return fallback;
    }
}
