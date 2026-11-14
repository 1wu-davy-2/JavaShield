package com.javashield.tool;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Feature names used by a tool licence.
 *
 * <p>The feature list in a signed licence is authoritative. Edition names only
 * provide defaults when the issuer did not write a {@code features} array.</p>
 */
public final class ToolFeatures {

    public static final String CLI = "cli";
    public static final String MAVEN = "maven";
    public static final String GRADLE = "gradle";
    public static final String GUI = "gui";
    public static final String WAR = "war";
    public static final String NATIVE_RUNTIME = "native-runtime";
    public static final String OFFLINE_ACTIVATION = "offline-activation";
    public static final String LICENSE_ISSUANCE = "license-issuance";
    public static final String CI = "ci";
    public static final String OEM = "oem";

    private static final Set<String> TRIAL = set(CLI, MAVEN, GRADLE);
    private static final Set<String> PRO = union(TRIAL, LICENSE_ISSUANCE, WAR);
    private static final Set<String> ENTERPRISE = union(PRO, OFFLINE_ACTIVATION, CI,
            NATIVE_RUNTIME, GUI);
    private static final Set<String> OEM_EDITION = union(ENTERPRISE, OEM);

    private ToolFeatures() {
    }

    /** Features available while the local trial is active. */
    public static Set<String> trial() {
        return TRIAL;
    }

    /** Default features for a known edition, or an empty set for an unknown label. */
    public static Set<String> forEdition(String edition) {
        String value = edition == null ? "" : edition.trim().toLowerCase(Locale.ROOT);
        if ("trial".equals(value)) {
            return TRIAL;
        }
        if ("pro".equals(value) || "professional".equals(value)) {
            return PRO;
        }
        if ("enterprise".equals(value) || "business".equals(value)) {
            return ENTERPRISE;
        }
        if ("oem".equals(value)) {
            return OEM_EDITION;
        }
        return Collections.emptySet();
    }

    public static boolean trialIncludes(String feature) {
        return TRIAL.contains(feature);
    }

    private static Set<String> set(String... values) {
        return Collections.unmodifiableSet(new LinkedHashSet<String>(Arrays.asList(values)));
    }

    private static Set<String> union(Set<String> base, String... values) {
        LinkedHashSet<String> combined = new LinkedHashSet<String>(base);
        combined.addAll(Arrays.asList(values));
        return Collections.unmodifiableSet(combined);
    }
}
