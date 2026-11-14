package com.javashield.tool;

/**
 * Stable machine-readable codes for tool licence state.
 *
 * <p>Scripts, CI and (later) the desktop builder should branch on these codes,
 * never on the human-readable message.</p>
 */
public final class ToolCodes {

    /** Explicit development mode; tool licensing is disabled. */
    public static final String DEVELOPMENT = "development";
    /** A signed tool licence is valid. */
    public static final String OK = "ok";
    /** The local trial is active. */
    public static final String TRIAL = "trial";

    /** No local activation exists for a licence that requires one. */
    public static final String NOT_ACTIVATED = "not_activated";
    public static final String ACTIVATION_REQUIRED = "activation_required";
    /** The licence file is unreadable, malformed or has a bad signature. */
    public static final String LICENSE_INVALID = "license_invalid";
    public static final String TRIAL_EXPIRED = "trial_expired";
    public static final String EXPIRED = "expired";
    public static final String NOT_YET_VALID = "not_yet_valid";
    public static final String MACHINE_MISMATCH = "machine_mismatch";
    public static final String REVOKED = "revoked";
    public static final String FEATURE_MISSING = "feature_missing";
    public static final String QUOTA_EXHAUSTED = "quota_exhausted";
    /** The requested build option is not available in trial mode. */
    public static final String TRIAL_LIMIT = "trial_limit";
    /** Local trial/quota state was modified or cannot be verified. */
    public static final String STATE_INVALID = "state_invalid";
    /** Local state could not be read or written. */
    public static final String STATE_IO = "state_io";

    public static final String MODE_DEVELOPMENT = "development";
    public static final String MODE_LICENSED = "licensed";
    public static final String MODE_TRIAL = "trial";
    public static final String MODE_UNLICENSED = "unlicensed";
    public static final String MODE_INVALID = "invalid";

    private ToolCodes() {
    }
}
