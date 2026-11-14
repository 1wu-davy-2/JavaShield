package com.javashield.core.license;

/** Outcome of validating a licence against this machine and this build. */
public final class LicenseStatus {

    private final boolean valid;
    private final boolean inGrace;
    private final String message;
    private final LicensePayload payload;

    private LicenseStatus(boolean valid, boolean inGrace, String message, LicensePayload payload) {
        this.valid = valid;
        this.inGrace = inGrace;
        this.message = message;
        this.payload = payload;
    }

    public static LicenseStatus ok(boolean inGrace, LicensePayload payload, String message) {
        return new LicenseStatus(true, inGrace, message, payload);
    }

    public static LicenseStatus fail(String message, LicensePayload payload) {
        return new LicenseStatus(false, false, message, payload);
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isInGrace() {
        return inGrace;
    }

    public String getMessage() {
        return message;
    }

    public LicensePayload getPayload() {
        return payload;
    }

    public String getExpires() {
        return payload == null ? null : payload.getExpires();
    }

    public String getCustomer() {
        return payload == null ? null : payload.getCustomer();
    }

    public String getEdition() {
        return payload == null ? null : payload.getEdition();
    }

    @Override
    public String toString() {
        return (valid ? "valid" : "invalid") + (inGrace ? " (grace)" : "") + ": " + message;
    }
}
