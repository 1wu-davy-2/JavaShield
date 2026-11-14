package com.javashield.tool;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

import com.javashield.core.Product;

/** Result of a tool licence check. */
public final class ToolLicenseStatus {

    private String mode;
    private String code;
    private String message;
    private boolean allowed;
    private boolean development;
    private boolean trial;
    private boolean verified;
    private String machine;
    private String licenseId;
    private String customer;
    private String edition;
    private LocalDate expires;
    private int trialDaysLeft;
    private int trialBuildsLeft;
    private int trialBuildsUsed;
    private int trialMaxBuilds;
    private int quotaUsed;
    private int quotaLimit;
    private ToolEntitlement entitlement;

    private ToolLicenseStatus() {
    }

    public static ToolLicenseStatus of(String mode, String code, String message, boolean allowed) {
        ToolLicenseStatus status = new ToolLicenseStatus();
        status.mode = mode;
        status.code = code;
        status.message = message;
        status.allowed = allowed;
        return status;
    }

    public static ToolLicenseStatus development(String machine) {
        ToolLicenseStatus status = of(ToolCodes.MODE_DEVELOPMENT, ToolCodes.DEVELOPMENT,
                "development mode: tool licensing is disabled", true);
        status.development = true;
        status.machine = machine;
        status.edition = "development";
        return status;
    }

    public static ToolLicenseStatus licensed(ToolEntitlement entitlement, String machine,
                                             int used, int limit) {
        ToolLicenseStatus status = of(ToolCodes.MODE_LICENSED, ToolCodes.OK,
                "tool licence valid", true);
        status.entitlement = entitlement;
        status.verified = entitlement.isVerified();
        status.machine = machine;
        status.licenseId = entitlement.getLicenseId();
        status.customer = entitlement.getCustomer();
        status.edition = entitlement.getEdition();
        status.expires = entitlement.getExpires();
        status.quotaUsed = used;
        status.quotaLimit = limit;
        status.message = "tool licence valid"
                + (limit > 0 ? " (" + used + "/" + limit + " builds this month)" : "");
        return status;
    }

    public static ToolLicenseStatus trial(String code, String message, boolean allowed,
                                          String machine, int daysLeft, int buildsLeft,
                                          int buildsUsed, int maxBuilds) {
        ToolLicenseStatus status = of(allowed ? ToolCodes.MODE_TRIAL : ToolCodes.MODE_UNLICENSED,
                code, message, allowed);
        status.trial = true;
        status.edition = "trial";
        status.machine = machine;
        status.trialDaysLeft = daysLeft;
        status.trialBuildsLeft = buildsLeft;
        status.trialBuildsUsed = buildsUsed;
        status.trialMaxBuilds = maxBuilds;
        return status;
    }

    public boolean isAllowed() {
        return allowed;
    }

    public boolean isDevelopment() {
        return development;
    }

    public boolean isTrial() {
        return trial;
    }

    public boolean isLicensed() {
        return ToolCodes.MODE_LICENSED.equals(mode);
    }

    public String getMode() {
        return mode;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public String getMachine() {
        return machine;
    }

    public String getLicenseId() {
        return licenseId;
    }

    public String getCustomer() {
        return customer;
    }

    public String getEdition() {
        return edition;
    }

    public LocalDate getExpires() {
        return expires;
    }

    public int getTrialDaysLeft() {
        return trialDaysLeft;
    }

    public int getTrialBuildsLeft() {
        return trialBuildsLeft;
    }

    public int getTrialBuildsUsed() {
        return trialBuildsUsed;
    }

    public int getTrialMaxBuilds() {
        return trialMaxBuilds;
    }

    public int getQuotaUsed() {
        return quotaUsed;
    }

    public int getQuotaLimit() {
        return quotaLimit;
    }

    public ToolEntitlement getEntitlement() {
        return entitlement;
    }

    public boolean isVerified() {
        return verified;
    }

    /**
     * The watermark copied into the signed application manifest. Deliberately
     * contains no customer name or machine id.
     */
    public Map<String, Object> publicWatermark() {
        Map<String, Object> watermark = new LinkedHashMap<String, Object>();
        watermark.put("tool", Product.TOOL);
        watermark.put("tool_version", Product.VERSION);
        watermark.put("license_id", watermarkLicenseId());
        watermark.put("edition", edition == null ? "unknown" : edition);
        watermark.put("trial", Boolean.valueOf(trial));
        return watermark;
    }

    /** The watermark recorded in the build secret, including private labels. */
    public Map<String, Object> secretWatermark() {
        Map<String, Object> watermark = publicWatermark();
        if (customer != null && !customer.trim().isEmpty()) {
            watermark.put("customer", customer);
        }
        watermark.put("machine", machine);
        if (trial) {
            watermark.put("builds_used", Long.valueOf(trialBuildsUsed));
            watermark.put("quota_limit", Long.valueOf(trialMaxBuilds));
        } else if (isLicensed()) {
            watermark.put("builds_used", Long.valueOf(quotaUsed));
            watermark.put("quota_limit", Long.valueOf(quotaLimit));
            if (expires != null) {
                watermark.put("expires", expires.toString());
            }
        }
        return watermark;
    }

    private String watermarkLicenseId() {
        if (licenseId != null && !licenseId.trim().isEmpty()) {
            return licenseId;
        }
        if (development) {
            return "development";
        }
        if (trial) {
            return "trial";
        }
        return "unknown";
    }

    void setMessage(String message) {
        this.message = message;
    }

    void setEntitlement(ToolEntitlement entitlement) {
        this.entitlement = entitlement;
    }

    void setAllowed(boolean allowed) {
        this.allowed = allowed;
    }

    void setTrial(boolean trial) {
        this.trial = trial;
    }

    void setVerified(boolean verified) {
        this.verified = verified;
    }

    void setMachine(String machine) {
        this.machine = machine;
    }

    void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    void setCustomer(String customer) {
        this.customer = customer;
    }

    void setEdition(String edition) {
        this.edition = edition;
    }

    void setExpires(LocalDate expires) {
        this.expires = expires;
    }

    void setTrialDaysLeft(int trialDaysLeft) {
        this.trialDaysLeft = trialDaysLeft;
    }

    void setTrialBuildsLeft(int trialBuildsLeft) {
        this.trialBuildsLeft = trialBuildsLeft;
    }

    void setTrialBuildsUsed(int trialBuildsUsed) {
        this.trialBuildsUsed = trialBuildsUsed;
    }

    void setTrialMaxBuilds(int trialMaxBuilds) {
        this.trialMaxBuilds = trialMaxBuilds;
    }

    void setQuotaUsed(int quotaUsed) {
        this.quotaUsed = quotaUsed;
    }

    void setQuotaLimit(int quotaLimit) {
        this.quotaLimit = quotaLimit;
    }
}
