package com.javashield.tool;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.javashield.core.license.Dates;

/**
 * The signed payload of a tool licence: who may use the builder, for which
 * features, and under which limits.
 *
 * <p>This is separate from the product licence ({@code jshield.lic}. The product
 * licence controls where a protected application runs; this document controls
 * who may build one.</p>
 */
public final class ToolEntitlement {

    private String licenseId;
    private String customer;
    private String edition = "pro";
    private final Set<String> features = new LinkedHashSet<String>();
    private int seats = 1;
    private int maxActivations;
    private int maxBuildsPerMonth;
    private String bindMode = "any";
    private final List<String> fingerprints = new ArrayList<String>();
    private boolean activationRequired;
    private String issued;
    private LocalDate notBefore;
    private LocalDate expires;
    private int graceDays;
    private int revocationEpoch;
    private String notes;

    private boolean verified;

    public static ToolEntitlement fromPayload(Map<String, Object> payload) {
        if (payload == null) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool licence has no payload");
        }
        String product = ToolValues.string(payload.get("product"), ToolLicense.PRODUCT);
        if (!ToolLicense.PRODUCT.equalsIgnoreCase(product)) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool licence is for product '" + product + "', not " + ToolLicense.PRODUCT);
        }

        ToolEntitlement entitlement = new ToolEntitlement();
        entitlement.licenseId = ToolValues.string(payload.get("license_id"), null);
        if (entitlement.licenseId == null || entitlement.licenseId.trim().isEmpty()) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool licence has no license_id");
        }
        entitlement.licenseId = entitlement.licenseId.trim();
        entitlement.customer = ToolValues.string(payload.get("customer"), null);
        entitlement.edition = ToolValues.string(payload.get("edition"), "pro")
                .trim().toLowerCase(Locale.ROOT);

        boolean hasFeatureList = payload.containsKey("features");
        for (String feature : ToolValues.strings(payload.get("features"))) {
            String normalized = feature.trim().toLowerCase(Locale.ROOT);
            if (!normalized.isEmpty()) {
                entitlement.features.add(normalized);
            }
        }
        if (!hasFeatureList) {
            entitlement.features.addAll(ToolFeatures.forEdition(entitlement.edition));
        }

        entitlement.seats = Math.max(0,
                ToolValues.integer(payload.get("seats"), 1));
        entitlement.maxActivations = Math.max(0,
                ToolValues.integer(payload.get("max_activations"), 0));
        entitlement.maxBuildsPerMonth = Math.max(0,
                ToolValues.integer(payload.get("max_builds_per_month"), 0));
        for (String fingerprint : ToolValues.strings(payload.get("fingerprints"))) {
            String normalized = fingerprint.trim();
            if (!normalized.isEmpty()) {
                entitlement.fingerprints.add(normalized);
            }
        }
        String bindMode = ToolValues.string(payload.get("bind_mode"), null);
        if (bindMode == null || bindMode.trim().isEmpty()) {
            bindMode = entitlement.fingerprints.isEmpty() ? "any" : "fixed";
        }
        entitlement.bindMode = bindMode.trim().toLowerCase(Locale.ROOT);
        entitlement.activationRequired = ToolValues.bool(payload.get("activation_required"), false);
        entitlement.issued = ToolValues.string(payload.get("issued"), null);
        entitlement.notBefore = parseDate(payload.get("not_before"));
        entitlement.expires = parseDate(payload.get("expires"));
        entitlement.graceDays = Math.max(0,
                ToolValues.integer(payload.get("grace_days"), 0));
        entitlement.revocationEpoch = ToolValues.integer(payload.get("revocation_epoch"), 0);
        entitlement.notes = ToolValues.string(payload.get("notes"), null);
        return entitlement;
    }

    private static LocalDate parseDate(Object value) {
        String text = ToolValues.string(value, null);
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        try {
            return Dates.parseDate(text);
        } catch (IllegalArgumentException exc) {
            throw new ToolLicenseException(ToolCodes.LICENSE_INVALID,
                    "tool licence has an invalid date: " + text, exc);
        }
    }

    public Map<String, Object> toPayload() {
        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("product", ToolLicense.PRODUCT);
        payload.put("license_id", licenseId);
        payload.put("customer", customer);
        payload.put("edition", edition);
        payload.put("features", new ArrayList<String>(new TreeSet<String>(features)));
        payload.put("seats", Long.valueOf(seats));
        payload.put("max_activations", Long.valueOf(maxActivations));
        payload.put("max_builds_per_month", Long.valueOf(maxBuildsPerMonth));
        payload.put("bind_mode", bindMode);
        payload.put("fingerprints", new ArrayList<String>(new TreeSet<String>(fingerprints)));
        payload.put("activation_required", Boolean.valueOf(activationRequired));
        payload.put("issued", issued);
        payload.put("not_before", notBefore == null ? null : notBefore.toString());
        payload.put("expires", expires == null ? null : expires.toString());
        payload.put("grace_days", Long.valueOf(graceDays));
        payload.put("revocation_epoch", Long.valueOf(revocationEpoch));
        payload.put("notes", notes);
        return payload;
    }

    public boolean hasFeature(String feature) {
        return feature != null
                && features.contains(feature.trim().toLowerCase(Locale.ROOT));
    }

    /** True when this licence may run on the supplied machine id. */
    public boolean machineAllowed(String machine) {
        if ("any".equals(bindMode)) {
            return true;
        }
        if (!"fixed".equals(bindMode) || machine == null || machine.trim().isEmpty()) {
            return false;
        }
        for (String fingerprint : fingerprints) {
            if (fingerprint.equalsIgnoreCase(machine.trim())) {
                return true;
            }
        }
        return false;
    }

    public String getLicenseId() {
        return licenseId;
    }

    public void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    public String getCustomer() {
        return customer;
    }

    public void setCustomer(String customer) {
        this.customer = customer;
    }

    public String getEdition() {
        return edition;
    }

    public void setEdition(String edition) {
        this.edition = edition;
    }

    public Set<String> getFeatures() {
        return Collections.unmodifiableSet(features);
    }

    public void setFeatures(Set<String> values) {
        features.clear();
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.trim().isEmpty()) {
                    features.add(value.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
    }

    public int getSeats() {
        return seats;
    }

    public void setSeats(int seats) {
        this.seats = seats;
    }

    public int getMaxActivations() {
        return maxActivations;
    }

    public void setMaxActivations(int maxActivations) {
        this.maxActivations = maxActivations;
    }

    public int getMaxBuildsPerMonth() {
        return maxBuildsPerMonth;
    }

    public void setMaxBuildsPerMonth(int maxBuildsPerMonth) {
        this.maxBuildsPerMonth = maxBuildsPerMonth;
    }

    public String getBindMode() {
        return bindMode;
    }

    public void setBindMode(String bindMode) {
        this.bindMode = bindMode;
    }

    public List<String> getFingerprints() {
        return Collections.unmodifiableList(fingerprints);
    }

    public void setFingerprints(List<String> values) {
        fingerprints.clear();
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.trim().isEmpty()) {
                    fingerprints.add(value.trim());
                }
            }
        }
    }

    public boolean isActivationRequired() {
        return activationRequired;
    }

    public void setActivationRequired(boolean activationRequired) {
        this.activationRequired = activationRequired;
    }

    public String getIssued() {
        return issued;
    }

    public void setIssued(String issued) {
        this.issued = issued;
    }

    public LocalDate getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(LocalDate notBefore) {
        this.notBefore = notBefore;
    }

    public LocalDate getExpires() {
        return expires;
    }

    public void setExpires(LocalDate expires) {
        this.expires = expires;
    }

    public int getGraceDays() {
        return graceDays;
    }

    public void setGraceDays(int graceDays) {
        this.graceDays = graceDays;
    }

    public int getRevocationEpoch() {
        return revocationEpoch;
    }

    public void setRevocationEpoch(int revocationEpoch) {
        this.revocationEpoch = revocationEpoch;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public boolean isVerified() {
        return verified;
    }

    void setVerified(boolean verified) {
        this.verified = verified;
    }
}
