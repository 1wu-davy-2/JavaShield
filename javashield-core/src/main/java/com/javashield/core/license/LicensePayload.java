package com.javashield.core.license;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.javashield.core.Product;
import com.javashield.core.json.Json;

/**
 * Typed view of the licence body.
 *
 * <p>{@link #toMap()} must stay stable because the map is what gets signed. Keep
 * field names in sync with the Python implementation when adding new ones.
 */
public final class LicensePayload {

    private int format = 2;
    private String product = Product.NAME;
    private String buildId;
    private byte[] buildKey;
    private String cipher = "aesgcm";
    private String jvm = "8-21";
    private String created;
    private String notBefore;
    private String expires;
    private int graceDays;
    private final List<String> fingerprints = new ArrayList<String>();
    private String customer;
    private String edition = "standard";
    private boolean bindFirstRun;
    private String signature;

    public int getFormat() {
        return format;
    }

    public void setFormat(int format) {
        this.format = format;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public String getBuildId() {
        return buildId;
    }

    public void setBuildId(String buildId) {
        this.buildId = buildId;
    }

    public byte[] getBuildKey() {
        return buildKey;
    }

    public void setBuildKey(byte[] buildKey) {
        this.buildKey = buildKey;
    }

    public String getCipher() {
        return cipher;
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public String getJvm() {
        return jvm;
    }

    public void setJvm(String jvm) {
        this.jvm = jvm;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getExpires() {
        return expires;
    }

    public void setExpires(String expires) {
        this.expires = expires;
    }

    public int getGraceDays() {
        return graceDays;
    }

    public void setGraceDays(int graceDays) {
        this.graceDays = graceDays;
    }

    public List<String> getFingerprints() {
        return fingerprints;
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

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public boolean isBindFirstRun() {
        return bindFirstRun;
    }

    public void setBindFirstRun(boolean bindFirstRun) {
        this.bindFirstRun = bindFirstRun;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        map.put("format", Long.valueOf(format));
        map.put("product", product);
        map.put("build_id", buildId);
        map.put("build_key", buildKey == null ? null : Base64.getEncoder().encodeToString(buildKey));
        map.put("cipher", cipher);
        map.put("jvm", jvm);
        map.put("created", created);
        map.put("not_before", notBefore);
        map.put("expires", expires);
        map.put("grace_days", Long.valueOf(graceDays));
        map.put("fingerprints", new ArrayList<Object>(fingerprints));
        map.put("customer", customer);
        map.put("edition", edition);
        map.put("bind_first_run", Boolean.valueOf(bindFirstRun));
        if (signature != null) {
            map.put("signature", signature);
        }
        return map;
    }

    public static LicensePayload fromMap(Map<String, Object> map) {
        LicensePayload payload = new LicensePayload();
        payload.format = (int) Json.asLong(map.get("format"));
        payload.product = optionalString(map.get("product"));
        payload.buildId = optionalString(map.get("build_id"));
        String buildKey = optionalString(map.get("build_key"));
        payload.buildKey = buildKey == null ? null : Base64.getDecoder().decode(buildKey);
        payload.cipher = optionalString(map.get("cipher"));
        payload.jvm = optionalString(map.get("jvm"));
        payload.created = optionalString(map.get("created"));
        payload.notBefore = optionalString(map.get("not_before"));
        payload.expires = optionalString(map.get("expires"));
        payload.graceDays = (int) Json.asLong(map.get("grace_days"));
        payload.fingerprints.clear();
        Object rawFingerprints = map.get("fingerprints");
        if (rawFingerprints instanceof List) {
            for (Object item : (List<?>) rawFingerprints) {
                if (item != null) {
                    payload.fingerprints.add(String.valueOf(item));
                }
            }
        }
        payload.customer = optionalString(map.get("customer"));
        payload.edition = optionalString(map.get("edition"));
        payload.bindFirstRun = Boolean.TRUE.equals(map.get("bind_first_run"));
        payload.signature = optionalString(map.get("signature"));
        return payload;
    }

    private static String optionalString(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
