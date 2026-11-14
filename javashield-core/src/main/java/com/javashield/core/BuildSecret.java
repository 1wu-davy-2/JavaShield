package com.javashield.core;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;

/**
 * The build secret. Contains every key needed to re-sign licences and to verify
 * a delivered package. It must never ship with the protected application.
 */
public final class BuildSecret {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private int format = 2;
    private String product = Product.NAME;
    private String buildId;
    private String cipher;
    private String integrity = "protected";
    private String jvm = "8-21";
    private String created = Dates.now();
    private String customer;
    private String output;
    private String license;
    private byte[] masterKey;
    private byte[] buildKey;
    private byte[] signingKey;
    private byte[] publicKey;

    public int getFormat() {
        return format;
    }

    public String getProduct() {
        return product;
    }

    public String getBuildId() {
        return buildId;
    }

    public void setBuildId(String buildId) {
        this.buildId = buildId;
    }

    public String getCipher() {
        return cipher;
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
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

    public String getCustomer() {
        return customer;
    }

    public void setCustomer(String customer) {
        this.customer = customer;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = license;
    }

    public byte[] getMasterKey() {
        return masterKey;
    }

    public void setMasterKey(byte[] masterKey) {
        this.masterKey = masterKey;
    }

    public byte[] getBuildKey() {
        return buildKey;
    }

    public void setBuildKey(byte[] buildKey) {
        this.buildKey = buildKey;
    }

    public byte[] getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(byte[] signingKey) {
        this.signingKey = signingKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        map.put("format", Long.valueOf(format));
        map.put("product", product);
        map.put("build_id", buildId);
        map.put("cipher", cipher);
        map.put("integrity", integrity);
        map.put("jvm", jvm);
        map.put("created", created);
        map.put("customer", customer);
        map.put("output", output);
        map.put("license", license);
        map.put("master_key", base64(masterKey));
        map.put("build_key", base64(buildKey));
        map.put("signing_key", base64(signingKey));
        map.put("public_key", base64(publicKey));
        return map;
    }

    public static BuildSecret fromMap(Map<String, Object> map) {
        BuildSecret secret = new BuildSecret();
        secret.format = (int) Json.asLong(map.get("format"));
        secret.product = text(map.get("product"));
        secret.buildId = text(map.get("build_id"));
        secret.cipher = text(map.get("cipher"));
        secret.integrity = text(map.get("integrity"));
        secret.jvm = text(map.get("jvm"));
        secret.created = text(map.get("created"));
        secret.customer = text(map.get("customer"));
        secret.output = text(map.get("output"));
        secret.license = text(map.get("license"));
        secret.masterKey = bytes(map.get("master_key"));
        secret.buildKey = bytes(map.get("build_key"));
        secret.signingKey = bytes(map.get("signing_key"));
        secret.publicKey = bytes(map.get("public_key"));
        return secret;
    }

    public void save(Path path) throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(path, (Json.pretty(toMap()) + "\n").getBytes(UTF_8));
        restrictPermissions(path);
    }

    public static BuildSecret load(Path path) throws IOException {
        String text = new String(Files.readAllBytes(path), UTF_8);
        return fromMap(Json.parseObject(text));
    }

    private static void restrictPermissions(Path path) {
        try {
            Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, permissions);
        } catch (Exception ignored) {
            // Windows and some file systems do not support POSIX permissions.
        }
    }

    private static String base64(byte[] data) {
        return data == null ? null : Base64.getEncoder().encodeToString(data);
    }

    private static byte[] bytes(Object value) {
        return value == null ? null : Base64.getDecoder().decode(String.valueOf(value));
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
