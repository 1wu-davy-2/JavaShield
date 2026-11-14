package com.javashield.core;

/** Central place for product identity strings. */
public final class Product {

    public static final String NAME = "javashield";
    public static final String DISPLAY_NAME = "JavaShield";
    public static final String VERSION = "0.1.0";
    public static final String TOOL = NAME + " " + VERSION;

    public static final String LICENSE_FORMAT = "2";
    public static final String MANIFEST_FORMAT = "1";

    public static final String LICENSE_PREFIX = "jshield-license-v2:";
    public static final String MANIFEST_PREFIX = "jshield-manifest-v1:";

    public static final String LICENSE_FILE = "jshield.lic";
    public static final String SECRET_SUFFIX = ".jshield-secret.json";
    public static final String MANIFEST_ENTRY = "META-INF/jshield-manifest.json";
    public static final String PAYLOAD_PREFIX = "META-INF/jshield/p/";
    public static final String AGENT_CONFIG = "jshield-agent.properties";

    private Product() {
    }
}
