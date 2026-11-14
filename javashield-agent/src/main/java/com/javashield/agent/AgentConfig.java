package com.javashield.agent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Properties;

import com.javashield.core.AgentKey;
import com.javashield.core.Product;

/**
 * Runtime configuration injected into the agent jar by the builder.
 *
 * <p>The master key is stored XOR-obfuscated so that a casual {@code strings}
 * pass over the jar does not reveal it. This is not cryptographic protection:
 * an attacker who reads and runs the agent can always recover it. The real
 * defences are the signed licence and the per-class keys.
 */
public final class AgentConfig {

    private final String buildId;
    private final String cipher;
    private final String manifestEntry;
    private final byte[] masterKey;
    private final byte[] publicKey;

    private AgentConfig(String buildId, String cipher, String manifestEntry,
                        byte[] masterKey, byte[] publicKey) {
        this.buildId = buildId;
        this.cipher = cipher;
        this.manifestEntry = manifestEntry;
        this.masterKey = masterKey;
        this.publicKey = publicKey;
    }

    public String getBuildId() {
        return buildId;
    }

    public String getCipher() {
        return cipher;
    }

    public String getManifestEntry() {
        return manifestEntry;
    }

    public byte[] getMasterKey() {
        return masterKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public static AgentConfig load() {
        Properties properties = new Properties();
        try {
            String explicit = System.getProperty("jshield.config");
            if (explicit != null && !explicit.trim().isEmpty()) {
                InputStream in = Files.newInputStream(Paths.get(explicit.trim()));
                try {
                    properties.load(in);
                } finally {
                    in.close();
                }
            } else {
                ClassLoader loader = AgentConfig.class.getClassLoader();
                InputStream in = loader == null ? null : loader.getResourceAsStream(Product.AGENT_CONFIG);
                if (in != null) {
                    try {
                        properties.load(in);
                    } finally {
                        in.close();
                    }
                } else {
                    loadFromSibling(properties);
                }
            }
        } catch (IOException exc) {
            throw new IllegalStateException("cannot read " + Product.AGENT_CONFIG, exc);
        }

        String product = properties.getProperty("product", Product.NAME);
        if (!Product.NAME.equals(product)) {
            throw new IllegalStateException("agent belongs to another product: " + product);
        }
        String buildId = required(properties, "build_id");
        String cipher = properties.getProperty("cipher", "aesgcm");
        String manifest = properties.getProperty("manifest", Product.MANIFEST_ENTRY);
        String packedKey = required(properties, "master_key");
        String publicKeyText = required(properties, "public_key");

        byte[] masterKey = AgentKey.unpack(packedKey, buildId);
        if (masterKey.length != 32) {
            throw new IllegalStateException("agent master key is invalid");
        }
        byte[] publicKey;
        try {
            publicKey = Base64.getDecoder().decode(publicKeyText);
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException("agent public key is not valid Base64", exc);
        }
        if (publicKey.length != 32) {
            throw new IllegalStateException("agent public key is invalid");
        }
        return new AgentConfig(buildId, cipher, manifest, masterKey, publicKey);
    }

    private static void loadFromSibling(Properties properties) throws IOException {
        try {
            java.security.CodeSource source = AgentConfig.class.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                throw new IOException("agent location is unknown");
            }
            Path location = Paths.get(source.getLocation().toURI());
            if (!Files.isRegularFile(location)) {
                throw new IOException("agent is not running from a jar");
            }
            Path sibling = location.resolveSibling(Product.AGENT_CONFIG);
            if (!Files.isRegularFile(sibling)) {
                throw new IOException("cannot find " + Product.AGENT_CONFIG
                        + "; pass -Djshield.config=<path>");
            }
            InputStream in = Files.newInputStream(sibling);
            try {
                properties.load(in);
            } finally {
                in.close();
            }
        } catch (java.net.URISyntaxException exc) {
            throw new IOException("agent location is not a valid path", exc);
        }
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException("agent configuration is missing " + key);
        }
        return value.trim();
    }
}
