package com.javashield.agent;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneOffset;

import com.javashield.core.Fingerprint;
import com.javashield.core.Product;
import com.javashield.core.crypto.ShieldCryptoException;
import com.javashield.core.license.License;
import com.javashield.core.license.LicensePayload;
import com.javashield.core.license.LicenseStatus;
import com.javashield.core.license.LicenseVerifier;

/** Resolves, decrypts and validates the product licence at startup. */
public final class LicenseGate {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private LicenseGate() {
    }

    public static LicensePayload check(AgentConfig config, Path appJar, PayloadSource source)
            throws IOException {
        String text = readLicense(appJar, source);
        LicensePayload payload;
        try {
            payload = License.decode(text, config.getMasterKey(),
                    config.getBuildId(), config.getPublicKey());
        } catch (ShieldCryptoException exc) {
            throw new IllegalStateException("licence cannot be decrypted for this build", exc);
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException(exc.getMessage(), exc);
        }

        String fingerprint = Fingerprint.machineId();
        LicenseStatus status = LicenseVerifier.verify(payload, config.getBuildId(),
                fingerprint, LocalDate.now(ZoneOffset.UTC));
        if (!status.isValid()) {
            throw new IllegalStateException(status.getMessage());
        }

        BindingGuard.enforce(appJar, payload);
        ClockGuard.check(config.getBuildId(), payload.getBuildKey());
        return payload;
    }

    private static String readLicense(Path appJar, PayloadSource source) throws IOException {
        String explicit = System.getProperty("jshield.license");
        if (explicit != null && !explicit.trim().isEmpty()) {
            return readFile(Paths.get(explicit.trim()));
        }
        String fromEnv = System.getenv("JSHIELD_LICENSE");
        if (fromEnv != null && !fromEnv.trim().isEmpty()) {
            return readFile(Paths.get(fromEnv.trim()));
        }
        if (appJar != null && appJar.getParent() != null) {
            Path sibling = appJar.getParent().resolve(Product.LICENSE_FILE);
            if (Files.isRegularFile(sibling)) {
                return new String(Files.readAllBytes(sibling), UTF_8);
            }
        }
        byte[] embedded = source.readOptional(Product.LICENSE_FILE);
        if (embedded != null) {
            return new String(embedded, UTF_8);
        }
        throw new IllegalStateException("licence not found: place " + Product.LICENSE_FILE
                + " next to the jar or pass -Djshield.license=<path>");
    }

    private static String readFile(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("licence does not exist: " + path);
        }
        return new String(Files.readAllBytes(path), UTF_8);
    }
}
