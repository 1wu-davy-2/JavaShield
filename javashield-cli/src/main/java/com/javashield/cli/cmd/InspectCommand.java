package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;

import com.javashield.cli.Args;
import com.javashield.cli.builder.JarVerifier;
import com.javashield.core.BuildSecret;
import com.javashield.core.Fingerprint;
import com.javashield.core.license.License;
import com.javashield.core.license.LicensePayload;
import com.javashield.core.license.LicenseStatus;
import com.javashield.core.license.LicenseVerifier;
import com.javashield.core.manifest.Manifest;

/** Prints build and licence details without decrypting the application. */
public final class InspectCommand {

    private InspectCommand() {
    }

    public static int run(Args args) throws IOException {
        String jarValue = args.first("jar", "j");
        String secretValue = args.first("secret");
        if (jarValue == null && secretValue == null) {
            throw new IllegalArgumentException("pass --jar and/or --secret");
        }
        if (jarValue != null) {
            Map<String, Object> manifest = JarVerifier.readManifest(Paths.get(jarValue));
            System.out.println("[javashield] package    : " + jarValue);
            System.out.println("[javashield] build id   : " + manifest.get("build_id"));
            System.out.println("[javashield] cipher     : " + manifest.get("cipher"));
            System.out.println("[javashield] integrity  : " + manifest.get("integrity"));
            System.out.println("[javashield] tool       : " + manifest.get("tool"));
            System.out.println("[javashield] classes    : " + Manifest.classes(manifest).size());
        }
        if (secretValue != null) {
            inspectSecret(Paths.get(secretValue));
        }
        return 0;
    }

    private static void inspectSecret(Path secretPath) throws IOException {
        BuildSecret secret = BuildSecret.load(secretPath);
        System.out.println("[javashield] secret     : " + secretPath);
        System.out.println("[javashield] build id   : " + secret.getBuildId());
        System.out.println("[javashield] cipher     : " + secret.getCipher());
        System.out.println("[javashield] customer   : "
                + (secret.getCustomer() == null ? "-" : secret.getCustomer()));
        System.out.println("[javashield] created    : " + secret.getCreated());
        System.out.println("[javashield] machine id : " + Fingerprint.machineId());
        if (secret.getLicense() == null) {
            return;
        }
        Path licensePath = Paths.get(secret.getLicense());
        if (!Files.isRegularFile(licensePath)) {
            System.out.println("[javashield] licence    : missing " + licensePath);
            return;
        }
        LicensePayload payload = License.read(licensePath, secret.getMasterKey(),
                secret.getBuildId(), secret.getPublicKey());
        LicenseStatus status = LicenseVerifier.verify(payload, secret.getBuildId(),
                Fingerprint.machineId(), LocalDate.now(ZoneOffset.UTC));
        System.out.println("[javashield] licence    : " + licensePath);
        System.out.println("[javashield] expires    : "
                + (payload.getExpires() == null ? "never" : payload.getExpires()));
        System.out.println("[javashield] grace days : " + payload.getGraceDays());
        System.out.println("[javashield] binding    : "
                + (payload.isBindFirstRun() ? "first run"
                : payload.getFingerprints().isEmpty() ? "any machine"
                : payload.getFingerprints().toString()));
        System.out.println("[javashield] status     : " + status);
    }
}
