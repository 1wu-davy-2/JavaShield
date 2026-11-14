package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.javashield.cli.Args;
import com.javashield.core.BuildSecret;
import com.javashield.core.license.Dates;
import com.javashield.core.license.License;
import com.javashield.core.license.LicensePayload;

/**
 * Re-signs a licence without rebuilding the application.
 *
 * <p>Values that are not passed explicitly are inherited from the existing
 * licence, so renewing is just {@code issue --secret app.jar.jshield-secret.json -e 2028-12-31}.
 */
public final class IssueCommand {

    private IssueCommand() {
    }

    public static int run(Args args) throws IOException {
        Path secretPath = Paths.get(args.firstRequired("secret"));
        BuildSecret secret = BuildSecret.load(secretPath);

        String out = args.first("out", "license");
        Path licensePath;
        if (out != null) {
            licensePath = Paths.get(out);
        } else if (secret.getLicense() != null && !secret.getLicense().trim().isEmpty()) {
            licensePath = Paths.get(secret.getLicense());
        } else {
            throw new IllegalArgumentException("the build secret has no licence path; pass --out <path>");
        }

        LicensePayload payload;
        if (Files.isRegularFile(licensePath)) {
            payload = License.read(licensePath, secret.getMasterKey(),
                    secret.getBuildId(), secret.getPublicKey());
        } else {
            payload = new LicensePayload();
            payload.setBuildId(secret.getBuildId());
            payload.setBuildKey(secret.getBuildKey());
            payload.setCipher(secret.getCipher());
            payload.setJvm(secret.getJvm());
            payload.setCreated(Dates.now());
            payload.setNotBefore(Dates.today());
            payload.setEdition("standard");
        }

        if (args.has("expire") || args.has("e")) {
            payload.setExpires(args.first("expire", "e"));
            Dates.parseDate(payload.getExpires());
        }
        if (args.has("grace-days")) {
            payload.setGraceDays(args.intValue("grace-days", payload.getGraceDays()));
        }
        if (args.has("customer")) {
            payload.setCustomer(args.first("customer"));
        }
        if (args.has("edition")) {
            payload.setEdition(args.first("edition"));
        }
        if (args.has("bind")) {
            payload.getFingerprints().clear();
            payload.getFingerprints().addAll(args.all("bind"));
        }
        if (args.flag("bind-first-run")) {
            payload.setBindFirstRun(true);
        }
        if (args.has("jvm")) {
            payload.setJvm(args.first("jvm"));
        }

        License.write(licensePath, payload, secret.getMasterKey(), secret.getSigningKey());

        System.out.println("[javashield] licence       : " + licensePath);
        System.out.println("[javashield] build id      : " + payload.getBuildId());
        System.out.println("[javashield] expires       : "
                + (payload.getExpires() == null ? "never" : payload.getExpires()));
        System.out.println("[javashield] grace days    : " + payload.getGraceDays());
        System.out.println("[javashield] customer      : "
                + (payload.getCustomer() == null ? "-" : payload.getCustomer()));
        System.out.println("[javashield] binding       : "
                + (payload.isBindFirstRun() ? "first run"
                : payload.getFingerprints().isEmpty() ? "any machine"
                : payload.getFingerprints().toString()));
        return 0;
    }
}
