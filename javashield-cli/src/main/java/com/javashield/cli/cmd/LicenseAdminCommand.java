package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.javashield.cli.Args;
import com.javashield.core.crypto.Ed25519;
import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;
import com.javashield.tool.ToolEntitlement;
import com.javashield.tool.ToolFeatures;
import com.javashield.tool.ToolLicense;
import com.javashield.tool.ToolStateStore;

/**
 * Offline root-key and tool-licence administration.
 *
 * <p>The private key never ships with the builder. This command is shipped for
 * convenience only; it can do nothing without {@code root.key}.</p>
 */
public final class LicenseAdminCommand {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final char[] SERIAL_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private LicenseAdminCommand() {
    }

    public static int run(Args args) throws IOException {
        List<String> positional = args.positional();
        if (positional.isEmpty()) {
            throw new IllegalArgumentException(
                    "usage: license-admin init-root|issue|show|revoke [options]");
        }
        String action = positional.get(0);
        if ("init-root".equals(action)) {
            return initRoot(args);
        }
        if ("issue".equals(action)) {
            return issue(args);
        }
        if ("show".equals(action)) {
            return show(args);
        }
        if ("revoke".equals(action)) {
            return revoke(args);
        }
        throw new IllegalArgumentException("unknown license-admin action: " + action);
    }

    private static int initRoot(Args args) throws IOException {
        String outArg = args.first("out", "o");
        Path out = Paths.get(outArg == null ? "root-keys" : outArg);
        Path key = out.resolve("root.key");
        Path pub = out.resolve("root.pub");
        if (!args.flag("force") && (Files.exists(key) || Files.exists(pub))) {
            throw new IllegalArgumentException(
                    "root key already exists in " + out + " (use --force to replace it)");
        }
        if (Files.exists(key)) {
            System.out.println("[javashield] warning: replacing the root key invalidates "
                    + "every tool licence signed with the old key");
        }
        Files.createDirectories(out);

        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        ToolStateStore.writePrivateFile(key, Json.pretty(ToolLicense.rootKeyDocument(seed)) + "\n");
        ToolStateStore.writeFile(pub, ToolLicense.encodePublicKey(publicKey) + "\n");

        System.out.println("[javashield] root key      : " + key + " (keep offline, never commit)");
        System.out.println("[javashield] public key    : " + pub);
        System.out.println("[javashield] key value     : " + ToolLicense.encodePublicKey(publicKey));
        return 0;
    }

    private static int issue(Args args) throws IOException {
        byte[] seed = ToolLicense.readRootSeed(Paths.get(args.firstRequired("key")));

        ToolEntitlement entitlement = new ToolEntitlement();
        String licenseId = args.first("license-id");
        entitlement.setLicenseId(licenseId == null ? serial() : licenseId.trim());
        entitlement.setCustomer(args.first("customer"));

        String edition = args.first("edition") == null ? "pro" : args.first("edition");
        entitlement.setEdition(edition.trim().toLowerCase(Locale.ROOT));

        Set<String> features = new LinkedHashSet<String>();
        List<String> featureArgs = new ArrayList<String>(args.all("feature"));
        featureArgs.addAll(args.all("features"));
        for (String value : featureArgs) {
            for (String part : value.split(",")) {
                if (!part.trim().isEmpty()) {
                    features.add(part.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        if (features.isEmpty()) {
            features.addAll(ToolFeatures.forEdition(edition));
        }
        entitlement.setFeatures(features);

        entitlement.setSeats(Math.max(0, args.intValue("seats", 1)));
        entitlement.setMaxActivations(Math.max(0, args.intValue("max-activations", 0)));
        entitlement.setMaxBuildsPerMonth(Math.max(0, args.intValue("max-builds", 0)));

        List<String> fingerprints = new ArrayList<String>();
        for (String value : args.all("fingerprint")) {
            for (String part : value.split(",")) {
                if (!part.trim().isEmpty()) {
                    fingerprints.add(part.trim());
                }
            }
        }
        List<String> bindArgs = args.all("bind");
        bindArgs.addAll(args.all("bind-mode"));
        String bindMode;
        if (!bindArgs.isEmpty()) {
            bindMode = bindArgs.get(bindArgs.size() - 1).trim().toLowerCase(Locale.ROOT);
        } else {
            bindMode = fingerprints.isEmpty() ? "any" : "fixed";
        }
        if (!"any".equals(bindMode) && !"fixed".equals(bindMode)) {
            throw new IllegalArgumentException("--bind must be any or fixed");
        }
        if ("fixed".equals(bindMode) && fingerprints.isEmpty()) {
            throw new IllegalArgumentException(
                    "--bind fixed needs at least one --fingerprint <machine-id>");
        }
        entitlement.setBindMode(bindMode);
        entitlement.setFingerprints(fingerprints);
        entitlement.setActivationRequired(args.flag("activation-required"));

        LocalDate start = LocalDate.now(ZoneOffset.UTC);
        String notBefore = args.first("not-before");
        if (notBefore != null) {
            start = Dates.parseDate(notBefore);
            if (start == null) {
                start = LocalDate.now(ZoneOffset.UTC);
            }
        }
        String expiresArg = args.first("expires", "e");
        LocalDate expires;
        if (expiresArg == null) {
            expires = start.plusDays(365);
        } else if ("never".equalsIgnoreCase(expiresArg)
                || "none".equalsIgnoreCase(expiresArg)) {
            expires = null;
        } else {
            expires = Dates.parseDate(expiresArg);
        }
        if (expires != null && expires.isBefore(start)) {
            throw new IllegalArgumentException("--expires must not be before --not-before");
        }
        entitlement.setIssued(Dates.now());
        entitlement.setNotBefore(start);
        entitlement.setExpires(expires);
        entitlement.setGraceDays(Math.max(0, args.intValue("grace-days", 0)));
        entitlement.setRevocationEpoch(args.intValue("revocation-epoch", 0));
        entitlement.setNotes(args.first("notes"));

        Path out = Paths.get(args.first("out", "o") == null
                ? "tool-license.json" : args.first("out", "o"));
        Map<String, Object> document = ToolLicense.signDocument(
                ToolLicense.FORMAT, ToolLicense.SIGNATURE_PREFIX,
                entitlement.toPayload(), seed);
        ToolLicense.writeDocument(out, document);

        String publicKey = ToolLicense.encodePublicKey(Ed25519.publicKeyFromSeed(seed));
        System.out.println("[javashield] tool licence : " + out);
        System.out.println("[javashield] license id   : " + entitlement.getLicenseId());
        System.out.println("[javashield] customer     : " + orDash(entitlement.getCustomer()));
        System.out.println("[javashield] edition      : " + entitlement.getEdition());
        System.out.println("[javashield] features     : " + featureList(entitlement.getFeatures()));
        System.out.println("[javashield] expires      : "
                + (entitlement.getExpires() == null ? "never" : entitlement.getExpires()));
        System.out.println("[javashield] public key   : " + publicKey);
        System.out.println("[javashield] trust key    : embed root.pub in the tool or set "
                + "JAVASHIELD_TOOL_PUBLIC_KEY");
        return 0;
    }

    private static int show(Args args) throws IOException {
        Path license = Paths.get(args.firstRequired("license"));
        String keyArg = args.first("public-key");
        byte[] publicKey;
        if (keyArg == null) {
            publicKey = ToolLicense.loadPublicKey();
        } else {
            Path keyPath = Paths.get(keyArg);
            publicKey = Files.isRegularFile(keyPath)
                    ? ToolLicense.decodePublicKey(new String(Files.readAllBytes(keyPath), UTF_8))
                    : ToolLicense.decodePublicKey(keyArg);
        }
        ToolEntitlement entitlement = ToolLicense.read(license, publicKey);
        printEntitlement(entitlement, publicKey != null);
        return 0;
    }

    private static int revoke(Args args) throws IOException {
        byte[] seed = ToolLicense.readRootSeed(Paths.get(args.firstRequired("key")));
        List<String> revoked = new ArrayList<String>();
        for (String value : args.all("license-id")) {
            for (String part : value.split(",")) {
                if (!part.trim().isEmpty()) {
                    revoked.add(part.trim());
                }
            }
        }
        if (revoked.isEmpty()) {
            throw new IllegalArgumentException("missing --license-id <id>");
        }
        int epoch = args.intValue("epoch", 1);
        Path out = Paths.get(args.first("out", "o") == null
                ? "revocations.json" : args.first("out", "o"));
        Map<String, Object> document = ToolLicense.revocationsDocument(
                seed, revoked, epoch, Dates.now());
        ToolLicense.writeDocument(out, document);
        System.out.println("[javashield] revocations  : " + out);
        System.out.println("[javashield] epoch        : " + epoch);
        System.out.println("[javashield] revoked      : " + revoked);
        return 0;
    }

    private static void printEntitlement(ToolEntitlement entitlement, boolean verified) {
        System.out.println("[javashield] license id   : " + entitlement.getLicenseId());
        System.out.println("[javashield] customer     : " + orDash(entitlement.getCustomer()));
        System.out.println("[javashield] edition      : " + entitlement.getEdition());
        System.out.println("[javashield] features     : "
                + featureList(entitlement.getFeatures()));
        System.out.println("[javashield] seats        : " + entitlement.getSeats());
        System.out.println("[javashield] activations  : "
                + (entitlement.getMaxActivations() == 0
                ? "unlimited" : String.valueOf(entitlement.getMaxActivations())));
        System.out.println("[javashield] builds/month : "
                + (entitlement.getMaxBuildsPerMonth() == 0
                ? "unlimited" : String.valueOf(entitlement.getMaxBuildsPerMonth())));
        System.out.println("[javashield] binding      : " + entitlement.getBindMode()
                + (entitlement.getFingerprints().isEmpty()
                ? "" : " " + entitlement.getFingerprints()));
        System.out.println("[javashield] activation   : "
                + (entitlement.isActivationRequired() ? "required" : "not required"));
        System.out.println("[javashield] not before   : "
                + (entitlement.getNotBefore() == null ? "-" : entitlement.getNotBefore()));
        System.out.println("[javashield] expires      : "
                + (entitlement.getExpires() == null ? "never" : entitlement.getExpires()));
        System.out.println("[javashield] grace days   : " + entitlement.getGraceDays());
        System.out.println("[javashield] revocation   : epoch "
                + entitlement.getRevocationEpoch());
        System.out.println("[javashield] notes        : " + orDash(entitlement.getNotes()));
        System.out.println("[javashield] verification : "
                + (verified ? "signature ok" : "unverified (no tool public key)"));
    }

    private static String featureList(Set<String> features) {
        if (features.isEmpty()) {
            return "-";
        }
        return String.join(", ", new TreeSet<String>(features));
    }

    private static String orDash(String value) {
        return value == null || value.trim().isEmpty() ? "-" : value;
    }

    private static String serial() {
        StringBuilder serial = new StringBuilder("JS");
        for (int group = 0; group < 3; group++) {
            serial.append('-');
            for (int index = 0; index < 4; index++) {
                serial.append(SERIAL_ALPHABET[RANDOM.nextInt(SERIAL_ALPHABET.length)]);
            }
        }
        return serial.toString();
    }
}
