package com.javashield.cli.cmd;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import com.javashield.cli.Args;
import com.javashield.tool.ToolCodes;
import com.javashield.tool.ToolEntitlement;
import com.javashield.tool.ToolLicense;
import com.javashield.tool.ToolLicenseChecker;
import com.javashield.tool.ToolLicenseException;
import com.javashield.tool.ToolLicenseStatus;
import com.javashield.tool.ToolStateStore;

/** {@code javashield license status|install|deactivate|revocations}. */
public final class LicenseCommand {

    private LicenseCommand() {
    }

    public static int run(Args args) {
        List<String> positional = args.positional();
        String action = positional.isEmpty() ? "status" : positional.get(0);
        if ("status".equals(action)) {
            return status(args);
        }
        if ("install".equals(action)) {
            return install(args);
        }
        if ("deactivate".equals(action)) {
            return deactivate(args);
        }
        if ("revocations".equals(action)) {
            return revocations(args);
        }
        throw new IllegalArgumentException("unknown license action: " + action);
    }

    private static ToolStateStore store(Args args) {
        String home = args.first("home");
        return new ToolStateStore(home == null
                ? ToolStateStore.defaultHome() : Paths.get(home));
    }

    private static ToolLicenseChecker checker(Args args, Path licensePath) {
        return new ToolLicenseChecker(store(args), ToolLicense.loadPublicKey(),
                ToolLicense.devMode(), LocalDate.now(ZoneOffset.UTC), licensePath);
    }

    private static int status(Args args) {
        String licenseArg = args.first("license");
        Path license = licenseArg == null ? null : Paths.get(licenseArg);
        ToolLicenseStatus status = checker(args, license).check();
        printStatus(status);
        return status.isAllowed() ? 0 : 1;
    }

    private static int install(Args args) {
        Path source = Paths.get(args.firstRequired("license"));
        ToolStateStore store = store(args);
        byte[] publicKey = ToolLicense.loadPublicKey();
        ToolEntitlement entitlement = ToolLicense.read(source, publicKey);
        if (publicKey == null) {
            System.out.println("[javashield] warning: no tool public key is configured; "
                    + "installing without signature verification");
        }

        Path target = store.resolve(ToolStateStore.TOOL_LICENSE_FILE);
        ToolStateStore.copyPrivate(source, target);
        // Validate the file itself even when development mode is enabled; the
        // development bypass affects building, not whether an installed file
        // is a well-formed licence.
        ToolLicenseChecker checker = new ToolLicenseChecker(store, publicKey,
                false, LocalDate.now(ZoneOffset.UTC), target);
        if (entitlement.isActivationRequired()) {
            checker.activate(entitlement);
        }
        ToolLicenseStatus status = checker.check();
        if (!status.isAllowed() && !ToolCodes.QUOTA_EXHAUSTED.equals(status.getCode())) {
            ToolStateStore.delete(target);
            ToolStateStore.delete(store.resolve(ToolStateStore.INSTALL_FILE));
            throw new ToolLicenseException(status.getCode(),
                    "cannot install tool licence: " + status.getMessage());
        }
        if (!status.isAllowed()) {
            System.out.println("[javashield] warning: " + status.getMessage()
                    + "; the licence is installed and available again next month");
        }
        System.out.println("[javashield] tool licence file: " + target);
        printStatus(status);
        return 0;
    }

    private static int deactivate(Args args) {
        ToolStateStore store = store(args);
        ToolStateStore.delete(store.resolve(ToolStateStore.TOOL_LICENSE_FILE));
        ToolStateStore.delete(store.resolve(ToolStateStore.INSTALL_FILE));
        System.out.println("[javashield] tool licence removed from " + store.home());
        return 0;
    }

    private static int revocations(Args args) {
        Path file = Paths.get(args.firstRequired("file"));
        byte[] publicKey = ToolLicense.loadPublicKey();
        if (publicKey == null) {
            System.out.println("[javashield] warning: no tool public key is configured; "
                    + "the revocation list will be stored without verification");
        } else {
            ToolLicense.readRevocations(file, publicKey);
        }
        ToolStateStore store = store(args);
        Path target = store.resolve(ToolStateStore.REVOCATIONS_FILE);
        ToolStateStore.copyPrivate(file, target);
        System.out.println("[javashield] revocation list installed: " + target);
        return 0;
    }

    private static void printStatus(ToolLicenseStatus status) {
        System.out.println("[javashield] tool licence : " + status.getMode());
        System.out.println("[javashield] code         : " + status.getCode());
        System.out.println("[javashield] machine      : " + status.getMachine());
        System.out.println("[javashield] edition      : "
                + (status.getEdition() == null ? "unknown" : status.getEdition()));
        if (status.getLicenseId() != null) {
            System.out.println("[javashield] license id   : " + status.getLicenseId());
        }
        if (status.getCustomer() != null) {
            System.out.println("[javashield] customer     : " + status.getCustomer());
        }
        if (status.getExpires() != null) {
            System.out.println("[javashield] expires      : " + status.getExpires());
        }
        if (status.isTrial()) {
            System.out.println("[javashield] trial        : " + status.getTrialDaysLeft()
                    + " day(s) left, " + status.getTrialBuildsLeft() + " build(s) left");
        } else if (status.isLicensed() || status.getQuotaLimit() > 0) {
            System.out.println("[javashield] builds       : " + status.getQuotaUsed() + " used"
                    + (status.getQuotaLimit() > 0
                    ? " of " + status.getQuotaLimit() + " this month" : " (unlimited)"));
        }
        System.out.println("[javashield] verification : " + verification(status));
        System.out.println("[javashield] message      : " + status.getMessage());
    }

    private static String verification(ToolLicenseStatus status) {
        if (status.isDevelopment() || status.isTrial()) {
            return "not required";
        }
        if (status.isVerified()) {
            return "signature ok";
        }
        return ToolLicense.loadPublicKey() == null
                ? "unverified (no tool public key)" : "signature not verified";
    }
}
