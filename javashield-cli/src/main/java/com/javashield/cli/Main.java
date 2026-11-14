package com.javashield.cli;

import java.util.Arrays;

import com.javashield.cli.cmd.BuildCommand;
import com.javashield.cli.cmd.InspectCommand;
import com.javashield.cli.cmd.IssueCommand;
import com.javashield.cli.cmd.LicenseAdminCommand;
import com.javashield.cli.cmd.LicenseCommand;
import com.javashield.cli.cmd.MiscCommand;
import com.javashield.cli.cmd.VerifyCommand;
import com.javashield.core.Product;

/** Command line entry point. */
public final class Main {

    private Main() {
    }

    public static void main(String[] argv) {
        if (argv.length == 0) {
            usage();
            System.exit(2);
        }
        String command = argv[0];
        Args args = Args.parse(Arrays.copyOfRange(argv, 1, argv.length));
        try {
            int code;
            if ("build".equals(command)) {
                code = BuildCommand.run(args);
            } else if ("issue".equals(command)) {
                code = IssueCommand.run(args);
            } else if ("verify".equals(command)) {
                code = VerifyCommand.run(args);
            } else if ("inspect".equals(command)) {
                code = InspectCommand.run(args);
            } else if ("license".equals(command)) {
                code = LicenseCommand.run(args);
            } else if ("license-admin".equals(command) || "tool-license".equals(command)) {
                code = LicenseAdminCommand.run(args);
            } else if ("fingerprint".equals(command)) {
                code = MiscCommand.fingerprint(args);
            } else if ("selftest".equals(command)) {
                code = MiscCommand.selftest(args);
            } else if ("help".equals(command) || "--help".equals(command) || "-h".equals(command)) {
                usage();
                code = 0;
            } else if ("version".equals(command) || "--version".equals(command) || "-V".equals(command)) {
                System.out.println(Product.DISPLAY_NAME + " " + Product.VERSION);
                code = 0;
            } else {
                System.err.println("[javashield] unknown command: " + command);
                usage();
                code = 2;
            }
            System.exit(code);
        } catch (IllegalArgumentException exc) {
            System.err.println("[javashield] " + exc.getMessage());
            System.exit(2);
        } catch (Exception exc) {
            String message = exc.getMessage();
            System.err.println("[javashield] " + (message == null ? exc.toString() : message));
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println(Product.DISPLAY_NAME + " " + Product.VERSION
                + " - bytecode protection for JVM applications");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  javashield build -i <app.jar> -o <dist/app.jar> [options]");
        System.out.println("  javashield issue --secret <app.jar.jshield-secret.json> [options]");
        System.out.println("  javashield verify --jar <dist/app.jar> --secret <secret.json>");
        System.out.println("  javashield inspect --jar <dist/app.jar> | --secret <secret.json>");
        System.out.println("  javashield license [status|install|deactivate|revocations] [options]");
        System.out.println("  javashield license-admin <init-root|issue|show|revoke> [options]");
        System.out.println("  javashield fingerprint");
        System.out.println("  javashield selftest");
        System.out.println();
        System.out.println("Build options:");
        System.out.println("  --cipher auto|aesgcm|chacha|chacha-pure   encryption suite (default auto)");
        System.out.println("  --integrity protected|full|off            manifest coverage");
        System.out.println("  -e, --expire <date>                       expiry, yyyy-MM-dd");
        System.out.println("  --grace-days <n>                          grace period after expiry");
        System.out.println("  --bind <machine-id>                       allow a machine, repeatable");
        System.out.println("  --bind-first-run                          bind on first start");
        System.out.println("  --customer <name>                         customer label");
        System.out.println("  --edition standard|pro|enterprise         licence edition");
        System.out.println("  --jvm <range>                             documented JVM range (default 8-21)");
        System.out.println("  --exclude <package>                       keep a package in plaintext, repeatable");
        System.out.println("  --in-place                                encrypt class entries, no metadata stub");
        System.out.println("  --no-embed                                do not copy the agent into the jar");
        System.out.println("  --agent <path>                            agent jar template");
        System.out.println("  --force                                   overwrite the output");
        System.out.println();
        System.out.println("Issue options:");
        System.out.println("  --secret <path>   build secret (required)");
        System.out.println("  --out <path>      licence output (default: path recorded in the secret)");
        System.out.println("  -e, --expire <date>  --grace-days <n>  --customer <name>");
        System.out.println("  --bind <machine-id> (repeatable, replaces the current list)");
        System.out.println("  --bind-first-run   --edition <name>  --jvm <range>");
        System.out.println();
        System.out.println("Tool licence:");
        System.out.println("  license status [--license <path>] [--home <dir>]");
        System.out.println("  license install --license <path> [--home <dir>]");
        System.out.println("  license deactivate [--home <dir>]");
        System.out.println("  license revocations --file <path> [--home <dir>]");
        System.out.println("  license-admin init-root --out <dir> [--force]");
        System.out.println("  license-admin issue --key <root.key> --out <licence.json>");
        System.out.println("        [--license-id <id>] [--customer <name>] [--edition pro|enterprise|oem]");
        System.out.println("        [--feature <name> ...] [--max-builds <n>] [--max-activations <n>]");
        System.out.println("        [--expires yyyy-MM-dd|never] [--bind any|fixed]");
        System.out.println("        [--fingerprint <machine-id> ...] [--activation-required]");
        System.out.println("  license-admin show --license <licence.json> [--public-key <path|base64>]");
        System.out.println("  license-admin revoke --key <root.key> --license-id <id> --out <revocations.json>");
    }
}
