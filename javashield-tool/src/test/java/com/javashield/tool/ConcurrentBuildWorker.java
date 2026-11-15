package com.javashield.tool;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;

/**
 * Child process used by {@code ToolLicenseCheckerTest} to exercise the
 * cross-process trial/quota lock. The parent starts several JVMs at the same
 * published instant and expects exactly the configured number of successes.
 */
public final class ConcurrentBuildWorker {

    private ConcurrentBuildWorker() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6) {
            throw new IllegalArgumentException("expected six arguments");
        }
        Path home = Paths.get(args[0]);
        String machine = args[1];
        long startAt = Long.parseLong(args[2]);
        LocalDate today = LocalDate.parse(args[3]);
        int days = Integer.parseInt(args[4]);
        int builds = Integer.parseInt(args[5]);

        long wait = startAt - System.currentTimeMillis();
        if (wait > 0) {
            Thread.sleep(wait);
        }

        ToolStateStore store = new ToolStateStore(home, machine);
        ToolLicenseChecker checker = new ToolLicenseChecker(
                store, null, false, today, null, days, builds);
        try {
            ToolLicenseStatus status = checker.check();
            checker.recordBuild(status);
            System.out.println("OK");
        } catch (ToolLicenseException exc) {
            System.out.println("DENIED:" + exc.getCode());
        }
    }
}
