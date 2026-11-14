package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;

import com.javashield.cli.Args;
import com.javashield.builder.AgentLocator;
import com.javashield.builder.BuildOptions;
import com.javashield.builder.BuildResult;
import com.javashield.builder.JarBuilder;
import com.javashield.tool.ToolCodes;
import com.javashield.tool.ToolFeatures;
import com.javashield.tool.ToolLicenseChecker;
import com.javashield.tool.ToolLicenseException;
import com.javashield.tool.ToolLicenseStatus;
import com.javashield.tool.ToolTrialPolicy;

/** {@code javashield build -i app.jar -o dist/app.jar} */
public final class BuildCommand {

    private BuildCommand() {
    }

    public static int run(Args args) throws IOException {
        BuildOptions options = new BuildOptions();
        options.input = Paths.get(args.firstRequired("input", "i"));
        options.output = Paths.get(args.firstRequired("output", "o"));
        options.cipher = args.first("cipher") == null ? "auto" : args.first("cipher");
        options.integrity = args.first("integrity") == null ? "protected" : args.first("integrity");
        options.expire = args.first("expire", "e");
        options.graceDays = args.intValue("grace-days", 0);
        options.bindFirstRun = args.flag("bind-first-run");
        options.customer = args.first("customer");
        options.edition = args.first("edition") == null ? "standard" : args.first("edition");
        options.jvm = args.first("jvm") == null ? "8-21" : args.first("jvm");
        options.inPlace = args.flag("in-place");
        options.embedAgent = !args.flag("no-embed");
        options.force = args.flag("force");
        options.fingerprints.addAll(args.all("bind"));
        options.excludes.addAll(args.all("exclude"));

        String agent = args.first("agent");
        options.agentJar = agent == null ? AgentLocator.find() : Paths.get(agent);

        ToolLicenseChecker checker = ToolLicenseChecker.createDefault();
        ToolLicenseStatus status = checker.require(ToolFeatures.CLI);

        ToolTrialPolicy.BuildProfile profile = new ToolTrialPolicy.BuildProfile();
        profile.cipher = options.cipher;
        profile.integrity = options.integrity;
        profile.inPlace = options.inPlace;
        profile.customerWatermark = options.customer != null
                && !options.customer.trim().isEmpty();
        profile.explicitBinding = !options.fingerprints.isEmpty();
        profile.bindFirstRun = options.bindFirstRun;
        profile.embeddedAgent = options.embedAgent;
        List<String> problems = ToolTrialPolicy.problems(status, profile);
        if (!problems.isEmpty()) {
            throw new ToolLicenseException(ToolCodes.TRIAL_LIMIT,
                    "trial builds do not allow " + ToolTrialPolicy.describe(problems));
        }

        JarBuilder.validate(options);
        if (JarBuilder.isProtected(options.input)) {
            throw new IllegalArgumentException(
                    "input is already protected; rebuild it from the original jar");
        }
        status = checker.recordBuild(status);
        options.toolWatermark = status.secretWatermark();
        if (status.isTrial()) {
            System.out.println("[javashield] trial build " + status.getTrialBuildsUsed()
                    + "/" + status.getTrialMaxBuilds());
        }

        BuildResult result = JarBuilder.build(options);
        System.out.println("[javashield] done in " + result.classes + " classes, "
                + result.bytes + " bytes");
        return 0;
    }
}
