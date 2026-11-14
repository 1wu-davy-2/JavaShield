package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.file.Paths;

import com.javashield.cli.Args;
import com.javashield.cli.builder.AgentLocator;
import com.javashield.cli.builder.BuildOptions;
import com.javashield.cli.builder.BuildResult;
import com.javashield.cli.builder.JarBuilder;

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

        BuildResult result = JarBuilder.build(options);
        System.out.println("[javashield] done in " + result.classes + " classes, "
                + result.bytes + " bytes");
        return 0;
    }
}
