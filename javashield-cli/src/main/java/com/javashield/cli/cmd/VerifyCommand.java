package com.javashield.cli.cmd;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import com.javashield.cli.Args;
import com.javashield.builder.JarVerifier;
import com.javashield.core.BuildSecret;
import com.javashield.core.manifest.Manifest;

/** {@code javashield verify --jar dist/app.jar --secret app.jar.jshield-secret.json} */
public final class VerifyCommand {

    private VerifyCommand() {
    }

    public static int run(Args args) throws IOException {
        Path jar = Paths.get(args.firstRequired("jar", "j"));
        Path secretPath = Paths.get(args.firstRequired("secret"));
        BuildSecret secret = BuildSecret.load(secretPath);

        List<String> failures = JarVerifier.verify(jar, secret);
        Map<String, Object> manifest = JarVerifier.readManifest(jar);
        int classes = Manifest.classes(manifest).size();

        if (failures.isEmpty()) {
            System.out.println("[javashield] verify OK");
            System.out.println("[javashield] build id : " + manifest.get("build_id"));
            System.out.println("[javashield] cipher   : " + manifest.get("cipher"));
            System.out.println("[javashield] classes  : " + classes);
            return 0;
        }
        System.err.println("[javashield] verify FAILED (" + failures.size() + " problems)");
        for (String failure : failures) {
            System.err.println("  - " + failure);
        }
        return 1;
    }
}
