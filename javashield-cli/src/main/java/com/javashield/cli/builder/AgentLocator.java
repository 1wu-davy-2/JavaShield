package com.javashield.cli.builder;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.javashield.core.Product;

/** Finds the agent jar used as the template for embedding and standalone output. */
public final class AgentLocator {

    private AgentLocator() {
    }

    public static Path find() {
        String explicit = System.getProperty("javashield.agent.jar");
        if (isFile(explicit)) {
            return Paths.get(explicit).toAbsolutePath();
        }
        String fromEnv = System.getenv("JAVASHIELD_AGENT_JAR");
        if (isFile(fromEnv)) {
            return Paths.get(fromEnv).toAbsolutePath();
        }

        Path cliJar = cliJar();
        if (cliJar != null && cliJar.getParent() != null) {
            Path directory = cliJar.getParent();
            Path[] candidates = {
                    directory.resolve("jshield-agent.jar"),
                    directory.resolve("javashield-agent-" + Product.VERSION + "-agent.jar"),
                    directory.resolve("javashield-agent-" + Product.VERSION + "-SNAPSHOT-agent.jar"),
                    directory.resolve("javashield-agent-" + Product.VERSION + ".jar")
            };
            for (Path candidate : candidates) {
                if (Files.isRegularFile(candidate)) {
                    return candidate.toAbsolutePath();
                }
            }
        }

        Path development = findDevelopmentAgent();
        if (development != null) {
            return development;
        }
        throw new IllegalStateException("cannot locate the agent jar; pass --agent <path> "
                + "or set -Djavashield.agent.jar=<path>");
    }

    /** Looks for the agent module output while running from a source tree. */
    private static Path findDevelopmentAgent() {
        Path directory = Paths.get("").toAbsolutePath();
        for (int depth = 0; depth < 5 && directory != null; depth++) {
            Path candidate = directory.resolve("javashield-agent").resolve("target")
                    .resolve("javashield-agent-" + Product.VERSION + "-SNAPSHOT-agent.jar");
            if (Files.isRegularFile(candidate)) {
                return candidate.toAbsolutePath();
            }
            directory = directory.getParent();
        }
        return null;
    }

    private static Path cliJar() {
        try {
            if (AgentLocator.class.getProtectionDomain().getCodeSource() == null) {
                return null;
            }
            Path path = Paths.get(AgentLocator.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            return Files.isRegularFile(path) ? path : null;
        } catch (URISyntaxException exc) {
            return null;
        }
    }

    private static boolean isFile(String path) {
        return path != null && !path.trim().isEmpty() && Files.isRegularFile(Paths.get(path.trim()));
    }
}
