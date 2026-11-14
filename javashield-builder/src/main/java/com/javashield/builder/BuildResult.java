package com.javashield.builder;

import java.nio.file.Path;

/** Summary of one successful build. */
public final class BuildResult {

    public final Path output;
    public final Path license;
    public final Path secret;
    public final Path standaloneAgent;
    public final String buildId;
    public final String cipher;
    public final int classes;
    public final long bytes;

    public BuildResult(Path output, Path license, Path secret, Path standaloneAgent,
                       String buildId, String cipher, int classes, long bytes) {
        this.output = output;
        this.license = license;
        this.secret = secret;
        this.standaloneAgent = standaloneAgent;
        this.buildId = buildId;
        this.cipher = cipher;
        this.classes = classes;
        this.bytes = bytes;
    }
}
