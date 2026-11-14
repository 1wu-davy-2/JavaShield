package com.javashield.builder;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Options for one build. Kept as a plain bean so the CLI and tests share it. */
public final class BuildOptions {

    public Path input;
    public Path output;
    public Path agentJar;

    public String cipher = "auto";
    public String integrity = "protected";
    public String expire;
    public int graceDays;
    public boolean bindFirstRun;
    public final List<String> fingerprints = new ArrayList<String>();
    public String customer;
    public String edition = "standard";
    public String jvm = "8-21";
    public final List<String> excludes = new ArrayList<String>();

    /** Encrypt the class entry itself instead of keeping a metadata stub. */
    public boolean inPlace;

    /** Copy the agent into the application jar and set Launcher-Agent-Class. */
    public boolean embedAgent = true;

    public boolean force;

    /** Optional override for the build secret path; defaults to next to the output. */
    public java.nio.file.Path secretPath;

    /** Optional sink so build tools (Maven, Gradle, GUI) can route progress logs. */
    public LogSink logSink;

    public interface LogSink {
        void log(String message);
    }
}
