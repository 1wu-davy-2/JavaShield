package com.javashield.agent;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Finds the protected application archive, if the process was started with one. */
final class AppLocator {

    private AppLocator() {
    }

    static Path locate() {
        String explicit = System.getProperty("jshield.app");
        if (explicit != null && !explicit.trim().isEmpty()) {
            Path path = Paths.get(explicit.trim()).toAbsolutePath();
            if (!Files.isRegularFile(path)) {
                throw new IllegalStateException("jshield.app does not point to a file: " + path);
            }
            return path;
        }
        String command = System.getProperty("sun.java.command");
        if (command != null) {
            String trimmed = command.trim();
            int space = trimmed.indexOf(' ');
            String first = space < 0 ? trimmed : trimmed.substring(0, space);
            if (first.endsWith(".jar")) {
                Path path = Paths.get(first).toAbsolutePath();
                if (Files.isRegularFile(path)) {
                    return path;
                }
            }
        }
        return null;
    }
}
