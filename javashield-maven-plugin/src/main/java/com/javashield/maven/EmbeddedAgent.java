package com.javashield.maven;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Locates the runtime agent shipped inside the plugin jar.
 *
 * <p>The agent is copied into {@code com/javashield/maven/} at build time, so the
 * plugin works from the local repository without relying on file layout.
 */
final class EmbeddedAgent {

    private static final String PREFIX = "com/javashield/maven/javashield-agent-";
    private static final String SUFFIX = "-agent.jar";

    private EmbeddedAgent() {
    }

    static File extract() throws IOException {
        URL location = EmbeddedAgent.class.getProtectionDomain().getCodeSource() == null
                ? null : EmbeddedAgent.class.getProtectionDomain().getCodeSource().getLocation();
        if (location == null) {
            return null;
        }
        File source;
        try {
            source = new File(location.toURI());
        } catch (URISyntaxException exc) {
            return null;
        }
        if (source.isFile()) {
            return fromJar(source);
        }
        if (source.isDirectory()) {
            File directory = new File(source, "com/javashield/maven");
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.getName().startsWith("javashield-agent-")
                            && file.getName().endsWith(SUFFIX)) {
                        return file;
                    }
                }
            }
        }
        return null;
    }

    private static File fromJar(File jarFile) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith(PREFIX) && name.endsWith(SUFFIX)) {
                    return copyOut(jar.getInputStream(entry));
                }
            }
        }
        return null;
    }

    private static File copyOut(InputStream in) throws IOException {
        File temp = File.createTempFile("jshield-agent", ".jar");
        temp.deleteOnExit();
        try (OutputStream out = new FileOutputStream(temp)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
        } finally {
            in.close();
        }
        return temp;
    }
}
