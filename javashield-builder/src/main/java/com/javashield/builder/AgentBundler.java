package com.javashield.builder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.javashield.core.AgentKey;
import com.javashield.core.Product;

/** Copies the runtime agent into the application jar, or writes it standalone. */
public final class AgentBundler {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private AgentBundler() {
    }

    public static String config(String buildId, String cipher, byte[] masterKey, byte[] publicKey) {
        return "product=" + Product.NAME + "\n"
                + "build_id=" + buildId + "\n"
                + "cipher=" + cipher + "\n"
                + "master_key=" + AgentKey.pack(masterKey, buildId) + "\n"
                + "public_key=" + Base64.getEncoder().encodeToString(publicKey) + "\n"
                + "manifest=" + Product.MANIFEST_ENTRY + "\n";
    }

    public static void embed(JarOutputStream out, Path agentJar, String config, Set<String> written)
            throws IOException {
        try (JarFile agent = new JarFile(agentJar.toFile(), false)) {
            for (JarEntry entry : Collections.list(agent.entries())) {
                String name = entry.getName();
                if (entry.isDirectory()
                        || name.equals("META-INF/MANIFEST.MF")
                        || name.equals(Product.AGENT_CONFIG)) {
                    continue;
                }
                write(out, name, readAll(agent.getInputStream(entry)), entry.getTime(), written);
            }
        }
        write(out, Product.AGENT_CONFIG, config.getBytes(UTF_8), System.currentTimeMillis(), written);
    }

    /** Rewrites the template agent jar with this build's configuration. */
    public static void writeStandalone(Path template, Path target, String config) throws IOException {
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (JarFile agent = new JarFile(template.toFile(), false)) {
            Manifest manifest = agent.getManifest() == null ? new Manifest() : new Manifest(agent.getManifest());
            try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(target), manifest)) {
                Set<String> written = new HashSet<String>();
                written.add("META-INF/MANIFEST.MF");
                for (JarEntry entry : Collections.list(agent.entries())) {
                    String name = entry.getName();
                    if (entry.isDirectory()
                            || name.equals("META-INF/MANIFEST.MF")
                            || name.equals(Product.AGENT_CONFIG)) {
                        continue;
                    }
                    write(out, name, readAll(agent.getInputStream(entry)), entry.getTime(), written);
                }
                write(out, Product.AGENT_CONFIG, config.getBytes(UTF_8), System.currentTimeMillis(), written);
            }
        }
    }

    static void write(JarOutputStream out, String name, byte[] data, long time, Set<String> written)
            throws IOException {
        if (!written.add(name)) {
            return;
        }
        JarEntry entry = new JarEntry(name);
        if (time > 0) {
            entry.setTime(time);
        }
        out.putNextEntry(entry);
        out.write(data);
        out.closeEntry();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    /** Kept for callers that want to inspect the template without opening it twice. */
    static List<JarEntry> entriesOf(Path jar) throws IOException {
        try (JarFile file = new JarFile(jar.toFile(), false)) {
            return Collections.list(file.entries());
        }
    }
}
