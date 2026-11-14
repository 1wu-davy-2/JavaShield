package com.javashield.cli.builder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.javashield.core.BuildSecret;
import com.javashield.core.Product;
import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;
import com.javashield.core.license.Dates;
import com.javashield.core.license.License;
import com.javashield.core.license.LicensePayload;

/**
 * Rewrites an application jar: every business class becomes a metadata stub plus
 * an encrypted payload, and a signed manifest records both.
 *
 * <p>Two modes are supported:
 * <ul>
 *   <li>stub (default): the class entry keeps its signatures and annotations so
 *       Spring and other ASM based scanners still work;</li>
 *   <li>in-place: the class entry itself becomes ciphertext, which is smaller
 *       and hides class structure but breaks metadata scanning.</li>
 * </ul>
 */
public final class JarBuilder {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private JarBuilder() {
    }

    public static BuildResult build(BuildOptions options) throws IOException {
        validate(options);
        Path input = options.input.toAbsolutePath();
        Path output = options.output.toAbsolutePath();
        Path parent = output.getParent() == null ? Paths.get(".").toAbsolutePath() : output.getParent();
        Files.createDirectories(parent);

        Path work = Files.createTempDirectory(parent, ".jshield-work-");
        try {
            return doBuild(options, input, output, parent, work);
        } finally {
            deleteRecursively(work);
        }
    }

    private static BuildResult doBuild(BuildOptions options, Path input, Path output,
                                       Path parent, Path work) throws IOException {
        byte[] masterKey = Keys.random(32);
        byte[] buildKey = Keys.random(32);
        byte[] signingSeed = Keys.random(32);
        byte[] publicKey = Ed25519.publicKeyFromSeed(signingSeed);
        String buildId = Keys.buildId();
        String cipher = Envelope.resolveCipher(options.cipher);

        Path jarOut = work.resolve(output.getFileName().toString());
        Map<String, Object> manifest = com.javashield.core.manifest.Manifest.create(
                buildId, cipher, options.integrity);
        Set<String> written = new LinkedHashSet<String>();
        Set<String> warned = new HashSet<String>();
        int classCount = 0;

        try (JarFile jar = new JarFile(input.toFile(), false)) {
            if (jar.getJarEntry(Product.MANIFEST_ENTRY) != null) {
                throw new IllegalArgumentException(
                        "input is already protected; rebuild it from the original jar");
            }
            List<JarEntry> entries = Collections.list(jar.entries());
            String prefix = detectPrefix(entries, jar.getManifest());
            Manifest targetManifest = jar.getManifest() == null
                    ? new Manifest() : new Manifest(jar.getManifest());
            boolean embed = options.embedAgent && options.agentJar != null;
            if (embed && input.getFileName().toString().toLowerCase().endsWith(".war")) {
                warn(warned, "war files cannot embed an agent; start Tomcat with -javaagent");
                embed = false;
            }
            if (embed && targetManifest.getMainAttributes().getValue(Attributes.Name.MAIN_CLASS) == null) {
                warn(warned, "jar has no Main-Class; the agent is not embedded, start with -javaagent");
                embed = false;
            }
            if (embed) {
                targetManifest.getMainAttributes().putValue(
                        "Launcher-Agent-Class", "com.javashield.agent.Agent");
            }
            targetManifest.getMainAttributes().putValue("JavaShield-Build-Id", buildId);

            try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarOut), targetManifest)) {
                written.add("META-INF/MANIFEST.MF");
                for (JarEntry entry : entries) {
                    if (entry.isDirectory()) {
                        continue;
                    }
                    String name = entry.getName();
                    if (name.equals("META-INF/MANIFEST.MF")) {
                        continue;
                    }
                    if (isSignatureFile(name)) {
                        warn(warned, "dropping jar signature file " + name);
                        continue;
                    }
                    if (isTarget(name, prefix, options, warned)) {
                        classCount += protectClass(jar, out, entry, name, prefix, buildId, buildKey,
                                cipher, options, manifest, written);
                    } else {
                        copy(out, jar.getInputStream(entry), entry, written);
                    }
                }

                if (embed) {
                    String config = AgentBundler.config(buildId, cipher, masterKey, publicKey);
                    AgentBundler.embed(out, options.agentJar.toAbsolutePath(), config, written);
                }

                Map<String, Object> signed = com.javashield.core.manifest.Manifest.sign(
                        manifest, signingSeed);
                byte[] text = com.javashield.core.manifest.Manifest.serialize(signed).getBytes(UTF_8);
                AgentBundler.write(out, Product.MANIFEST_ENTRY, text, System.currentTimeMillis(), written);
            }
        }

        move(jarOut, output, options.force);

        Path licensePath = parent.resolve(Product.LICENSE_FILE);
        Path secretPath = Paths.get(output.toString() + Product.SECRET_SUFFIX);
        Path agentPath = parent.resolve("jshield-agent.jar");

        LicensePayload payload = new LicensePayload();
        payload.setBuildId(buildId);
        payload.setBuildKey(buildKey);
        payload.setCipher(cipher);
        payload.setJvm(options.jvm);
        payload.setCreated(Dates.now());
        payload.setNotBefore(Dates.today());
        payload.setExpires(options.expire);
        payload.setGraceDays(options.graceDays);
        payload.getFingerprints().addAll(options.fingerprints);
        payload.setCustomer(options.customer);
        payload.setEdition(options.edition);
        payload.setBindFirstRun(options.bindFirstRun);
        License.write(licensePath, payload, masterKey, signingSeed);

        BuildSecret secret = new BuildSecret();
        secret.setBuildId(buildId);
        secret.setCipher(cipher);
        secret.setIntegrity(options.integrity);
        secret.setJvm(options.jvm);
        secret.setCustomer(options.customer);
        secret.setOutput(output.toString());
        secret.setLicense(licensePath.toString());
        secret.setMasterKey(masterKey);
        secret.setBuildKey(buildKey);
        secret.setSigningKey(signingSeed);
        secret.setPublicKey(publicKey);
        secret.save(secretPath);

        if (options.agentJar != null) {
            String config = AgentBundler.config(buildId, cipher, masterKey, publicKey);
            AgentBundler.writeStandalone(options.agentJar.toAbsolutePath(), agentPath, config);
        }

        long size = Files.size(output);
        System.out.println("[javashield] build id      : " + buildId);
        System.out.println("[javashield] cipher        : " + cipher);
        System.out.println("[javashield] mode          : " + (options.inPlace ? "in-place" : "stub"));
        System.out.println("[javashield] classes       : " + classCount);
        System.out.println("[javashield] output        : " + output + " (" + size + " bytes)");
        System.out.println("[javashield] licence       : " + licensePath);
        System.out.println("[javashield] build secret  : " + secretPath);
        if (options.agentJar != null) {
            System.out.println("[javashield] agent         : " + agentPath);
        }
        System.out.println("[javashield] keep the build secret offline; never ship it");

        return new BuildResult(output, licensePath, secretPath, agentPath,
                buildId, cipher, classCount, size);
    }

    private static int protectClass(JarFile jar, JarOutputStream out, JarEntry entry, String name,
                                    String prefix, String buildId, byte[] buildKey, String cipher,
                                    BuildOptions options, Map<String, Object> manifest,
                                    Set<String> written) throws IOException {
        byte[] original = readAll(jar.getInputStream(entry));
        String internalName = name.substring(prefix.length(), name.length() - ".class".length());
        byte[] key = Envelope.deriveClassKey(buildKey, internalName);
        byte[] aad = Envelope.classAad(buildId, internalName);
        byte[] sealed = Envelope.seal(key, Envelope.deflate(original), aad, cipher);

        if (options.inPlace) {
            AgentBundler.write(out, name, sealed, entry.getTime(), written);
            com.javashield.core.manifest.Manifest.putClass(manifest, internalName, name, name,
                    sha256(sealed), sha256(sealed), sha256(original));
        } else {
            String payload = Product.PAYLOAD_PREFIX + Keys.payloadName(internalName) + ".bin";
            AgentBundler.write(out, payload, sealed, entry.getTime(), written);
            byte[] stub = StubGenerator.stub(original);
            AgentBundler.write(out, name, stub, entry.getTime(), written);
            com.javashield.core.manifest.Manifest.putClass(manifest, internalName, name, payload,
                    sha256(stub), sha256(sealed), sha256(original));
        }
        return 1;
    }

    private static void validate(BuildOptions options) {
        if (options.input == null || options.output == null) {
            throw new IllegalArgumentException("input and output are required");
        }
        if (!Files.isRegularFile(options.input)) {
            throw new IllegalArgumentException("input jar not found: " + options.input);
        }
        String name = options.input.getFileName().toString().toLowerCase();
        if (name.endsWith(".war")) {
            throw new IllegalArgumentException(
                    "WAR support is planned for 0.2 (the agent needs the webapp class loader); "
                            + "build a Spring Boot fat jar instead");
        }
        if (!name.endsWith(".jar")) {
            throw new IllegalArgumentException("input must be a .jar file: " + options.input);
        }
        if (Files.exists(options.output) && !options.force) {
            throw new IllegalArgumentException("output already exists: " + options.output + " (use --force)");
        }
        if (options.agentJar == null) {
            throw new IllegalArgumentException("agent jar is required");
        }
        if (options.agentJar != null && !Files.isRegularFile(options.agentJar)) {
            throw new IllegalArgumentException("agent jar not found: " + options.agentJar);
        }
        if (options.expire != null) {
            Dates.parseDate(options.expire);
        }
    }

    private static String detectPrefix(List<JarEntry> entries, Manifest manifest) {
        if (manifest != null) {
            String value = manifest.getMainAttributes().getValue("Spring-Boot-Classes");
            if (value != null && !value.trim().isEmpty()) {
                String prefix = value.trim();
                return prefix.endsWith("/") ? prefix : prefix + "/";
            }
        }
        for (JarEntry entry : entries) {
            if (entry.getName().startsWith("WEB-INF/classes/")) {
                return "WEB-INF/classes/";
            }
        }
        return "";
    }

    private static boolean isTarget(String name, String prefix, BuildOptions options, Set<String> warned) {
        if (!name.endsWith(".class")) {
            return false;
        }
        if (name.startsWith("META-INF/versions/")) {
            return false;
        }
        if (name.endsWith("module-info.class")) {
            warn(warned, "module-info.class stays in plaintext");
            return false;
        }
        if (name.endsWith("package-info.class")) {
            return false;
        }
        if (name.startsWith("com/javashield/agent/") || name.startsWith("com/javashield/core/")) {
            return false;
        }
        if (!name.startsWith(prefix)) {
            return false;
        }
        String internalName = name.substring(prefix.length(), name.length() - ".class".length());
        for (String exclude : options.excludes) {
            String normalized = exclude.replace('.', '/');
            if (internalName.equals(normalized) || internalName.startsWith(normalized + "/")) {
                return false;
            }
        }
        return true;
    }

    private static void copy(JarOutputStream out, InputStream in, JarEntry source, Set<String> written)
            throws IOException {
        if (!written.add(source.getName())) {
            in.close();
            return;
        }
        JarEntry entry = new JarEntry(source.getName());
        if (source.getTime() > 0) {
            entry.setTime(source.getTime());
        }
        out.putNextEntry(entry);
        try {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
        } finally {
            in.close();
            out.closeEntry();
        }
    }

    private static boolean isSignatureFile(String name) {
        if (!name.startsWith("META-INF/")) {
            return false;
        }
        String upper = name.toUpperCase();
        return upper.endsWith(".SF") || upper.endsWith(".DSA")
                || upper.endsWith(".RSA") || upper.endsWith(".EC");
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

    private static String sha256(byte[] data) {
        return Hex.encode(Envelope.sha256(data));
    }

    private static void move(Path source, Path target, boolean force) throws IOException {
        if (force) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        } else {
            Files.move(source, target);
        }
    }

    private static void warn(Set<String> warned, String message) {
        if (warned.add(message)) {
            System.err.println("[javashield] warning: " + message);
        }
    }

    private static void deleteRecursively(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        List<Path> paths = new ArrayList<Path>();
        try {
            Files.walk(root).forEach(paths::add);
        } catch (IOException exc) {
            return;
        }
        Collections.reverse(paths);
        for (Path path : paths) {
            try {
                Files.deleteIfExists(path);
            } catch (IOException ignored) {
                // best effort
            }
        }
    }
}
