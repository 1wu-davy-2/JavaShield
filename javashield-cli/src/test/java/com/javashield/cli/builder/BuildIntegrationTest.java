package com.javashield.cli.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.javashield.core.BuildSecret;
import com.javashield.core.Product;

class BuildIntegrationTest {

    @TempDir
    Path temp;

    @Test
    void stubBuildProducesAVerifiablePackage() throws Exception {
        Path input = sampleJar("hello.jar");
        Path output = temp.resolve("dist/hello.jar");
        Path agent = fakeAgentJar("agent.jar");

        BuildOptions options = new BuildOptions();
        options.input = input;
        options.output = output;
        options.agentJar = agent;
        options.customer = "Integration";
        options.expire = "2030-12-31";
        options.force = true;

        BuildResult result = JarBuilder.build(options);

        assertTrue(Files.isRegularFile(output));
        assertTrue(Files.isRegularFile(result.license));
        assertTrue(Files.isRegularFile(result.secret));
        assertEquals(3, result.classes);

        BuildSecret secret = BuildSecret.load(result.secret);
        assertTrue(JarVerifier.verify(output, secret).isEmpty());

        try (JarFile jar = new JarFile(output.toFile())) {
            assertNotNull(jar.getJarEntry(Product.MANIFEST_ENTRY));
            assertNotNull(jar.getJarEntry("com/javashield/cli/fixture/Target.class"));
            assertEquals("com.javashield.agent.Agent",
                    jar.getManifest().getMainAttributes().getValue("Launcher-Agent-Class"));
            Map<String, Object> manifest = JarVerifier.readManifest(output);
            assertEquals(3, com.javashield.core.manifest.Manifest.classes(manifest).size());
        }
    }

    @Test
    void inPlaceBuildEncryptsClassEntries() throws Exception {
        Path input = sampleJar("inplace.jar");
        Path output = temp.resolve("dist-inplace/app.jar");

        BuildOptions options = new BuildOptions();
        options.input = input;
        options.output = output;
        options.agentJar = fakeAgentJar("agent2.jar");
        options.inPlace = true;
        options.embedAgent = false;
        options.force = true;

        JarBuilder.build(options);

        try (JarFile jar = new JarFile(output.toFile())) {
            JarEntry entry = jar.getJarEntry("com/javashield/cli/fixture/Target.class");
            assertNotNull(entry);
            byte[] data = readAll(jar.getInputStream(entry));
            assertEquals('J', (char) data[0]);
            assertEquals('S', (char) data[1]);
            assertEquals('X', (char) data[2]);
            assertEquals('1', (char) data[3]);
        }
    }

    @Test
    void fullIntegrityCoversDataFiles() throws Exception {
        Path input = sampleJar("full.jar");
        Path output = temp.resolve("dist-full/app.jar");
        BuildOptions options = new BuildOptions();
        options.input = input;
        options.output = output;
        options.agentJar = fakeAgentJar("agent4.jar");
        options.embedAgent = false;
        options.integrity = "full";
        options.force = true;
        BuildResult result = JarBuilder.build(options);
        BuildSecret secret = BuildSecret.load(result.secret);
        assertTrue(JarVerifier.verify(output, secret).isEmpty());

        rewriteEntry(output, "data.txt", "changed".getBytes("UTF-8"));
        List<String> failures = JarVerifier.verify(output, secret);
        assertFalse(failures.isEmpty());
        assertTrue(failures.get(0).contains("data.txt") || failures.get(0).contains("size"),
                "unexpected failure: " + failures);
    }

    @Test
    void tamperingBreaksVerification() throws Exception {
        Path input = sampleJar("tamper.jar");
        Path output = temp.resolve("dist-tamper/app.jar");
        BuildOptions options = new BuildOptions();
        options.input = input;
        options.output = output;
        options.agentJar = fakeAgentJar("agent3.jar");
        options.embedAgent = false;
        options.force = true;
        BuildResult result = JarBuilder.build(options);
        BuildSecret secret = BuildSecret.load(result.secret);
        assertTrue(JarVerifier.verify(output, secret).isEmpty());

        rewriteEntry(output, "com/javashield/cli/fixture/Target.class", new byte[]{1, 2, 3});
        List<String> failures = JarVerifier.verify(output, secret);
        assertFalse(failures.isEmpty());
    }

    @Test
    void springBootJarKeepsDirectoriesAndStoredNestedJars() throws Exception {
        Path input = temp.resolve("boot.jar");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS,
                "org.springframework.boot.loader.launch.JarLauncher");
        manifest.getMainAttributes().putValue("Spring-Boot-Classes", "BOOT-INF/classes/");
        manifest.getMainAttributes().putValue("Spring-Boot-Lib", "BOOT-INF/lib/");
        byte[] classBytes = readResource("/com/javashield/cli/fixture/Main.class");
        byte[] nested = "nested-jar-bytes".getBytes("UTF-8");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(input), manifest)) {
            for (String directory : new String[]{"BOOT-INF/", "BOOT-INF/classes/",
                    "BOOT-INF/classes/com/", "BOOT-INF/classes/com/javashield/",
                    "BOOT-INF/classes/com/javashield/cli/",
                    "BOOT-INF/classes/com/javashield/cli/fixture/", "BOOT-INF/lib/"}) {
                out.putNextEntry(new JarEntry(directory));
                out.closeEntry();
            }
            out.putNextEntry(new JarEntry("BOOT-INF/classes/com/javashield/cli/fixture/Main.class"));
            out.write(classBytes);
            out.closeEntry();
            JarEntry lib = new JarEntry("BOOT-INF/lib/demo-lib.jar");
            lib.setMethod(java.util.zip.ZipEntry.STORED);
            lib.setSize(nested.length);
            lib.setCompressedSize(nested.length);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(nested);
            lib.setCrc(crc.getValue());
            out.putNextEntry(lib);
            out.write(nested);
            out.closeEntry();
        }

        Path output = temp.resolve("dist-boot/app.jar");
        BuildOptions options = new BuildOptions();
        options.input = input;
        options.output = output;
        options.agentJar = fakeAgentJar("agent5.jar");
        options.embedAgent = false;
        options.force = true;
        BuildResult result = JarBuilder.build(options);
        assertEquals(1, result.classes);

        try (JarFile jar = new JarFile(output.toFile())) {
            assertNotNull(jar.getJarEntry("BOOT-INF/classes/"), "directory entries are required by Boot");
            assertNotNull(jar.getJarEntry("BOOT-INF/lib/"));
            assertEquals(java.util.zip.ZipEntry.STORED,
                    jar.getJarEntry("BOOT-INF/lib/demo-lib.jar").getMethod(),
                    "nested jars must stay STORED");
            assertEquals("com/javashield/cli/fixture/Main",
                    new org.objectweb.asm.ClassReader(readAll(
                            jar.getInputStream(jar.getJarEntry(
                                    "BOOT-INF/classes/com/javashield/cli/fixture/Main.class"))))
                            .getClassName());
        }
    }

    private static byte[] readResource(String resource) throws IOException {
        InputStream in = BuildIntegrationTest.class.getResourceAsStream(resource);
        if (in == null) {
            throw new IOException("fixture not found: " + resource);
        }
        return readAll(in);
    }

    private Path sampleJar(String name) throws IOException {
        Path jarPath = temp.resolve(name);
        Path fixtureDir = Paths.get("target/test-classes/com/javashield/cli/fixture");
        assertTrue(Files.isDirectory(fixtureDir), "test fixtures were not compiled");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "com.javashield.cli.fixture.Main");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarPath), manifest);
             Stream<Path> files = Files.list(fixtureDir)) {
            files.filter(path -> path.toString().endsWith(".class")).forEach(path -> {
                try {
                    out.putNextEntry(new JarEntry("com/javashield/cli/fixture/" + path.getFileName()));
                    out.write(Files.readAllBytes(path));
                    out.closeEntry();
                } catch (IOException exc) {
                    throw new IllegalStateException(exc);
                }
            });
            out.putNextEntry(new JarEntry("data.txt"));
            out.write("original-data".getBytes("UTF-8"));
            out.closeEntry();
        }
        return jarPath;
    }

    private Path fakeAgentJar(String name) throws IOException {
        Path path = temp.resolve(name);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", "com.javashield.agent.Agent");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(path), manifest)) {
            out.putNextEntry(new JarEntry("placeholder.txt"));
            out.write("agent".getBytes("UTF-8"));
            out.closeEntry();
        }
        return path;
    }

    private static void rewriteEntry(Path jarPath, String entryName, byte[] replacement) throws IOException {
        Path tempJar = jarPath.resolveSibling(jarPath.getFileName() + ".tmp");
        try (JarFile source = new JarFile(jarPath.toFile());
             JarOutputStream out = new JarOutputStream(Files.newOutputStream(tempJar))) {
            java.util.Enumeration<JarEntry> entries = source.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                out.putNextEntry(new JarEntry(entry.getName()));
                out.write(entry.getName().equals(entryName)
                        ? replacement : readAll(source.getInputStream(entry)));
                out.closeEntry();
            }
        }
        Files.move(tempJar, jarPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }
}
