package com.javashield.agent;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Reads protected class payloads either from the application jar or, when the
 * process was started from a class path, from the class loader.
 *
 * <p>{@link JarFile} is not documented as thread safe for concurrent
 * {@code getInputStream} calls on the same entry, so reads are serialised.
 */
public final class PayloadSource implements Closeable {

    private final JarFile jar;
    private final ClassLoader loader;
    private final Object lock = new Object();

    private PayloadSource(JarFile jar, ClassLoader loader) {
        this.jar = jar;
        this.loader = loader;
    }

    public static PayloadSource open(Path appJar) throws IOException {
        if (appJar != null) {
            return new PayloadSource(new JarFile(appJar.toFile(), false), null);
        }
        ClassLoader loader = PayloadSource.class.getClassLoader();
        if (loader == null) {
            loader = ClassLoader.getSystemClassLoader();
        }
        return new PayloadSource(null, loader);
    }

    public byte[] read(String path) throws IOException {
        if (jar != null) {
            synchronized (lock) {
                JarEntry entry = jar.getJarEntry(path);
                if (entry == null) {
                    throw new IOException("protected entry is missing: " + path);
                }
                InputStream in = jar.getInputStream(entry);
                try {
                    return readAll(in);
                } finally {
                    in.close();
                }
            }
        }
        InputStream in = loader == null ? null : loader.getResourceAsStream(path);
        if (in == null) {
            throw new IOException("protected entry is missing: " + path);
        }
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    public byte[] readOptional(String path) {
        try {
            return read(path);
        } catch (IOException exc) {
            return null;
        }
    }

    public boolean exists(String path) {
        if (jar != null) {
            synchronized (lock) {
                return jar.getJarEntry(path) != null;
            }
        }
        return loader != null && loader.getResource(path) != null;
    }

    @Override
    public void close() {
        if (jar != null) {
            try {
                jar.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
