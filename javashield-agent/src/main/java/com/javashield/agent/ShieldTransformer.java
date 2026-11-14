package com.javashield.agent;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Map;

import com.javashield.core.crypto.Envelope;

/**
 * Replaces a protected class stub with the real bytecode.
 *
 * <p>The JVM calls {@code transform} before parsing and verifying the class, so
 * returning plain bytes here is enough: no custom class loader and no changes to
 * the application packaging are required.
 */
public final class ShieldTransformer implements ClassFileTransformer {

    private final AgentConfig config;
    private final Map<String, Object> classes;
    private final PayloadSource source;
    private final byte[] buildKey;
    private final ThreadLocal<Boolean> busy = new ThreadLocal<Boolean>();

    public ShieldTransformer(AgentConfig config, Map<String, Object> classes,
                             PayloadSource source, byte[] buildKey) {
        this.config = config;
        this.classes = classes;
        this.source = source;
        this.buildKey = buildKey;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null) {
            return null;
        }
        Object entry = classes.get(className);
        if (!(entry instanceof Map)) {
            return null;
        }
        if (Boolean.TRUE.equals(busy.get())) {
            throw new IllegalStateException("javashield: recursive load while decrypting " + className);
        }
        busy.set(Boolean.TRUE);
        try {
            Object payloadPath = ((Map<?, ?>) entry).get("payload");
            if (payloadPath == null) {
                throw new IllegalStateException("javashield: manifest entry has no payload: " + className);
            }
            byte[] sealed = source.read(String.valueOf(payloadPath));
            byte[] key = Envelope.deriveClassKey(buildKey, className);
            byte[] compressed = Envelope.open(key, sealed,
                    Envelope.classAad(config.getBuildId(), className));
            return Envelope.inflate(compressed);
        } catch (IOException exc) {
            throw new IllegalStateException("javashield: cannot read payload for " + className, exc);
        } catch (RuntimeException exc) {
            throw new IllegalStateException("javashield: cannot decrypt protected class " + className, exc);
        } finally {
            busy.set(Boolean.FALSE);
        }
    }
}
