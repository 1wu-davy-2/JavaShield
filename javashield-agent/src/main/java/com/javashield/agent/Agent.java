package com.javashield.agent;

import java.lang.instrument.Instrumentation;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.javashield.core.license.LicensePayload;
import com.javashield.core.manifest.Manifest;

/**
 * Agent entry point.
 *
 * <p>Supported launch modes:
 * <ul>
 *   <li>{@code java -javaagent:jshield-agent.jar -jar app.jar}</li>
 *   <li>{@code java -jar app.jar} when the builder embedded the agent and set
 *       {@code Launcher-Agent-Class} in the application manifest</li>
 * </ul>
 *
 * <p>Any failure throws out of {@code premain}, which aborts JVM startup. That is
 * intentional: a protected application must never run unprotected.
 */
public final class Agent {

    private static final AtomicBoolean INSTALLED = new AtomicBoolean(false);

    private Agent() {
    }

    public static void premain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void agentmain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    private static void install(Instrumentation instrumentation) {
        if (!INSTALLED.compareAndSet(false, true)) {
            return;
        }
        try {
            AgentConfig config = AgentConfig.load();
            Path appJar = AppLocator.locate();
            PayloadSource source = PayloadSource.open(appJar);
            Map<String, Object> manifest = Integrity.verify(source, config);
            LicensePayload license = LicenseGate.check(config, appJar, source);
            ShieldTransformer transformer = new ShieldTransformer(
                    config, Manifest.classes(manifest), source, license.getBuildKey());
            instrumentation.addTransformer(transformer, false);

            System.err.println("[javashield] ready"
                    + " build=" + config.getBuildId()
                    + " classes=" + Manifest.classes(manifest).size()
                    + " cipher=" + config.getCipher()
                    + (license.getCustomer() == null ? "" : " customer=" + license.getCustomer())
                    + (license.getExpires() == null ? "" : " expires=" + license.getExpires()));
        } catch (Throwable failure) {
            String message = failure.getMessage();
            if (message == null || message.trim().isEmpty()) {
                message = failure.getClass().getName();
            }
            System.err.println("[javashield] refusing to start: " + message);
            throw new IllegalStateException("javashield: " + message, failure);
        }
    }
}
