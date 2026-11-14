package com.javashield.maven;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import com.javashield.builder.AgentLocator;
import com.javashield.builder.BuildOptions;
import com.javashield.builder.BuildResult;
import com.javashield.builder.JarBuilder;

/**
 * Protects the packaged application jar in place.
 *
 * <p>Bind this goal after {@code spring-boot-maven-plugin:repackage} so the input
 * is the executable fat jar, not the thin jar.
 */
@Mojo(name = "protect", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true)
public class ProtectMojo extends AbstractMojo {

    @Parameter(property = "javashield.skip", defaultValue = "false")
    private boolean skip;

    @Parameter(property = "javashield.input",
            defaultValue = "${project.build.directory}/${project.build.finalName}.jar")
    private File input;

    @Parameter(property = "javashield.output")
    private File output;

    @Parameter(property = "javashield.agentJar")
    private File agentJar;

    @Parameter(property = "javashield.cipher", defaultValue = "auto")
    private String cipher;

    @Parameter(property = "javashield.integrity", defaultValue = "protected")
    private String integrity;

    @Parameter(property = "javashield.expire")
    private String expire;

    @Parameter(property = "javashield.graceDays", defaultValue = "0")
    private int graceDays;

    @Parameter(property = "javashield.customer")
    private String customer;

    @Parameter(property = "javashield.edition", defaultValue = "standard")
    private String edition;

    @Parameter(property = "javashield.jvm", defaultValue = "8-21")
    private String jvm;

    @Parameter(property = "javashield.bindFirstRun", defaultValue = "false")
    private boolean bindFirstRun;

    @Parameter(property = "javashield.bind")
    private List<String> bind;

    @Parameter(property = "javashield.excludes")
    private List<String> excludes;

    @Parameter(property = "javashield.inPlace", defaultValue = "false")
    private boolean inPlace;

    @Parameter(property = "javashield.embedAgent", defaultValue = "true")
    private boolean embedAgent;

    /**
     * Where the build secret is archived. Kept out of {@code target/} so that
     * {@code mvn clean} does not destroy the only copy of the signing key.
     */
    @Parameter(property = "javashield.secretDirectory",
            defaultValue = "${project.basedir}/.javashield")
    private File secretDirectory;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("JavaShield skipped (javashield.skip=true)");
            return;
        }
        if (input == null || !input.isFile()) {
            throw new MojoExecutionException("input jar not found: " + input
                    + "; run the package phase first");
        }
        File target = output == null ? input : output;
        try {
            if (JarBuilder.isProtected(input.toPath())) {
                getLog().warn("input is already protected: " + input
                        + "; skipping (run 'mvn clean package' to rebuild it)");
                return;
            }
        } catch (IOException exc) {
            throw new MojoExecutionException("cannot read input jar: " + exc.getMessage(), exc);
        }
        File agent = resolveAgent();

        BuildOptions options = new BuildOptions();
        options.input = input.toPath();
        options.output = target.toPath();
        options.agentJar = agent.toPath();
        options.cipher = cipher;
        options.integrity = integrity;
        options.expire = expire;
        options.graceDays = graceDays;
        options.customer = customer;
        options.edition = edition;
        options.jvm = jvm;
        options.bindFirstRun = bindFirstRun;
        if (bind != null) {
            options.fingerprints.addAll(bind);
        }
        if (excludes != null) {
            options.excludes.addAll(excludes);
        }
        options.inPlace = inPlace;
        options.embedAgent = embedAgent;
        options.force = true;
        if (secretDirectory != null) {
            options.secretPath = secretDirectory.toPath()
                    .resolve(target.getName() + com.javashield.core.Product.SECRET_SUFFIX);
        }
        options.logSink = new BuildOptions.LogSink() {
            @Override
            public void log(String message) {
                getLog().info(message);
            }
        };

        if (inPlace) {
            getLog().warn("in-place mode removes class metadata; Spring classpath scanning will fail");
        }

        try {
            BuildResult result = JarBuilder.build(options);
            getLog().info("protected " + result.classes + " classes, build " + result.buildId);
        } catch (Exception exc) {
            throw new MojoExecutionException("JavaShield failed: " + exc.getMessage(), exc);
        }
    }

    private File resolveAgent() throws MojoExecutionException {
        if (agentJar != null) {
            if (!agentJar.isFile()) {
                throw new MojoExecutionException("agent jar not found: " + agentJar);
            }
            return agentJar;
        }
        try {
            File embedded = EmbeddedAgent.extract();
            if (embedded != null) {
                return embedded;
            }
        } catch (IOException exc) {
            getLog().warn("cannot extract the embedded agent: " + exc.getMessage());
        }
        try {
            return AgentLocator.find().toFile();
        } catch (RuntimeException exc) {
            throw new MojoExecutionException(
                    "cannot locate the agent jar; pass -Djavashield.agentJar=<path>", exc);
        }
    }
}
