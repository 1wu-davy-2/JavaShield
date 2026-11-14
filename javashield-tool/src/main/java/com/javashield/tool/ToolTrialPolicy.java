package com.javashield.tool;

import java.util.ArrayList;
import java.util.List;

/**
 * Build options that are available only with a paid tool licence.
 *
 * <p>The same policy is shared by the CLI, the Maven plugin and (later) the
 * desktop builder, so trial behaviour cannot drift between entry points.</p>
 */
public final class ToolTrialPolicy {

    private ToolTrialPolicy() {
    }

    /** The subset of build options the trial policy cares about. */
    public static final class BuildProfile {
        public String cipher = "auto";
        public String integrity = "protected";
        public boolean inPlace;
        public boolean customerWatermark;
        public boolean explicitBinding;
        public boolean bindFirstRun;
        public boolean embeddedAgent = true;
    }

    public static List<String> problems(ToolLicenseStatus status, BuildProfile profile) {
        List<String> problems = new ArrayList<String>();
        if (status == null || !status.isTrial()) {
            return problems;
        }
        BuildProfile build = profile == null ? new BuildProfile() : profile;
        if (build.inPlace) {
            problems.add("in-place encryption");
        }
        if ("full".equalsIgnoreCase(build.integrity)) {
            problems.add("full integrity coverage");
        }
        if (build.customerWatermark) {
            problems.add("customer watermark");
        }
        if (build.explicitBinding || build.bindFirstRun) {
            problems.add("machine binding");
        }
        return problems;
    }

    public static String describe(List<String> problems) {
        StringBuilder text = new StringBuilder();
        for (String problem : problems) {
            if (text.length() > 0) {
                text.append(", ");
            }
            text.append(problem);
        }
        return text.toString();
    }
}
