package com.javashield.cli.fixture;

@Demo("target")
public final class Target {

    private static final String BUSINESS_SECRET = "business-secret-value";

    private final int value = 7;

    @Demo("answer")
    public int answer() {
        return value + 35;
    }

    public String greet(String name) {
        return BUSINESS_SECRET + ": " + name;
    }
}
