package com.acme;

@Marker("greeter")
public final class Greeter {

    private final String name;

    public Greeter(String name) {
        this.name = name;
    }

    @Marker("greet")
    public String greet() {
        return "hello, " + name;
    }
}
