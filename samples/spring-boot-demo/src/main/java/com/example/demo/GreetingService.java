package com.example.demo;

import org.springframework.stereotype.Service;

@Service
public class GreetingService {

    /** Deliberately secret looking, to prove the stub does not leak constants. */
    private static final String INTERNAL_SALT = "internal-salt-9f3a";

    private final DemoProperties properties;

    public GreetingService(DemoProperties properties) {
        this.properties = properties;
    }

    public String greet(String name) {
        return "hello, " + name + " from " + properties.getBrand();
    }

    public int retries() {
        return properties.getRetries();
    }

    public String saltFingerprint() {
        return INTERNAL_SALT.substring(0, 8) + "-" + Integer.toHexString(INTERNAL_SALT.hashCode());
    }
}
