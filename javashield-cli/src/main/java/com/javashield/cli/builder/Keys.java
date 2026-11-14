package com.javashield.cli.builder;

import java.nio.charset.Charset;
import java.security.SecureRandom;

import com.javashield.core.crypto.Envelope;
import com.javashield.core.crypto.Hex;

/** Key and identifier generation. */
public final class Keys {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Keys() {
    }

    public static byte[] random(int length) {
        byte[] data = new byte[length];
        RANDOM.nextBytes(data);
        return data;
    }

    /** 16 hex characters, matching the Python implementation. */
    public static String buildId() {
        return Hex.encode(random(8));
    }

    /** Stable, path safe payload name derived from the class internal name. */
    public static String payloadName(String internalName) {
        return Hex.encode(Envelope.sha256(internalName.getBytes(UTF_8))).substring(0, 24);
    }
}
