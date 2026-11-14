package com.javashield.core;

import java.nio.charset.Charset;
import java.util.Base64;

import com.javashield.core.crypto.Envelope;

/**
 * Reversible obfuscation for the master key embedded in the agent.
 *
 * <p>This only stops {@code strings} from revealing the key. A determined
 * attacker can always recover it from the agent, which is why the licence is
 * signed and why per-class keys exist.
 */
public final class AgentKey {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private AgentKey() {
    }

    public static String pack(byte[] masterKey, String buildId) {
        byte[] stream = keystream(buildId, masterKey.length);
        byte[] masked = new byte[masterKey.length];
        for (int i = 0; i < masterKey.length; i++) {
            masked[i] = (byte) (masterKey[i] ^ stream[i]);
        }
        return Base64.getEncoder().encodeToString(masked);
    }

    public static byte[] unpack(String packed, String buildId) {
        byte[] masked;
        try {
            masked = Base64.getDecoder().decode(packed);
        } catch (IllegalArgumentException exc) {
            throw new IllegalStateException("agent master key is not valid Base64", exc);
        }
        byte[] stream = keystream(buildId, masked.length);
        byte[] key = new byte[masked.length];
        for (int i = 0; i < masked.length; i++) {
            key[i] = (byte) (masked[i] ^ stream[i]);
        }
        return key;
    }

    private static byte[] keystream(String buildId, int length) {
        byte[] seed = Envelope.sha256(("jshield-agent-v1:" + buildId).getBytes(UTF_8));
        return Envelope.hkdf(seed, "jshield-agent-v1".getBytes(UTF_8),
                buildId.getBytes(UTF_8), length);
    }
}
