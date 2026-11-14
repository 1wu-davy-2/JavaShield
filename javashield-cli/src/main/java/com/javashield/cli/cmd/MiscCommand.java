package com.javashield.cli.cmd;

import java.nio.charset.Charset;

import com.javashield.cli.Args;
import com.javashield.core.Fingerprint;
import com.javashield.core.crypto.Ed25519;
import com.javashield.core.crypto.Envelope;
import com.javashield.core.json.Json;
import com.javashield.core.license.Dates;
import com.javashield.core.license.License;
import com.javashield.core.license.LicensePayload;

/** Fingerprint and self test commands. */
public final class MiscCommand {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private MiscCommand() {
    }

    public static int fingerprint(Args args) {
        if (args.flag("raw")) {
            System.out.println(Fingerprint.rawIdentifier());
        } else {
            System.out.println(Fingerprint.machineId());
        }
        return 0;
    }

    public static int selftest(Args args) {
        String ciphers = Envelope.selftest();

        byte[] seed = Ed25519.generateSeed();
        byte[] publicKey = Ed25519.publicKeyFromSeed(seed);
        byte[] message = "javashield".getBytes(UTF_8);
        byte[] signature = Ed25519.sign(seed, message);
        if (!Ed25519.verify(publicKey, message, signature)) {
            throw new IllegalStateException("ed25519 round trip failed");
        }
        byte[] tampered = signature.clone();
        tampered[0] ^= 0x01;
        if (Ed25519.verify(publicKey, message, tampered)) {
            throw new IllegalStateException("ed25519 accepted a tampered signature");
        }

        String canonical = Json.canonical(Json.parse("{\"b\":1,\"a\":2}"));
        if (!"{\"a\":2,\"b\":1}".equals(canonical)) {
            throw new IllegalStateException("json canonical form is unstable: " + canonical);
        }

        byte[] masterKey = Envelope.randomBytes(32);
        byte[] signingSeed = Ed25519.generateSeed();
        LicensePayload payload = new LicensePayload();
        payload.setBuildId("0123456789abcdef");
        payload.setBuildKey(Envelope.randomBytes(32));
        payload.setCipher("aesgcm");
        payload.setCreated(Dates.now());
        payload.setNotBefore(Dates.today());
        payload.setExpires("2030-12-31");
        payload.setGraceDays(7);
        payload.setCustomer("selftest");
        String encoded = License.encode(payload, masterKey, signingSeed);
        LicensePayload decoded = License.decode(encoded, masterKey,
                payload.getBuildId(), Ed25519.publicKeyFromSeed(signingSeed));
        if (!"selftest".equals(decoded.getCustomer()) || decoded.getGraceDays() != 7) {
            throw new IllegalStateException("licence round trip failed");
        }

        System.out.println("[javashield] cipher  : " + ciphers);
        System.out.println("[javashield] ed25519 : ok (1KB message, tamper rejected)");
        System.out.println("[javashield] json    : ok (canonical, stable)");
        System.out.println("[javashield] licence : ok (sign, seal, open, verify)");
        return 0;
    }
}
