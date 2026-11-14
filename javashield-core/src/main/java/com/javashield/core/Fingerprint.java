package com.javashield.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import com.javashield.core.crypto.Hex;

/**
 * Stable machine fingerprint.
 *
 * <p>The algorithm intentionally matches the Python implementation used by
 * PyShield: take a platform specific identifier, hash it with SHA-256 and keep
 * the first 32 hex characters. Both products can therefore share one licence
 * backend and one customer machine code.
 *
 * <ul>
 *   <li>Windows: {@code HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid}</li>
 *   <li>Linux: {@code /etc/machine-id} or {@code /var/lib/dbus/machine-id}</li>
 *   <li>macOS: {@code IOPlatformUUID} from ioreg</li>
 *   <li>fallback: hostname + first non-loopback MAC address</li>
 * </ul>
 */
public final class Fingerprint {

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final Charset LATIN_1 = Charset.forName("ISO-8859-1");
    private static volatile String cachedId;

    private Fingerprint() {
    }

    /** Returns the 32 character machine code, never empty. */
    public static String machineId() {
        String override = System.getProperty("jshield.machine.id");
        if (override != null && !override.trim().isEmpty()) {
            return override.trim();
        }
        String value = cachedId;
        if (value == null) {
            synchronized (Fingerprint.class) {
                if (cachedId == null) {
                    cachedId = of(rawIdentifier());
                }
                value = cachedId;
            }
        }
        return value;
    }

    /** Returns the 32 character id for a supplied raw identifier (used by tests). */
    public static String of(String raw) {
        return Hex.encode(sha256(raw.getBytes(UTF_8))).substring(0, 32);
    }

    public static String rawIdentifier() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String value = null;
        if (os.contains("win")) {
            value = windowsMachineGuid();
            if (value == null) {
                value = volumeSerial();
            }
        } else if (os.contains("mac")) {
            value = macPlatformUuid();
        } else {
            value = linuxMachineId();
        }
        if (value == null || value.trim().isEmpty()) {
            value = fallbackIdentifier();
        }
        return value.trim();
    }

    private static String windowsMachineGuid() {
        List<String> lines = run("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid");
        for (String line : lines) {
            int index = line.indexOf("REG_SZ");
            if (index >= 0) {
                return line.substring(index + "REG_SZ".length()).trim();
            }
        }
        return null;
    }

    private static String volumeSerial() {
        List<String> lines = run("cmd", "/c", "vol", "C:");
        for (String line : lines) {
            int index = line.indexOf("Serial Number");
            if (index < 0) {
                index = line.indexOf("序列号");
            }
            if (index >= 0) {
                int colon = line.indexOf(':', index);
                if (colon >= 0) {
                    return line.substring(colon + 1).trim();
                }
            }
        }
        return null;
    }

    private static String linuxMachineId() {
        String[] candidates = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
        for (String candidate : candidates) {
            try {
                Path path = Paths.get(candidate);
                if (Files.isReadable(path)) {
                    String text = new String(Files.readAllBytes(path), UTF_8).trim();
                    if (!text.isEmpty()) {
                        return text;
                    }
                }
            } catch (IOException ignored) {
                // try the next candidate
            }
        }
        return null;
    }

    private static String macPlatformUuid() {
        List<String> lines = run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
        for (String line : lines) {
            if (line.contains("IOPlatformUUID")) {
                int quote = line.lastIndexOf('"');
                int previous = quote > 0 ? line.lastIndexOf('"', quote - 1) : -1;
                if (previous >= 0 && quote > previous) {
                    return line.substring(previous + 1, quote).trim();
                }
            }
        }
        return null;
    }

    private static String fallbackIdentifier() {
        StringBuilder sb = new StringBuilder();
        sb.append(System.getProperty("os.name", "?")).append('|');
        sb.append(System.getProperty("os.arch", "?")).append('|');
        try {
            sb.append(java.net.InetAddress.getLocalHost().getHostName());
        } catch (Exception exc) {
            sb.append("unknown-host");
        }
        String mac = firstMacAddress();
        if (mac != null) {
            sb.append('|').append(mac);
        }
        return sb.toString();
    }

    private static String firstMacAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            List<String> addresses = new ArrayList<String>();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || iface.isVirtual()) {
                    continue;
                }
                byte[] hardware = iface.getHardwareAddress();
                if (hardware != null && hardware.length == 6) {
                    addresses.add(Hex.encode(hardware));
                }
            }
            if (!addresses.isEmpty()) {
                Collections.sort(addresses);
                return addresses.get(0);
            }
        } catch (Exception ignored) {
            // fall through
        }
        return null;
    }

    private static List<String> run(String... command) {
        List<String> lines = new ArrayList<String>();
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), LATIN_1));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            } finally {
                reader.close();
            }
            process.waitFor();
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // Commands are best effort; the caller falls back to hostname + MAC.
        }
        return lines;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception exc) {
            throw new IllegalStateException("SHA-256 is unavailable", exc);
        }
    }

    /** Convenience for diagnostics: prints the operating system probe result. */
    public static void main(String[] args) {
        System.out.println("os=" + System.getProperty("os.name"));
        System.out.println("raw=" + rawIdentifier());
        System.out.println("machineId=" + machineId());
        System.out.println("cwd=" + new File(".").getAbsolutePath());
    }
}
