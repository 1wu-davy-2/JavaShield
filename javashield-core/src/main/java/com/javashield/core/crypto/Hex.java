package com.javashield.core.crypto;

/** Hex helpers kept in one place so every module prints keys the same way. */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] data) {
        if (data == null) {
            return "";
        }
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xFF;
            out[i * 2] = DIGITS[value >>> 4];
            out[i * 2 + 1] = DIGITS[value & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decode(String text) {
        if (text == null) {
            throw new IllegalArgumentException("hex text is null");
        }
        String value = text.trim();
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("hex text has an odd length");
        }
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = digit(value.charAt(i * 2));
            int low = digit(value.charAt(i * 2 + 1));
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        throw new IllegalArgumentException("not a hex character: " + c);
    }
}
