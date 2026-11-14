package com.javashield.core.crypto;

/**
 * Pure Java ChaCha20 (RFC 8439) used as the zero-dependency fallback cipher.
 *
 * <p>It is only used when neither AES-GCM nor ChaCha20-Poly1305 is available,
 * which in practice means very old JREs with a restricted JCE policy. The
 * implementation is intentionally straightforward rather than fastest.
 */
public final class ChaCha20 {

    private static final int[] SIGMA = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};
    public static final int NONCE_LENGTH = 12;
    public static final int KEY_LENGTH = 32;

    private ChaCha20() {
    }

    /** XORs {@code data} with the ChaCha20 keystream starting at {@code counter}. */
    public static byte[] xor(byte[] key, byte[] nonce, byte[] data, int counter) {
        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("ChaCha20 key must be 32 bytes");
        }
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("ChaCha20 nonce must be 12 bytes");
        }
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        byte[] out = new byte[data.length];
        int[] state = initialState(key, counter, nonce);
        byte[] block = new byte[64];
        int offset = 0;
        while (offset < data.length) {
            block(state, block);
            int span = Math.min(64, data.length - offset);
            for (int i = 0; i < span; i++) {
                out[offset + i] = (byte) (data[offset + i] ^ block[i]);
            }
            offset += span;
            state[12]++;
        }
        return out;
    }

    /** Returns the raw 64-byte keystream block, exposed for RFC 8439 test vectors. */
    public static byte[] blockBytes(byte[] key, byte[] nonce, int counter) {
        byte[] block = new byte[64];
        block(initialState(key, counter, nonce), block);
        return block;
    }

    private static int[] initialState(byte[] key, int counter, byte[] nonce) {
        int[] state = new int[16];
        System.arraycopy(SIGMA, 0, state, 0, 4);
        for (int i = 0; i < 8; i++) {
            state[4 + i] = littleEndianInt(key, i * 4);
        }
        state[12] = counter;
        for (int i = 0; i < 3; i++) {
            state[13 + i] = littleEndianInt(nonce, i * 4);
        }
        return state;
    }

    private static void block(int[] initial, byte[] out) {
        int x0 = initial[0];
        int x1 = initial[1];
        int x2 = initial[2];
        int x3 = initial[3];
        int x4 = initial[4];
        int x5 = initial[5];
        int x6 = initial[6];
        int x7 = initial[7];
        int x8 = initial[8];
        int x9 = initial[9];
        int x10 = initial[10];
        int x11 = initial[11];
        int x12 = initial[12];
        int x13 = initial[13];
        int x14 = initial[14];
        int x15 = initial[15];

        for (int round = 0; round < 10; round++) {
            x0 += x4; x12 ^= x0; x12 = Integer.rotateLeft(x12, 16);
            x8 += x12; x4 ^= x8; x4 = Integer.rotateLeft(x4, 12);
            x0 += x4; x12 ^= x0; x12 = Integer.rotateLeft(x12, 8);
            x8 += x12; x4 ^= x8; x4 = Integer.rotateLeft(x4, 7);

            x1 += x5; x13 ^= x1; x13 = Integer.rotateLeft(x13, 16);
            x9 += x13; x5 ^= x9; x5 = Integer.rotateLeft(x5, 12);
            x1 += x5; x13 ^= x1; x13 = Integer.rotateLeft(x13, 8);
            x9 += x13; x5 ^= x9; x5 = Integer.rotateLeft(x5, 7);

            x2 += x6; x14 ^= x2; x14 = Integer.rotateLeft(x14, 16);
            x10 += x14; x6 ^= x10; x6 = Integer.rotateLeft(x6, 12);
            x2 += x6; x14 ^= x2; x14 = Integer.rotateLeft(x14, 8);
            x10 += x14; x6 ^= x10; x6 = Integer.rotateLeft(x6, 7);

            x3 += x7; x15 ^= x3; x15 = Integer.rotateLeft(x15, 16);
            x11 += x15; x7 ^= x11; x7 = Integer.rotateLeft(x7, 12);
            x3 += x7; x15 ^= x3; x15 = Integer.rotateLeft(x15, 8);
            x11 += x15; x7 ^= x11; x7 = Integer.rotateLeft(x7, 7);

            x0 += x5; x15 ^= x0; x15 = Integer.rotateLeft(x15, 16);
            x10 += x15; x5 ^= x10; x5 = Integer.rotateLeft(x5, 12);
            x0 += x5; x15 ^= x0; x15 = Integer.rotateLeft(x15, 8);
            x10 += x15; x5 ^= x10; x5 = Integer.rotateLeft(x5, 7);

            x1 += x6; x12 ^= x1; x12 = Integer.rotateLeft(x12, 16);
            x11 += x12; x6 ^= x11; x6 = Integer.rotateLeft(x6, 12);
            x1 += x6; x12 ^= x1; x12 = Integer.rotateLeft(x12, 8);
            x11 += x12; x6 ^= x11; x6 = Integer.rotateLeft(x6, 7);

            x2 += x7; x13 ^= x2; x13 = Integer.rotateLeft(x13, 16);
            x8 += x13; x7 ^= x8; x7 = Integer.rotateLeft(x7, 12);
            x2 += x7; x13 ^= x2; x13 = Integer.rotateLeft(x13, 8);
            x8 += x13; x7 ^= x8; x7 = Integer.rotateLeft(x7, 7);

            x3 += x4; x14 ^= x3; x14 = Integer.rotateLeft(x14, 16);
            x9 += x14; x4 ^= x9; x4 = Integer.rotateLeft(x4, 12);
            x3 += x4; x14 ^= x3; x14 = Integer.rotateLeft(x14, 8);
            x9 += x14; x4 ^= x9; x4 = Integer.rotateLeft(x4, 7);
        }

        writeLittleEndian(x0 + initial[0], out, 0);
        writeLittleEndian(x1 + initial[1], out, 4);
        writeLittleEndian(x2 + initial[2], out, 8);
        writeLittleEndian(x3 + initial[3], out, 12);
        writeLittleEndian(x4 + initial[4], out, 16);
        writeLittleEndian(x5 + initial[5], out, 20);
        writeLittleEndian(x6 + initial[6], out, 24);
        writeLittleEndian(x7 + initial[7], out, 28);
        writeLittleEndian(x8 + initial[8], out, 32);
        writeLittleEndian(x9 + initial[9], out, 36);
        writeLittleEndian(x10 + initial[10], out, 40);
        writeLittleEndian(x11 + initial[11], out, 44);
        writeLittleEndian(x12 + initial[12], out, 48);
        writeLittleEndian(x13 + initial[13], out, 52);
        writeLittleEndian(x14 + initial[14], out, 56);
        writeLittleEndian(x15 + initial[15], out, 60);
    }

    private static int littleEndianInt(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static void writeLittleEndian(int value, byte[] out, int offset) {
        out[offset] = (byte) value;
        out[offset + 1] = (byte) (value >>> 8);
        out[offset + 2] = (byte) (value >>> 16);
        out[offset + 3] = (byte) (value >>> 24);
    }
}
