package com.javashield.core.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 零依赖的 Ed25519（RFC 8032）签名实现。
 *
 * <p>仅依赖 JDK 自带的 {@link BigInteger}、{@link MessageDigest} 与
 * {@link SecureRandom}，因此可直接用于 Java 8 运行环境。点运算采用
 * 扩展扭曲爱德华兹坐标（X:Y:Z:T），避免每次点加都做模逆，性能足够
 * 用于许可证签名等低频场景。</p>
 */
public final class Ed25519 {

    /** 种子（私钥）长度，字节。 */
    public static final int SEED_LENGTH = 32;

    /** 公钥长度，字节。 */
    public static final int PUBLIC_KEY_LENGTH = 32;

    /** 签名长度，字节（R 与 S 各 32 字节）。 */
    public static final int SIGNATURE_LENGTH = 64;

    /** 曲线模数 p = 2^255 - 19（RFC 8032 §5.1）。 */
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255)
            .subtract(BigInteger.valueOf(19));

    /** 子群阶 L = 2^252 + 27742317777372353535851937790883648493（RFC 8032 §5.1）。 */
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));

    /** 曲线常数 d = -121665 / 121666 mod p（RFC 8032 §5.1）。 */
    private static final BigInteger D = BigInteger.valueOf(-121665).mod(P)
            .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);

    /** 2d，扩展坐标点加公式的常数项。 */
    private static final BigInteger D2 = D.shiftLeft(1).mod(P);

    /** sqrt(-1) = 2^((p-1)/4) mod p，用于开方失败时的修正。 */
    private static final BigInteger SQRT_M1 = BigInteger.valueOf(2)
            .modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    /** 开方指数 (p-5)/8（RFC 8032 §5.1.3）。 */
    private static final BigInteger EXP_SQRT = P.subtract(BigInteger.valueOf(5)).shiftRight(3);

    /** 基点 B 的 x 坐标。 */
    private static final BigInteger BX = new BigInteger(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202");

    /** 基点 B 的 y 坐标。 */
    private static final BigInteger BY = new BigInteger(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960");

    /** 基点 B，T = x * y。 */
    private static final Point BASE = new Point(BX, BY, BigInteger.ONE, BX.multiply(BY).mod(P));

    /** 单位元 (0, 1)。 */
    private static final Point IDENTITY = new Point(BigInteger.ZERO, BigInteger.ONE,
            BigInteger.ONE, BigInteger.ZERO);

    private static final SecureRandom RANDOM = new SecureRandom();

    private Ed25519() {
        // 工具类，禁止实例化。
    }

    /**
     * 生成 32 字节随机种子。
     *
     * @return 新的种子副本
     */
    public static byte[] generateSeed() {
        byte[] seed = new byte[SEED_LENGTH];
        RANDOM.nextBytes(seed);
        return seed;
    }

    /**
     * 由种子推导公钥（RFC 8032 §5.1.5）。
     *
     * @param seed 32 字节种子
     * @return 32 字节公钥
     */
    public static byte[] publicKeyFromSeed(byte[] seed) {
        checkSeed(seed);
        byte[] h = sha512(seed);
        BigInteger a = decodeLittleEndian(clamp(Arrays.copyOfRange(h, 0, 32)));
        return encodePoint(scalarMult(a, BASE));
    }

    /**
     * 对消息签名（RFC 8032 §5.1.6）。
     *
     * @param seed    32 字节种子
     * @param message 待签名消息
     * @return 64 字节签名 R||S
     */
    public static byte[] sign(byte[] seed, byte[] message) {
        checkSeed(seed);
        if (message == null) {
            throw new IllegalArgumentException("message 不能为 null");
        }

        // 1. 扩展私钥：SHA-512(seed)，前 32 字节 clamp 后作为标量 a，后 32 字节作为前缀。
        byte[] h = sha512(seed);
        byte[] aBytes = clamp(Arrays.copyOfRange(h, 0, 32));
        byte[] prefix = Arrays.copyOfRange(h, 32, 64);
        BigInteger a = decodeLittleEndian(aBytes);

        // 2. 公钥 A = [a]B。
        byte[] publicKey = encodePoint(scalarMult(a, BASE));

        // 3. r = SHA-512(prefix || M) mod L；R = [r]B。
        BigInteger r = decodeLittleEndian(sha512(concat(prefix, message))).mod(L);
        byte[] rEncoded = encodePoint(scalarMult(r, BASE));

        // 4. k = SHA-512(R || A || M) mod L；S = (r + k * a) mod L。
        BigInteger k = decodeLittleEndian(sha512(concat(rEncoded, publicKey, message))).mod(L);
        BigInteger s = r.add(k.multiply(a)).mod(L);

        byte[] signature = new byte[SIGNATURE_LENGTH];
        System.arraycopy(rEncoded, 0, signature, 0, 32);
        byte[] sEncoded = encodeLittleEndian(s);
        System.arraycopy(sEncoded, 0, signature, 32, 32);
        return signature;
    }

    /**
     * 验证签名（RFC 8032 §5.1.7）。
     *
     * <p>非法公钥或非法签名一律返回 {@code false}，不抛出异常。</p>
     *
     * @param publicKey 32 字节公钥
     * @param message   原始消息
     * @param signature 64 字节签名
     * @return 验证通过返回 true
     */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (message == null) {
            throw new IllegalArgumentException("message 不能为 null");
        }
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            return false;
        }
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }

        // 1. 解码公钥 A；失败直接拒绝。
        Point aPoint = decodePoint(publicKey);
        if (aPoint == null) {
            return false;
        }

        // 2. 解析签名：R 为前 32 字节，S 为后 32 字节；要求 S < L。
        byte[] rEncoded = Arrays.copyOfRange(signature, 0, 32);
        BigInteger s = decodeLittleEndian(Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(L) >= 0) {
            return false;
        }

        // 3. k = SHA-512(R || A || M) mod L。
        BigInteger k = decodeLittleEndian(sha512(concat(rEncoded, publicKey, message))).mod(L);

        // 4. 校验 [S]B == R + [k]A，等价于 [S]B - [k]A == R。
        Point left = scalarMult(s, BASE);
        Point right = scalarMult(k, aPoint).negate();
        byte[] computed = encodePoint(left.plus(right));

        // 5. 常量时间比较，避免时序侧信道。
        return MessageDigest.isEqual(computed, rEncoded);
    }

    // ------------------------------------------------------------------
    // 编码与解码
    // ------------------------------------------------------------------

    /**
     * 解码 32 字节点（RFC 8032 §5.1.3）：小端 y，最高位为 x 的奇偶。
     * 校验 y < p、点在曲线上、拒绝非规范编码；失败返回 null。
     */
    private static Point decodePoint(byte[] encoded) {
        if (encoded.length != PUBLIC_KEY_LENGTH) {
            return null;
        }
        byte[] yBytes = encoded.clone();
        int sign = (yBytes[31] >> 7) & 1;
        yBytes[31] &= 0x7f;

        BigInteger y = decodeLittleEndian(yBytes);
        if (y.compareTo(P) >= 0) {
            return null; // 非规范的 y 编码，拒绝。
        }

        // u = y^2 - 1, v = d*y^2 + 1。
        BigInteger y2 = mul(y, y);
        BigInteger u = sub(y2, BigInteger.ONE);
        BigInteger v = add(mul(D, y2), BigInteger.ONE);
        if (v.signum() == 0) {
            return null;
        }

        BigInteger x = recoverX(u, v);
        if (x == null) {
            return null; // 不在曲线上。
        }

        // x = 0 时符号位必须为 0；否则按符号位取补。
        if (x.signum() == 0 && sign == 1) {
            return null;
        }
        if (x.testBit(0) != (sign == 1)) {
            x = P.subtract(x);
        }
        return new Point(x, y, BigInteger.ONE, mul(x, y));
    }

    /**
     * 计算 x = sqrt(u / v)（RFC 8032 §5.1.3），不存在平方根时返回 null。
     */
    private static BigInteger recoverX(BigInteger u, BigInteger v) {
        BigInteger v3 = v.modPow(BigInteger.valueOf(3), P);
        BigInteger v7 = v.modPow(BigInteger.valueOf(7), P);
        BigInteger x = mul(mul(u, v3), mul(u, v7).modPow(EXP_SQRT, P));

        BigInteger check = mul(v, mul(x, x));
        if (check.equals(u)) {
            return x;
        }
        if (check.equals(sub(BigInteger.ZERO, u))) {
            x = mul(x, SQRT_M1);
            if (mul(v, mul(x, x)).equals(u)) {
                return x;
            }
        }
        return null;
    }

    /** 将点压缩为 32 字节：小端 y，最高位写入 x 的奇偶。 */
    private static byte[] encodePoint(Point point) {
        BigInteger zInv = point.z.modInverse(P);
        BigInteger x = mul(point.x, zInv);
        BigInteger y = mul(point.y, zInv);

        byte[] out = encodeLittleEndian(y);
        if (x.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    private static byte[] encodeLittleEndian(BigInteger value) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) (value.shiftRight(8 * i).intValue() & 0xff);
        }
        return out;
    }

    private static BigInteger decodeLittleEndian(byte[] bytes) {
        BigInteger value = BigInteger.ZERO;
        for (int i = bytes.length - 1; i >= 0; i--) {
            value = value.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xff));
        }
        return value;
    }

    // ------------------------------------------------------------------
    // 点运算（扩展扭曲爱德华兹坐标，a = -1）
    // ------------------------------------------------------------------

    /** 标量乘法：从高位到低位的 double-and-add，非递归。 */
    private static Point scalarMult(BigInteger scalar, Point point) {
        Point result = IDENTITY;
        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = result.doublePoint();
            if (scalar.testBit(i)) {
                result = result.plus(point);
            }
        }
        return result;
    }

    /** 扩展坐标点，满足 x = X/Z, y = Y/Z, T = XY/Z。 */
    private static final class Point {
        private final BigInteger x;
        private final BigInteger y;
        private final BigInteger z;
        private final BigInteger t;

        private Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t) {
            this.x = x;
            this.y = y;
            this.z = z;
            this.t = t;
        }

        /** 点加 add-2008-hwcd-3。 */
        private Point plus(Point other) {
            BigInteger a = mul(sub(y, x), sub(other.y, other.x));
            BigInteger b = mul(add(y, x), add(other.y, other.x));
            BigInteger c = mul(mul(t, D2), other.t);
            BigInteger d = mul(z.shiftLeft(1).mod(P), other.z);
            BigInteger e = sub(b, a);
            BigInteger f = sub(d, c);
            BigInteger g = add(d, c);
            BigInteger h = add(b, a);
            return new Point(mul(e, f), mul(g, h), mul(f, g), mul(e, h));
        }

        /** 点倍 dbl-2008-hwcd（a = -1）。 */
        private Point doublePoint() {
            BigInteger a = mul(x, x);
            BigInteger b = mul(y, y);
            BigInteger c = mul(z.shiftLeft(1).mod(P), z);
            BigInteger d = a.negate().mod(P);
            BigInteger e = sub(sub(mul(add(x, y), add(x, y)), a), b);
            BigInteger g = add(d, b);
            BigInteger f = sub(g, c);
            BigInteger h = sub(d, b);
            return new Point(mul(e, f), mul(g, h), mul(f, g), mul(e, h));
        }

        private Point negate() {
            return new Point(x.negate().mod(P), y, z, t.negate().mod(P));
        }
    }

    // ------------------------------------------------------------------
    // 辅助方法
    // ------------------------------------------------------------------

    /** RSA 式 clamp：a[0] &= 248; a[31] &= 127; a[31] |= 64（RFC 8032 §5.1.5）。 */
    private static byte[] clamp(byte[] a) {
        a[0] &= (byte) 248;
        a[31] &= (byte) 127;
        a[31] |= (byte) 64;
        return a;
    }

    private static void checkSeed(byte[] seed) {
        if (seed == null) {
            throw new IllegalArgumentException("seed 不能为 null");
        }
        if (seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("seed 长度必须为 " + SEED_LENGTH + " 字节");
        }
    }

    private static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JVM 不支持 SHA-512", e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static BigInteger add(BigInteger a, BigInteger b) {
        return a.add(b).mod(P);
    }

    private static BigInteger sub(BigInteger a, BigInteger b) {
        return a.subtract(b).mod(P);
    }

    private static BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(P);
    }
}
