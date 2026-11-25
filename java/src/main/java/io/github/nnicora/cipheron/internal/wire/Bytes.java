package io.github.nnicora.cipheron.internal.wire;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/** Byte helpers the protocol code shares. */
public final class Bytes {
    /** The empty byte string. */
    public static final byte[] EMPTY = new byte[0];

    private static final HexFormat HEX = HexFormat.of();

    private Bytes() {}

    /** SHA-256 of {@code b}. */
    public static byte[] sha256(byte[] b) {
        return sha256().digest(b);
    }

    /** A new SHA-256 instance. */
    public static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** Lower-case hex of {@code b}. */
    public static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    /** The bytes lower-case or upper-case hex {@code s} names. */
    public static byte[] unhex(String s) {
        return HEX.parseHex(s);
    }

    /** The UTF-8 bytes of {@code s}. */
    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** {@code b} as a string of its bytes, read as UTF-8. */
    public static String string(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /** Whether {@code a} and {@code b} are equal, in time that does not depend on where they differ. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /** Whether {@code a} and {@code b} are equal, in time that does not depend on where they differ. */
    public static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(utf8(a), utf8(b));
    }

    /** {@code b[from, to)}, copied. */
    public static byte[] slice(byte[] b, int from, int to) {
        return Arrays.copyOfRange(b, from, to);
    }

    /** {@code b}, or the empty byte string for null. */
    public static byte[] orEmpty(byte[] b) {
        return b == null ? EMPTY : b;
    }

    /** The unsigned big-endian 32-bit value at {@code b[off]}. */
    public static long uint32(byte[] b, int off) {
        return ((long) (b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8)
                | (b[off + 3] & 0xff);
    }

    /** The big-endian 64-bit value at {@code b[off]}. */
    public static long int64(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[off + i] & 0xff);
        }
        return v;
    }

    /** {@code v} as 8 bytes big-endian. */
    public static byte[] int64(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) v;
            v >>>= 8;
        }
        return b;
    }

    /** {@code v} as 4 bytes big-endian. */
    public static byte[] uint32(long v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    /** Overwrites {@code b} with zeros (best effort: copies the JVM made are out of reach). */
    public static void wipe(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }
}
