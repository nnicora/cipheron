package io.github.nnicora.cipheron.internal.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * The protocol's length-prefixed encoding: each field is its length (4 bytes, big-endian) followed by its bytes, so
 * no two different field lists encode the same. Every transcript, digest, fingerprint and label of transcript
 * version 1 is a concatenation of such fields ({@code wire/transport/auth.go}, {@code transcript}).
 */
public final class Lp {
    private final ByteArrayOutputStream out;

    private Lp(int capacity) {
        this.out = new ByteArrayOutputStream(capacity);
    }

    /** An empty encoding. */
    public static Lp create() {
        return new Lp(128);
    }

    /** An empty encoding with room for {@code capacity} bytes. */
    public static Lp withCapacity(int capacity) {
        return new Lp(capacity);
    }

    /** Adds {@code b} as a field: its length, then its bytes. A null field is a zero-length one. */
    public Lp add(byte[] b) {
        byte[] f = b == null ? Bytes.EMPTY : b;
        putUint32(f.length);
        out.writeBytes(f);
        return this;
    }

    /** Adds the UTF-8 bytes of {@code s} as a field. */
    public Lp add(String s) {
        return add(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Adds {@code v} as a field: 4 bytes big-endian, behind its length (4). */
    public Lp addUint32(long v) {
        putUint32(4);
        putUint32(v);
        return this;
    }

    /** Appends {@code b} as it is, with no length: an already encoded group of fields. */
    public Lp raw(byte[] b) {
        out.writeBytes(b);
        return this;
    }

    /** The encoding. */
    public byte[] bytes() {
        return out.toByteArray();
    }

    private void putUint32(long v) {
        out.write((int) (v >>> 24) & 0xff);
        out.write((int) (v >>> 16) & 0xff);
        out.write((int) (v >>> 8) & 0xff);
        out.write((int) v & 0xff);
    }
}
