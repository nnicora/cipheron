package io.github.nnicora.cipheron;

import java.time.Duration;

/** An option of one call: its associated data, its target associated data, its deadline. */
public final class CallOption {
    final byte[] aad;
    final byte[] toAad;
    final int segmentSize;
    final Duration timeout;

    private CallOption(byte[] aad, byte[] toAad, int segmentSize, Duration timeout) {
        this.aad = aad;
        this.toAad = toAad;
        this.segmentSize = segmentSize;
        this.timeout = timeout;
    }

    /**
     * Binds the ciphertext to {@code aad} (1 byte to 64 KiB): context such as a row's key, which is not encrypted
     * and must be given again to decrypt. Encrypt then writes format 5 (or 6).
     */
    public static CallOption associatedData(byte[] aad) {
        return new CallOption(aad.clone(), null, 0, null);
    }

    /** A re-encryption's associated data for the new ciphertext: the same bytes as {@link #associatedData}. */
    public static CallOption targetAssociatedData(byte[] aad) {
        return new CallOption(null, aad.clone(), 0, null);
    }

    /** The segment size of an object call: 1 KiB to 16 MiB, default 64 KiB. */
    public static CallOption segmentSize(int bytes) {
        return new CallOption(null, null, bytes, null);
    }

    /** The call's deadline, instead of the client's default. */
    public static CallOption timeout(Duration d) {
        if (d.isNegative() || d.isZero()) {
            throw new IllegalArgumentException("a timeout is positive");
        }
        return new CallOption(null, null, 0, d);
    }
}
