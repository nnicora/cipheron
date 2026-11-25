package io.github.nnicora.cipheron.internal.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF-SHA256 (RFC 5869) on the JDK's HMAC-SHA256: HPKE's KDF 0x0001. */
public final class Hkdf {
    /** The length of HMAC-SHA256's output, and of a pseudorandom key. */
    public static final int HASH_LEN = 32;

    private Hkdf() {}

    /** HKDF-Extract: a pseudorandom key from {@code ikm}, salted by {@code salt} (empty: 32 zero bytes). */
    public static byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        byte[] s = salt == null || salt.length == 0 ? new byte[HASH_LEN] : salt;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(s, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    /** HKDF-Expand: {@code length} bytes from the pseudorandom key {@code prk}, bound to {@code info}. */
    public static byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        if (length < 0 || length > 255 * HASH_LEN) {
            throw new GeneralSecurityException("HKDF-Expand: a length of 0 to 8160 bytes");
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int off = 0;
        for (int i = 1; off < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int n = Math.min(t.length, length - off);
            System.arraycopy(t, 0, out, off, n);
            off += n;
        }
        return out;
    }
}
