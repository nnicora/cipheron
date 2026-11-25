package io.github.nnicora.cipheron.internal.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

/**
 * NIST P-256 (secp256r1): the curve of the protocol's HPKE KEM, DHKEM(P-256, HKDF-SHA256). Public keys and HPKE
 * encapsulations travel as uncompressed SEC 1 points, 65 bytes ({@code 0x04 || X || Y}).
 */
public final class P256 {
    /** The length of an uncompressed point. */
    public static final int POINT_LEN = 65;

    /** The length of a field element and of a scalar. */
    public static final int SCALAR_LEN = 32;

    static final BigInteger P = new BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    static final BigInteger B = new BigInteger(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    static final BigInteger N = new BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    private static final ECParameterSpec SPEC = spec();

    private P256() {}

    private static ECParameterSpec spec() {
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec("secp256r1"));
            return p.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is not available", e);
        }
    }

    /** The curve's parameters. */
    public static ECParameterSpec params() {
        return SPEC;
    }

    /**
     * Whether {@code b} is an uncompressed P-256 point: 65 bytes, {@code 0x04}, coordinates below p, on the curve
     * ({@code y² = x³ − 3x + b}). The point at infinity has no such encoding.
     */
    public static boolean validPoint(byte[] b) {
        if (b == null || b.length != POINT_LEN || b[0] != 0x04) {
            return false;
        }
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(b, 1, 33));
        BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(b, 33, 65));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            return false;
        }
        BigInteger lhs = y.multiply(y).mod(P);
        BigInteger rhs = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P);
        return lhs.equals(rhs);
    }

    /** The JCA public key of the uncompressed point {@code b}, which must be valid ({@link #validPoint}). */
    public static ECPublicKey publicKey(byte[] b) throws GeneralSecurityException {
        if (!validPoint(b)) {
            throw new GeneralSecurityException("not a P-256 public key");
        }
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(b, 1, 33));
        BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(b, 33, 65));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), SPEC));
    }

    /** The uncompressed encoding of {@code key}. */
    public static byte[] encode(PublicKey key) {
        ECPoint w = ((ECPublicKey) key).getW();
        byte[] out = new byte[POINT_LEN];
        out[0] = 0x04;
        fixed(w.getAffineX(), out, 1);
        fixed(w.getAffineY(), out, 1 + SCALAR_LEN);
        return out;
    }

    /** A new key pair. */
    public static KeyPair generate() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return g.generateKeyPair();
    }

    /** {@code v} as exactly 32 bytes big-endian at {@code out[off]}. */
    static void fixed(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int start = b.length > SCALAR_LEN ? b.length - SCALAR_LEN : 0;
        int len = b.length - start;
        System.arraycopy(b, start, out, off + SCALAR_LEN - len, len);
    }
}
