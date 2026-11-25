package io.github.nnicora.cipheron.internal.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * Ed25519 (RFC 8032, pure) on the JDK's provider: every signature of the protocol — request keys, the response key,
 * the signing keys, key statements — is one. Keys travel as their raw 32 bytes, signatures as 64.
 */
public final class Ed25519 {
    /** The length of an Ed25519 public key. */
    public static final int PUBLIC_KEY_LEN = 32;

    /** The length of an Ed25519 signature. */
    public static final int SIGNATURE_LEN = 64;

    /** The length of an Ed25519 private key's seed. */
    public static final int SEED_LEN = 32;

    private Ed25519() {}

    /**
     * Whether {@code signature} is {@code pub}'s over {@code message}. A key that is not 32 bytes, a signature that is
     * not 64, a point that does not decode or an S not below the group order is {@code false}, never an exception.
     */
    public static boolean verify(byte[] pub, byte[] message, byte[] signature) {
        if (pub == null || signature == null || pub.length != PUBLIC_KEY_LEN || signature.length != SIGNATURE_LEN) {
            return false;
        }
        try {
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(publicKey(pub));
            v.update(message);
            return v.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** The JCA public key of the raw 32 bytes {@code pub}. */
    public static PublicKey publicKey(byte[] pub) throws GeneralSecurityException {
        if (pub.length != PUBLIC_KEY_LEN) {
            throw new GeneralSecurityException("an Ed25519 public key is 32 bytes");
        }
        byte[] le = pub.clone();
        boolean xOdd = (le[31] & 0x80) != 0;
        le[31] &= 0x7f;
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, be));
        return KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
    }

    /** The raw 32 bytes of {@code key}. */
    public static byte[] raw(PublicKey key) {
        EdECPoint p = ((EdECPublicKey) key).getPoint();
        byte[] be = p.getY().toByteArray();
        byte[] le = new byte[PUBLIC_KEY_LEN];
        for (int i = 0; i < be.length && i < PUBLIC_KEY_LEN; i++) {
            le[i] = be[be.length - 1 - i];
        }
        if (p.isXOdd()) {
            le[31] |= (byte) 0x80;
        }
        return le;
    }

    /** The JCA private key of the 32-byte seed {@code seed}. */
    public static PrivateKey privateKey(byte[] seed) throws GeneralSecurityException {
        if (seed.length != SEED_LEN) {
            throw new GeneralSecurityException("an Ed25519 private key's seed is 32 bytes");
        }
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, Arrays.copyOf(seed, SEED_LEN)));
    }

    /** {@code key}'s signature over {@code message}. */
    public static byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(message);
        return s.sign();
    }
}
