package io.github.nnicora.cipheron.internal.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HPKE (RFC 9180), base mode, single shot, with the KEM DHKEM(P-256, HKDF-SHA256) (0x0010) and the KDF HKDF-SHA256
 * (0x0001): the protocol's suite seals with AES-256-GCM (0x0002). Requests are sealed to the profile's HPKE key, and
 * a Decrypt answer to the client's one-time key. Only the primitives come from the JDK; the key schedule is RFC 9180's
 * section 5.1, held to its test vectors.
 */
public final class Hpke {
    /** The protocol's KEM id: DHKEM(P-256, HKDF-SHA256). */
    public static final int KEM_P256_HKDF_SHA256 = 0x0010;

    /** The protocol's KDF id: HKDF-SHA256. */
    public static final int KDF_HKDF_SHA256 = 0x0001;

    /** AES-128-GCM's AEAD id (RFC 9180's test vectors only). */
    public static final int AEAD_AES_128_GCM = 0x0001;

    /** The protocol's AEAD id: AES-256-GCM. */
    public static final int AEAD_AES_256_GCM = 0x0002;

    /** The length of a GCM tag: what sealing adds to a plaintext. */
    public static final int TAG_LEN = 16;

    private static final int NONCE_LEN = 12;
    private static final int SECRET_LEN = 32;
    private static final byte[] VERSION = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);

    private Hpke() {}

    /**
     * A sealed payload.
     *
     * @param enc the encapsulated key: the sender's ephemeral public key, 65 bytes
     * @param ciphertext the ciphertext and its tag
     */
    public record Sealed(byte[] enc, byte[] ciphertext) {}

    /** Seals {@code plaintext} to {@code recipient} (65 bytes) under {@code info}, AES-256-GCM, no AAD. */
    public static Sealed seal(byte[] recipient, byte[] info, byte[] plaintext) throws GeneralSecurityException {
        return seal(AEAD_AES_256_GCM, recipient, info, new byte[0], plaintext, P256.generate());
    }

    /** Opens a payload sealed to {@code recipient}, whose public key is {@code recipientPublic}. */
    public static byte[] open(PrivateKey recipient, byte[] recipientPublic, byte[] info, byte[] enc, byte[] ciphertext)
            throws GeneralSecurityException {
        return open(AEAD_AES_256_GCM, recipient, recipientPublic, info, new byte[0], enc, ciphertext);
    }

    /** Seals with the AEAD {@code aead} and the ephemeral key pair {@code ephemeral} (tests pin it). */
    static Sealed seal(int aead, byte[] recipient, byte[] info, byte[] aad, byte[] plaintext, KeyPair ephemeral)
            throws GeneralSecurityException {
        ECPublicKey pkR = P256.publicKey(recipient);
        byte[] enc = P256.encode(ephemeral.getPublic());
        byte[] dh = dh(ephemeral.getPrivate(), pkR);
        byte[] shared = extractAndExpand(dh, concat(enc, recipient));
        Context c = keySchedule(aead, shared, info);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(c.key, "AES"), new GCMParameterSpec(TAG_LEN * 8, c.nonce));
        gcm.updateAAD(aad);
        return new Sealed(enc, gcm.doFinal(plaintext));
    }

    static byte[] open(int aead, PrivateKey recipient, byte[] recipientPublic, byte[] info, byte[] aad, byte[] enc,
            byte[] ciphertext) throws GeneralSecurityException {
        if (enc == null || enc.length != P256.POINT_LEN) {
            throw new GeneralSecurityException("an encapsulated key is 65 bytes");
        }
        byte[] dh = dh(recipient, P256.publicKey(enc));
        byte[] shared = extractAndExpand(dh, concat(enc, recipientPublic));
        Context c = keySchedule(aead, shared, info);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(c.key, "AES"), new GCMParameterSpec(TAG_LEN * 8, c.nonce));
        gcm.updateAAD(aad);
        return gcm.doFinal(ciphertext);
    }

    /** The key schedule's output for sequence number 0: the AEAD key and nonce. */
    record Context(byte[] key, byte[] nonce) {}

    /** RFC 9180's KeySchedule in base mode (no PSK). */
    static Context keySchedule(int aead, byte[] sharedSecret, byte[] info) throws GeneralSecurityException {
        byte[] suite = suiteId(aead);
        byte[] pskIdHash = labeledExtract(suite, new byte[0], "psk_id_hash", new byte[0]);
        byte[] infoHash = labeledExtract(suite, new byte[0], "info_hash", info);
        byte[] context = concat(new byte[] {0}, pskIdHash, infoHash);
        byte[] secret = labeledExtract(suite, sharedSecret, "secret", new byte[0]);
        int keyLen = aead == AEAD_AES_128_GCM ? 16 : 32;
        return new Context(labeledExpand(suite, secret, "key", context, keyLen),
                labeledExpand(suite, secret, "base_nonce", context, NONCE_LEN));
    }

    /** DHKEM's ExtractAndExpand: the shared secret of the DH output, bound to {@code kemContext}. */
    static byte[] extractAndExpand(byte[] dh, byte[] kemContext) throws GeneralSecurityException {
        byte[] suite = concat("KEM".getBytes(StandardCharsets.US_ASCII), i2osp(KEM_P256_HKDF_SHA256, 2));
        byte[] prk = labeledExtract(suite, new byte[0], "eae_prk", dh);
        return labeledExpand(suite, prk, "shared_secret", kemContext, SECRET_LEN);
    }

    private static byte[] dh(PrivateKey sk, ECPublicKey pk) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    private static byte[] suiteId(int aead) {
        return concat("HPKE".getBytes(StandardCharsets.US_ASCII), i2osp(KEM_P256_HKDF_SHA256, 2),
                i2osp(KDF_HKDF_SHA256, 2), i2osp(aead, 2));
    }

    private static byte[] labeledExtract(byte[] suite, byte[] salt, String label, byte[] ikm)
            throws GeneralSecurityException {
        return Hkdf.extract(salt, concat(VERSION, suite, label.getBytes(StandardCharsets.US_ASCII), ikm));
    }

    private static byte[] labeledExpand(byte[] suite, byte[] prk, String label, byte[] info, int length)
            throws GeneralSecurityException {
        return Hkdf.expand(prk, concat(i2osp(length, 2), VERSION, suite, label.getBytes(StandardCharsets.US_ASCII),
                info), length);
    }

    private static byte[] i2osp(int v, int n) {
        byte[] b = new byte[n];
        for (int i = n - 1; i >= 0; i--) {
            b[i] = (byte) v;
            v >>>= 8;
        }
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }
}
