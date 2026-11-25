package io.github.nnicora.cipheron.internal.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.nnicora.cipheron.internal.wire.Bytes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.ECPrivateKeySpec;

import org.junit.jupiter.api.Test;

/** HPKE and HKDF held to their RFCs' test vectors, and the protocol's suite to a round trip. */
class HpkeTest {
    // RFC 9180, appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
    private static final byte[] INFO = Bytes.unhex("4f6465206f6e2061204772656369616e2055726e");
    private static final byte[] PK_EM = Bytes.unhex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32"
            + "5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    private static final byte[] SK_EM = Bytes.unhex(
            "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
    private static final byte[] PK_RM = Bytes.unhex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70"
            + "6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    private static final byte[] SK_RM = Bytes.unhex(
            "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    private static final byte[] SHARED_SECRET = Bytes.unhex(
            "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");
    private static final byte[] KEY = Bytes.unhex("868c066ef58aae6dc589b6cfdd18f97e");
    private static final byte[] BASE_NONCE = Bytes.unhex("4e0bc5018beba4bf004cca59");
    private static final byte[] PT = Bytes.unhex("4265617574792069732074727574682c20747275746820626561757479");
    private static final byte[] AAD = Bytes.unhex("436f756e742d30");
    private static final byte[] CT = Bytes.unhex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f"
            + "9076ac232e3ab2523f39513434");

    private static PrivateKey privateKey(byte[] scalar) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC")
                .generatePrivate(new ECPrivateKeySpec(new BigInteger(1, scalar), P256.params()));
    }

    @Test
    void theRfcVectorsKeyScheduleIsReproduced() throws GeneralSecurityException {
        byte[] dh = javaxDh(privateKey(SK_EM), PK_RM);
        byte[] shared = Hpke.extractAndExpand(dh, concat(PK_EM, PK_RM));
        assertArrayEquals(SHARED_SECRET, shared);
        Hpke.Context c = Hpke.keySchedule(Hpke.AEAD_AES_128_GCM, shared, INFO);
        assertArrayEquals(KEY, c.key());
        assertArrayEquals(BASE_NONCE, c.nonce());
    }

    @Test
    void theRfcVectorsFirstEncryptionSealsAndOpens() throws GeneralSecurityException {
        KeyPair ephemeral = new KeyPair(P256.publicKey(PK_EM), privateKey(SK_EM));
        Hpke.Sealed s = Hpke.seal(Hpke.AEAD_AES_128_GCM, PK_RM, INFO, AAD, PT, ephemeral);
        assertArrayEquals(PK_EM, s.enc());
        assertArrayEquals(CT, s.ciphertext());
        assertArrayEquals(PT, Hpke.open(Hpke.AEAD_AES_128_GCM, privateKey(SK_RM), PK_RM, INFO, AAD, PK_EM, CT));
    }

    @Test
    void theProtocolsSuiteRoundTripsAndRefusesTampering() throws GeneralSecurityException {
        KeyPair r = P256.generate();
        byte[] pub = P256.encode(r.getPublic());
        byte[] info = "cipheron/v1|request|p|encrypt".getBytes(StandardCharsets.US_ASCII);
        Hpke.Sealed s = Hpke.seal(pub, info, PT);
        assertArrayEquals(PT, Hpke.open(r.getPrivate(), pub, info, s.enc(), s.ciphertext()));

        byte[] flipped = s.ciphertext().clone();
        flipped[0] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> Hpke.open(r.getPrivate(), pub, info, s.enc(), flipped));
        byte[] otherInfo = "cipheron/v1|request|p|sign".getBytes(StandardCharsets.US_ASCII);
        assertThrows(GeneralSecurityException.class,
                () -> Hpke.open(r.getPrivate(), pub, otherInfo, s.enc(), s.ciphertext()));
    }

    @Test
    void hkdfMatchesRfc5869TestCase1() throws GeneralSecurityException {
        byte[] ikm = Bytes.unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Bytes.unhex("000102030405060708090a0b0c");
        byte[] info = Bytes.unhex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.extract(salt, ikm);
        assertArrayEquals(Bytes.unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
        assertArrayEquals(Bytes.unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"), Hkdf.expand(prk, info, 42));
    }

    @Test
    void anInvalidPointIsRefused() {
        byte[] notOnCurve = PK_RM.clone();
        notOnCurve[64] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> P256.publicKey(notOnCurve));
    }

    private static byte[] javaxDh(PrivateKey sk, byte[] pk) throws GeneralSecurityException {
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
        ka.init(sk);
        ka.doPhase(P256.publicKey(pk), true);
        return ka.generateSecret();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
