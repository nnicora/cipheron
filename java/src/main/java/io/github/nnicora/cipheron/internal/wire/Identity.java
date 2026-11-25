package io.github.nnicora.cipheron.internal.wire;

import io.github.nnicora.cipheron.internal.crypto.Ed25519;
import io.github.nnicora.cipheron.internal.crypto.P256;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A profile's identity: its tenancy and the keys that never rotate — the HPKE key requests are sealed to and the
 * response key every answer is signed by — with their suite and algorithm, and the keys added to it later. A client
 * pins it by its {@link #fingerprint} ({@code wire/transport/auth.go}, {@code identity.go}).
 *
 * @param tenancy the tenancy's name: {@code shared}, {@code perTenantWrapped} or {@code perTenantDerived}
 * @param hpke the HPKE public key (DHKEM(P-256): an uncompressed point, 65 bytes)
 * @param suite the HPKE suite; all zero reads as {@link Suite#CLASSICAL}
 * @param response the response public key (Ed25519: 32 bytes)
 * @param responseAlgorithm the response key's algorithm; 0 reads as Ed25519 (1)
 * @param additional keys added to the identity after the profile was made
 */
public record Identity(String tenancy, byte[] hpke, Suite suite, byte[] response, long responseAlgorithm,
        List<Key> additional) {

    /** The signature algorithm number of Ed25519. */
    public static final long ALGORITHM_ED25519 = 1;

    /** The most keys an identity has besides its two. */
    public static final int MAX_ADDITIONAL_KEYS = 8;

    /** The longest identity public key. */
    public static final int MAX_KEY_LEN = 4096;

    /** The role of an additional HPKE key. */
    public static final long ROLE_HPKE = 1;

    /** The role of an additional response key. */
    public static final long ROLE_RESPONSE = 2;

    public Identity {
        additional = additional == null ? List.of() : List.copyOf(additional);
        suite = suite == null ? Suite.NONE : suite;
    }

    /**
     * An HPKE suite: its KEM, KDF and AEAD ids.
     *
     * @param kem the KEM id
     * @param kdf the KDF id
     * @param aead the AEAD id
     */
    public record Suite(int kem, int kdf, int aead) {
        /** The classical suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
        public static final Suite CLASSICAL = new Suite(0x0010, 0x0001, 0x0002);

        /** The zero suite: not written. */
        public static final Suite NONE = new Suite(0, 0, 0);

        /** This suite, the zero one read as {@link #CLASSICAL}. */
        public Suite orClassical() {
            return equals(NONE) ? CLASSICAL : this;
        }

        /** The suite's 6 bytes: the three ids, 2 bytes big-endian each. */
        public byte[] bytes() {
            return new byte[] {(byte) (kem >>> 8), (byte) kem, (byte) (kdf >>> 8), (byte) kdf, (byte) (aead >>> 8),
                    (byte) aead};
        }

        @Override
        public String toString() {
            return String.format("0x%04x/0x%04x/0x%04x", kem, kdf, aead);
        }
    }

    /**
     * A key added to an identity.
     *
     * @param role {@link #ROLE_HPKE} or {@link #ROLE_RESPONSE}
     * @param suite the suite of an HPKE key
     * @param algorithm the algorithm of a response key
     * @param publicKey the key
     */
    public record Key(long role, Suite suite, long algorithm, byte[] publicKey) {
        public Key {
            suite = suite == null ? Suite.NONE : suite;
        }

        /** The key's algorithm id: the suite's 6 bytes for an HPKE key, the algorithm's 4 for any other. */
        byte[] algorithmId() {
            return role == ROLE_HPKE ? suite.bytes() : Bytes.uint32(algorithm);
        }

        /** {@code lp(u32(role)) lp(algorithm id) lp(public key)}. */
        byte[] encode() {
            return Lp.create().addUint32(role).add(algorithmId()).add(publicKey).bytes();
        }
    }

    /** The identity's suite, zero read as classical. */
    public Suite effectiveSuite() {
        return suite.orClassical();
    }

    /** The response key's algorithm, 0 read as Ed25519. */
    public long effectiveResponseAlgorithm() {
        return responseAlgorithm == 0 ? ALGORITHM_ED25519 : responseAlgorithm;
    }

    /** Whether this is a classical identity: the classical suite, an Ed25519 response key, no additional key. */
    public boolean classical() {
        return effectiveSuite().equals(Suite.CLASSICAL) && effectiveResponseAlgorithm() == ALGORITHM_ED25519
                && additional.isEmpty();
    }

    /** The fingerprint derivation of this identity: 1 for a classical one, 2 for any other. */
    public int fingerprintVersion() {
        return classical() ? 1 : 2;
    }

    /**
     * The string a client pins the profile's identity by: {@code sha256:} and the hex SHA-256 of derivation 1
     * (classical) {@code lp("cipheron/v1|fingerprint") lp(profile) lp(tenancy) lp(HPKE) lp(response)}, or of
     * derivation 2 (any other identity), which names the suite, the algorithm and every additional key.
     */
    public String fingerprint(String profile) {
        byte[] t;
        if (classical()) {
            t = Lp.create().add(Labels.FINGERPRINT).add(profile).add(tenancy).add(hpke).add(response).bytes();
        } else {
            Lp l = Lp.create().add(Labels.FINGERPRINT2).add(profile).add(tenancy).add(effectiveSuite().bytes())
                    .add(hpke).addUint32(effectiveResponseAlgorithm()).add(response).addUint32(additional.size());
            for (byte[] e : sortedAdditional()) {
                l.raw(e);
            }
            t = l.bytes();
        }
        return Grammar.sha256String(Bytes.sha256(t));
    }

    /** Whether this identity is the one {@code fp} names, in constant time. */
    public boolean matches(String profile, String fp) {
        return Bytes.constantTimeEquals(fingerprint(profile), fp);
    }

    /** Whether this identity and {@code o} are the same (exactly when their fingerprints are). */
    public boolean sameAs(Identity o) {
        return Bytes.constantTimeEquals(fingerprint(""), o.fingerprint(""));
    }

    /** The additional keys' encodings, in canonical (bytewise ascending) order. */
    List<byte[]> sortedAdditional() {
        List<byte[]> out = new ArrayList<>();
        for (Key k : additional) {
            out.add(k.encode());
        }
        out.sort(Arrays::compareUnsigned);
        return out;
    }

    /** Whether {@code tenancy} is one of the three. */
    public static boolean validTenancy(String tenancy) {
        return "shared".equals(tenancy) || "perTenantWrapped".equals(tenancy) || "perTenantDerived".equals(tenancy);
    }

    /** Whether a profile of {@code tenancy} has signing keys of its own (shared, derived). */
    public static boolean hasSigningKeys(String tenancy) {
        return "shared".equals(tenancy) || "perTenantDerived".equals(tenancy);
    }

    /**
     * The tolerant check a client makes of an identity it received: the tenancy; for the classical suite a valid
     * P-256 point, for any other 1 to 4096 bytes; a 32-byte response key when it is Ed25519, 1 to 4096 bytes in
     * any case; the additional keys' form. A suite or algorithm the client does not implement is accepted here
     * ({@link #usable} says whether the client can use the identity).
     *
     * @return null when the identity passes, else why it does not
     */
    public String validateReceived() {
        if (!validTenancy(tenancy)) {
            return "the profile's tenancy \"" + tenancy + "\" is not one of shared, perTenantWrapped, perTenantDerived";
        }
        byte[] h = Bytes.orEmpty(hpke);
        if (effectiveSuite().equals(Suite.CLASSICAL)) {
            if (!P256.validPoint(h)) {
                return "the HPKE public key is not a P-256 point";
            }
        } else if (h.length == 0 || h.length > MAX_KEY_LEN) {
            return "an HPKE public key is 1 to " + MAX_KEY_LEN + " bytes";
        }
        byte[] r = Bytes.orEmpty(response);
        if (effectiveResponseAlgorithm() == ALGORITHM_ED25519 && r.length != Ed25519.PUBLIC_KEY_LEN) {
            return "an Ed25519 public key is 32 bytes";
        }
        if (r.length == 0 || r.length > MAX_KEY_LEN) {
            return "a response public key is 1 to " + MAX_KEY_LEN + " bytes";
        }
        return validateAdditional();
    }

    /** Whether the client can use this identity's keys: the classical suite and an Ed25519 response key. */
    public String usable() {
        if (!effectiveSuite().equals(Suite.CLASSICAL)) {
            return "the profile's HPKE suite " + effectiveSuite() + " is not one this library implements ("
                    + Suite.CLASSICAL + ")";
        }
        if (effectiveResponseAlgorithm() != ALGORITHM_ED25519) {
            return "the profile's response key algorithm " + effectiveResponseAlgorithm()
                    + " is not one this library implements (Ed25519)";
        }
        return null;
    }

    private String validateAdditional() {
        if (additional.size() > MAX_ADDITIONAL_KEYS) {
            return "an identity has at most " + MAX_ADDITIONAL_KEYS + " additional keys";
        }
        List<byte[]> enc = sortedAdditional();
        for (int i = 0; i < additional.size(); i++) {
            Key k = additional.get(i);
            if (k.role() == 0) {
                return "an additional identity key has no role";
            }
            byte[] p = Bytes.orEmpty(k.publicKey());
            if (p.length == 0 || p.length > MAX_KEY_LEN) {
                return "an identity public key is 1 to " + MAX_KEY_LEN + " bytes";
            }
            if (i > 0 && Arrays.equals(enc.get(i - 1), enc.get(i))) {
                return "an additional identity key is listed twice";
            }
        }
        return null;
    }
}
