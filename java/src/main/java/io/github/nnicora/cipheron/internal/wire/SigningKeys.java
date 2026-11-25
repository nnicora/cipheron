package io.github.nnicora.cipheron.internal.wire;

import io.github.nnicora.cipheron.internal.crypto.Ed25519;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A profile's signing keys: the keys its Sign answers are made with, listed by PublicKey and authenticated by the
 * response key ({@code wire/transport/keys.go}). A key's state is a name in the API and a number on the wire.
 */
public final class SigningKeys {
    /** The length of a signing key's id. */
    public static final int KEY_ID_LEN = 16;

    /** The most signing keys a profile lists. */
    public static final int MAX_SIGNING_KEYS = 256;

    public static final String ACTIVE = "active";
    public static final String VERIFY_ONLY = "verifyOnly";
    public static final String REVOKED = "revoked";

    private SigningKeys() {}

    /**
     * One signing key.
     *
     * @param keyId its id ({@link #keyIdOf})
     * @param state {@link #ACTIVE}, {@link #VERIFY_ONLY} or {@link #REVOKED}; anything else is not a state
     * @param publicKey its public key
     * @param algorithm its algorithm; 0 reads as Ed25519
     */
    public record Key(byte[] keyId, String state, byte[] publicKey, long algorithm) {
        /** The key's algorithm, 0 read as Ed25519. */
        public long effectiveAlgorithm() {
            return algorithm == 0 ? Identity.ALGORITHM_ED25519 : algorithm;
        }

        /** Whether the key verifies: active or verify-only, of an algorithm this library implements. */
        public boolean usable() {
            return (ACTIVE.equals(state) || VERIFY_ONLY.equals(state))
                    && effectiveAlgorithm() == Identity.ALGORITHM_ED25519;
        }
    }

    /** Whether {@code state} is one of the three. */
    public static boolean validState(String state) {
        return ACTIVE.equals(state) || VERIFY_ONLY.equals(state) || REVOKED.equals(state);
    }

    /** The wire number of {@code state}: 1, 2 or 3; 0 for a name that is not a state. */
    public static long code(String state) {
        if (ACTIVE.equals(state)) {
            return 1;
        }
        if (VERIFY_ONLY.equals(state)) {
            return 2;
        }
        if (REVOKED.equals(state)) {
            return 3;
        }
        return 0;
    }

    /** The state the wire number {@code code} names; null for a number that is not one. */
    public static String stateOf(long code) {
        if (code == 1) {
            return ACTIVE;
        }
        if (code == 2) {
            return VERIFY_ONLY;
        }
        if (code == 3) {
            return REVOKED;
        }
        return null;
    }

    /**
     * A signing key's id: the first 16 bytes of the SHA-256 of {@code lp("cipheron/v1|signing-key-id") lp(pub)} for
     * Ed25519 (algorithm 0 or 1), of {@code lp("cipheron/v1|signing-key-id2") lp(u32(alg)) lp(pub)} for any other.
     */
    public static byte[] keyIdOf(long algorithm, byte[] pub) {
        byte[] t;
        if (algorithm == 0 || algorithm == Identity.ALGORITHM_ED25519) {
            t = Lp.create().add(Labels.SIGNING_KEY_ID).add(pub).bytes();
        } else {
            t = Lp.create().add(Labels.SIGNING_KEY_ID2).addUint32(algorithm).add(pub).bytes();
        }
        return Arrays.copyOf(Bytes.sha256(t), KEY_ID_LEN);
    }

    /**
     * The tolerant check of a received list: none in a wrapped profile; 1 to 256 otherwise, each of a valid state,
     * an Ed25519 key of 32 bytes (any key 1 to 4096), its id its key's, none listed twice, exactly one active.
     *
     * @return null when the list passes, else why it does not
     */
    public static String validateReceived(String tenancy, List<Key> keys) {
        if (!Identity.hasSigningKeys(tenancy)) {
            return keys.isEmpty() ? null : "a " + tenancy + " profile has no signing keys of its own";
        }
        if (keys.isEmpty() || keys.size() > MAX_SIGNING_KEYS) {
            return "a " + tenancy + " profile lists 1 to " + MAX_SIGNING_KEYS + " signing keys, not " + keys.size();
        }
        int active = 0;
        Set<String> seen = new HashSet<>();
        for (Key k : keys) {
            byte[] pub = Bytes.orEmpty(k.publicKey());
            if (!validState(k.state())) {
                return "a signing key's state \"" + k.state() + "\" is not active, verifyOnly or revoked";
            }
            if (k.effectiveAlgorithm() == Identity.ALGORITHM_ED25519 && pub.length != Ed25519.PUBLIC_KEY_LEN) {
                return "an Ed25519 public key is 32 bytes";
            }
            if (pub.length == 0 || pub.length > Identity.MAX_KEY_LEN) {
                return "a signing public key is 1 to " + Identity.MAX_KEY_LEN + " bytes";
            }
            if (!Arrays.equals(Bytes.orEmpty(k.keyId()), keyIdOf(k.effectiveAlgorithm(), pub))) {
                return "a signing key's id is not its public key's";
            }
            if (!seen.add(Bytes.hex(k.keyId()))) {
                return "signing key " + Bytes.hex(k.keyId()) + " is listed twice";
            }
            if (ACTIVE.equals(k.state())) {
                active++;
            }
        }
        return active == 1 ? null : "a profile has exactly one active signing key, not " + active;
    }
}
