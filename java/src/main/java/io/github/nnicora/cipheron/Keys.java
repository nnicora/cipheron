package io.github.nnicora.cipheron;

import java.util.Arrays;
import java.util.List;

/**
 * A profile's keys as this client verified them: its identity (what its fingerprint covers), its signing keys and
 * the key-context digest of the cipheron that answered.
 *
 * @param profile the profile
 * @param tenancy its tenancy
 * @param fingerprint its identity's fingerprint: what a client pins
 * @param fingerprintVersion the fingerprint's derivation: 1 for a classical identity, 2 for any other
 * @param contextDigest the key-context digest
 * @param hpkePublicKey the HPKE key requests are sealed to
 * @param responsePublicKey the key every answer is signed by
 * @param signingKeys the signing keys, in ascending key id order
 * @param statement the profile's key statement (an offline party checks it against the pin), or null
 * @param statementSignature the statement's signature, or null
 */
public record Keys(String profile, Tenancy tenancy, String fingerprint, int fingerprintVersion, String contextDigest,
        byte[] hpkePublicKey, byte[] responsePublicKey, List<SigningKey> signingKeys, byte[] statement,
        byte[] statementSignature) {
    public Keys {
        signingKeys = List.copyOf(signingKeys);
    }

    /** The active signing key, the one Sign uses; null in a wrapped profile, which has none. */
    public SigningKey active() {
        for (SigningKey k : signingKeys) {
            if (k.state() == SigningKey.State.ACTIVE) {
                return k;
            }
        }
        return null;
    }

    /** The signing key {@code keyId} names, or null. */
    public SigningKey signingKey(byte[] keyId) {
        for (SigningKey k : signingKeys) {
            if (Arrays.equals(k.keyId(), keyId)) {
                return k;
            }
        }
        return null;
    }
}
