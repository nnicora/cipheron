package io.github.nnicora.cipheron;

/**
 * One of a profile's signing keys, as its authenticated list names it.
 *
 * @param keyId the key's id, 16 bytes
 * @param state whether it signs, only verifies, or verifies nothing
 * @param publicKey its public key (Ed25519: 32 bytes)
 * @param algorithm its algorithm's number (1: Ed25519)
 */
public record SigningKey(byte[] keyId, State state, byte[] publicKey, long algorithm) {
    /** A signing key's state. */
    public enum State {
        /** It signs, and verifies. */
        ACTIVE("active"),
        /** It verifies what it signed, and signs nothing new. */
        VERIFY_ONLY("verifyOnly"),
        /** It verifies nothing. */
        REVOKED("revoked");

        private final String wire;

        State(String wire) {
            this.wire = wire;
        }

        /** The state's name in the protocol. */
        public String wire() {
            return wire;
        }

        /** The state the protocol name {@code s} names. */
        public static State of(String s) {
            for (State v : values()) {
                if (v.wire.equals(s)) {
                    return v;
                }
            }
            throw new IllegalArgumentException("not a signing key state: " + s);
        }
    }

    public SigningKey {
        keyId = keyId.clone();
        publicKey = publicKey.clone();
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /** Whether the key verifies: active or verify-only. */
    public boolean usable() {
        return state != State.REVOKED;
    }
}
