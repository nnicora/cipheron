package io.github.nnicora.cipheron;

/**
 * A signature cipheron made, and the id of the key that made it: store both, as {@code verify} needs both.
 *
 * @param bytes the Ed25519 signature, 64 bytes
 * @param keyId the signing key's id, 16 bytes
 */
public record Signature(byte[] bytes, byte[] keyId) {
    public Signature {
        bytes = bytes.clone();
        keyId = keyId.clone();
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }
}
