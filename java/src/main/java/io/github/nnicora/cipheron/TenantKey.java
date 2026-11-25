package io.github.nnicora.cipheron;

/**
 * A wrapped profile's tenant key: the blob the application stores and passes with every call of the tenant, and
 * what identifies it.
 *
 * @param blob the tenant key blob
 * @param keyId the tenant key's id, 16 bytes
 * @param signingPublicKey its signing public key (Ed25519)
 * @param fingerprint what a client pins it by ({@code sha256:…})
 */
public record TenantKey(byte[] blob, byte[] keyId, byte[] signingPublicKey, String fingerprint) {
    public TenantKey {
        blob = blob.clone();
        keyId = keyId.clone();
        signingPublicKey = signingPublicKey.clone();
    }

    @Override
    public byte[] blob() {
        return blob.clone();
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }

    @Override
    public byte[] signingPublicKey() {
        return signingPublicKey.clone();
    }
}
