package io.github.nnicora.cipheron;

/**
 * Which key a ciphertext was made under, read from its header without decrypting it ({@link Cipheron#keyId}).
 *
 * @param format the format byte: 3 or 6 (a tenant key), 4 or 5 (a master version)
 * @param masterVersion the master key version id (formats 4, 5), else null
 * @param tenantKeyId the tenant key's id (formats 3, 6), else null
 * @param associatedData whether the ciphertext was made with associated data (formats 5, 6)
 */
public record CiphertextKey(int format, String masterVersion, byte[] tenantKeyId, boolean associatedData) {
    /** {@code tenant-key:<hex>} for a tenant key, the master version id for any other. */
    @Override
    public String toString() {
        return tenantKeyId != null
                ? "tenant-key:" + java.util.HexFormat.of().formatHex(tenantKeyId)
                : masterVersion;
    }
}
