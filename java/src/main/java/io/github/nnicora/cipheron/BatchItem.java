package io.github.nnicora.cipheron;

/**
 * One item of a batch: its data (a plaintext to encrypt, a ciphertext to decrypt or re-encrypt), and its associated
 * data; a re-encryption's item names its target associated data too (the same bytes).
 *
 * @param data the item's data
 * @param associatedData its associated data, or null
 * @param toAssociatedData a re-encryption's target associated data, or null
 */
public record BatchItem(byte[] data, byte[] associatedData, byte[] toAssociatedData) {
    /** An item of {@code data} with no associated data. */
    public static BatchItem of(byte[] data) {
        return new BatchItem(data, null, null);
    }

    /** An item of {@code data} bound to {@code aad} (a re-encryption keeps it: the target is the same bytes). */
    public static BatchItem of(byte[] data, byte[] aad) {
        return new BatchItem(data, aad, aad);
    }
}
