package io.github.nnicora.cipheron.internal.wire;

import java.security.MessageDigest;

/**
 * Payload digests: the SHA-256 of {@code lp("cipheron/v1|digest")} and the payload's fields, each length-prefixed.
 * A request's and an answer's transcripts commit to their payloads through these ({@code wire/transport/auth.go},
 * {@code Digest}'s table). Empty fields are digested all the same, as zero-length fields.
 */
public final class Digests {
    private Digests() {}

    /** The digest of {@code fields}. */
    public static byte[] digest(byte[]... fields) {
        MessageDigest h = Bytes.sha256();
        write(h, Bytes.utf8(Labels.DIGEST));
        for (byte[] f : fields) {
            write(h, Bytes.orEmpty(f));
        }
        return h.digest();
    }

    private static void write(MessageDigest h, byte[] f) {
        h.update(Bytes.uint32(f.length));
        h.update(f);
    }

    /** An Encrypt request's (or EncryptBatch item's) digest: its associated data is a fifth field only when given. */
    public static byte[] encrypt(byte[] enc, byte[] sealedPlaintext, String tenant, byte[] tenantKey, byte[] aad) {
        if (aad == null || aad.length == 0) {
            return digest(enc, sealedPlaintext, Bytes.utf8(tenant), tenantKey);
        }
        return digest(enc, sealedPlaintext, Bytes.utf8(tenant), tenantKey, aad);
    }

    /** A Decrypt request's (or DecryptBatch item's) digest, as {@link #encrypt}. */
    public static byte[] decrypt(byte[] recipientPublicKey, byte[] ciphertext, String tenant, byte[] tenantKey,
            byte[] aad) {
        if (aad == null || aad.length == 0) {
            return digest(recipientPublicKey, ciphertext, Bytes.utf8(tenant), tenantKey);
        }
        return digest(recipientPublicKey, ciphertext, Bytes.utf8(tenant), tenantKey, aad);
    }

    /** A Sign request's digest. */
    public static byte[] sign(byte[] enc, byte[] sealedData, String tenant, byte[] tenantKey) {
        return digest(enc, sealedData, Bytes.utf8(tenant), tenantKey);
    }

    /**
     * A ReEncrypt request's (or ReEncryptBatch item's) digest: the four fields of the table, and ALL FOUR extension
     * fields (associated data, target associated data, target profile, target tenant) when any is non-empty.
     */
    public static byte[] reEncrypt(byte[] ciphertext, String tenant, byte[] tenantKey, byte[] toTenantKey, byte[] aad,
            byte[] toAad, String toProfile, String toTenant) {
        boolean ext = len(aad) > 0 || len(toAad) > 0 || !toProfile.isEmpty() || !toTenant.isEmpty();
        if (!ext) {
            return digest(ciphertext, Bytes.utf8(tenant), tenantKey, toTenantKey);
        }
        return digest(ciphertext, Bytes.utf8(tenant), tenantKey, toTenantKey, aad, toAad, Bytes.utf8(toProfile),
                Bytes.utf8(toTenant));
    }

    /** A CreateTenantKey request's digest: the tenant and an empty tenant key. */
    public static byte[] provision(String tenant) {
        return digest(Bytes.utf8(tenant), Bytes.EMPTY);
    }

    /** A RewrapTenantKey request's digest: the tenant and its blob. */
    public static byte[] rewrapTenantKey(String tenant, byte[] tenantKey) {
        return digest(Bytes.utf8(tenant), tenantKey);
    }

    /** The response digest of an Encrypt or ReEncrypt answer. */
    public static byte[] ciphertextResponse(byte[] ciphertext) {
        return digest(ciphertext);
    }

    /** The response digest of a Sign answer. */
    public static byte[] signResponse(byte[] signature, byte[] keyId) {
        return digest(signature, keyId);
    }

    /** The response digest of a Decrypt answer. */
    public static byte[] decryptResponse(byte[] recipientPublicKey, byte[] enc, byte[] sealedPlaintext) {
        return digest(recipientPublicKey, enc, sealedPlaintext);
    }

    /** The response digest of a CreateTenantKey or RewrapTenantKey answer. */
    public static byte[] tenantKeyResponse(byte[] tenantKey, byte[] signingPublicKey, String fingerprint) {
        return digest(tenantKey, signingPublicKey, Bytes.utf8(fingerprint));
    }

    /** A batch's digest: the count (4 bytes) and each item's digest, in order. */
    public static byte[] batch(byte[][] itemDigests) {
        byte[][] fields = new byte[itemDigests.length + 1][];
        fields[0] = Bytes.uint32(itemDigests.length);
        System.arraycopy(itemDigests, 0, fields, 1, itemDigests.length);
        return digest(fields);
    }

    /** A batch answer's result item digest: {@code 0x00} and the single answer's response-digest fields. */
    public static byte[] batchResult(byte[]... fields) {
        byte[][] all = new byte[fields.length + 1][];
        all[0] = new byte[] {0};
        System.arraycopy(fields, 0, all, 1, fields.length);
        return digest(all);
    }

    /** A batch answer's error item digest: {@code 0x01}, the code (4 bytes), the reason and the message. */
    public static byte[] batchError(long code, String reason, String message) {
        return digest(new byte[] {1}, Bytes.uint32(code), Bytes.utf8(reason), Bytes.utf8(message));
    }

    private static int len(byte[] b) {
        return b == null ? 0 : b.length;
    }
}
