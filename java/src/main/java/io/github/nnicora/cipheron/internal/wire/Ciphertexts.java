package io.github.nnicora.cipheron.internal.wire;

import java.util.Arrays;

/**
 * Ciphertext headers ({@code CPH1}): which key a ciphertext was made under, read without the key
 * ({@code wire/transport/ciphertext.go}, {@code catalog.go}). This release reads formats 3 and 6 (a tenant key:
 * a wrapped profile) and 4 and 5 (a master version: a shared or derived profile); 5 and 6 carry associated data.
 *
 * <pre>
 * 3, 6: "CPH1" | format | tenant key id (16) | salt (32) | nonce (12) | ciphertext | tag (16)
 * 4, 5: "CPH1" | format | len (1) | master version id (len) | salt (32) | nonce (12) | ciphertext | tag (16)
 * </pre>
 */
public final class Ciphertexts {
    public static final byte[] MAGIC = {'C', 'P', 'H', '1'};

    public static final int FORMAT_TENANT_KEY = 3;
    public static final int FORMAT_VERSIONED = 4;
    public static final int FORMAT_VERSIONED_AAD = 5;
    public static final int FORMAT_TENANT_KEY_AAD = 6;

    public static final int TENANT_KEY_ID_LEN = 16;
    public static final int SALT_LEN = 32;
    public static final int NONCE_LEN = 12;
    public static final int TAG_LEN = 16;

    /** The longest caller associated data. */
    public static final int MAX_ASSOCIATED_DATA_LEN = 64 << 10;

    private Ciphertexts() {}

    /**
     * Which key a ciphertext names.
     *
     * @param format its format byte
     * @param associatedData whether the format carries associated data (5, 6)
     * @param masterVersion the master version id (formats 4, 5), else null
     * @param tenantKeyId the tenant key's id (formats 3, 6), else null
     * @param headerLen the header's length, salt included
     */
    public record KeyId(int format, boolean associatedData, String masterVersion, byte[] tenantKeyId,
            int headerLen) {
        /** Whether the ciphertext names a master version (formats 4, 5). */
        public boolean versioned() {
            return masterVersion != null;
        }

        /** Whether the ciphertext names a tenant key (formats 3, 6). */
        public boolean tenantKey() {
            return tenantKeyId != null;
        }

        /** The bytes the format adds to a plaintext: the header, the nonce and the tag. */
        public int overhead() {
            return headerLen + NONCE_LEN + TAG_LEN;
        }

        /** {@code tenant-key:<hex>} for a tenant key, the master version id for a versioned ciphertext. */
        @Override
        public String toString() {
            return tenantKeyId != null ? "tenant-key:" + Bytes.hex(tenantKeyId) : masterVersion;
        }
    }

    /** A refusal: the bytes are not a ciphertext of a format this release reads. */
    public static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;
        private final boolean unknownFormat;

        Refused(String why, boolean unknownFormat) {
            super(why);
            this.unknownFormat = unknownFormat;
        }

        /** Whether the bytes are a ciphertext's (the magic) of a format this release does not read. */
        public boolean unknownFormat() {
            return unknownFormat;
        }
    }

    /** Whether {@code format} is one this release reads. */
    public static boolean readable(int format) {
        return format == FORMAT_TENANT_KEY || format == FORMAT_VERSIONED || format == FORMAT_VERSIONED_AAD
                || format == FORMAT_TENANT_KEY_AAD;
    }

    /**
     * Reads which key {@code ct} names: the magic, a format this release reads, the format's key field, the salt, and
     * room for at least a nonce and a tag (an empty plaintext's ciphertext). Nothing is decrypted.
     */
    public static KeyId parse(byte[] ct) throws Refused {
        int m = MAGIC.length;
        if (ct.length < m || !Arrays.equals(ct, 0, m, MAGIC, 0, m) || ct.length == m) {
            throw new Refused("cipheron: not a cipheron ciphertext", false);
        }
        int format = ct[m] & 0xff;
        if (!readable(format)) {
            throw new Refused("cipheron: not a cipheron ciphertext: a format this protocol does not have (format "
                    + format + ")", true);
        }
        int off = m + 1;
        String version = null;
        byte[] tenantKeyId = null;
        if (format == FORMAT_TENANT_KEY || format == FORMAT_TENANT_KEY_AAD) {
            if (ct.length - off < TENANT_KEY_ID_LEN) {
                throw refused();
            }
            tenantKeyId = Arrays.copyOfRange(ct, off, off + TENANT_KEY_ID_LEN);
            off += TENANT_KEY_ID_LEN;
        } else {
            if (ct.length - off < 1) {
                throw refused();
            }
            int n = ct[off] & 0xff;
            if (n == 0 || n > Grammar.MAX_MASTER_VERSION_ID_LEN || n > ct.length - off - 1) {
                throw refused();
            }
            byte[] id = Arrays.copyOfRange(ct, off + 1, off + 1 + n);
            if (!Grammar.validMasterVersionId(id)) {
                throw refused();
            }
            version = Bytes.string(id);
            off += 1 + n;
        }
        int header = off + SALT_LEN;
        if (header > ct.length || ct.length - header < NONCE_LEN + TAG_LEN) {
            throw refused();
        }
        boolean aad = format == FORMAT_VERSIONED_AAD || format == FORMAT_TENANT_KEY_AAD;
        return new KeyId(format, aad, version, tenantKeyId, header);
    }

    private static Refused refused() {
        return new Refused("cipheron: not a cipheron ciphertext", false);
    }

    /**
     * The associated-data rule of {@code id}: at most 64 KiB; formats 5 and 6 need some, 3 and 4 take none.
     *
     * @return null when {@code aad} fits, else why it does not
     */
    public static String checkAssociatedData(KeyId id, byte[] aad) {
        int n = aad == null ? 0 : aad.length;
        if (n > MAX_ASSOCIATED_DATA_LEN) {
            return "associated data is at most " + MAX_ASSOCIATED_DATA_LEN + " bytes, not " + n;
        }
        if (id.associatedData() && n == 0) {
            return "the ciphertext was made with associated data (format " + id.format() + ") and none is given";
        }
        if (!id.associatedData() && n > 0) {
            return "the ciphertext was made without associated data (format " + id.format() + ") and some is given";
        }
        return null;
    }

    /**
     * A re-encryption keeps the stored ciphertext's associated data: {@code toAad} is the same bytes, or both are
     * empty.
     *
     * @return null when they agree, else why not
     */
    public static String checkReEncryptAssociatedData(byte[] aad, byte[] toAad) {
        byte[] a = Bytes.orEmpty(aad);
        byte[] t = Bytes.orEmpty(toAad);
        if (a.length > 0 && t.length == 0) {
            return "associated data for the stored ciphertext and none for the new one";
        }
        if (!Arrays.equals(a, t)) {
            return "a re-encryption keeps the stored ciphertext's associated data, and to_associated_data differs "
                    + "from it";
        }
        return null;
    }

    /** The overhead of a ciphertext of {@code format} under master version {@code versionId}. */
    public static int versionedOverhead(String versionId) {
        return MAGIC.length + 1 + 1 + Bytes.utf8(versionId).length + SALT_LEN + NONCE_LEN + TAG_LEN;
    }

    /** The overhead of a ciphertext of a tenant-key format. */
    public static int tenantKeyOverhead() {
        return MAGIC.length + 1 + TENANT_KEY_ID_LEN + SALT_LEN + NONCE_LEN + TAG_LEN;
    }
}
