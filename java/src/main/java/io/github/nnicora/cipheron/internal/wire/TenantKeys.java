package io.github.nnicora.cipheron.internal.wire;

import io.github.nnicora.cipheron.internal.crypto.Ed25519;

import java.util.Arrays;

/**
 * Tenant key blobs ({@code CPT1}) of a wrapped profile: a tenant's key, wrapped by cipheron, held by the application.
 * A client reads the header (which is NOT authenticated client-side: it is the blob's GCM additional data, which only
 * cipheron checks) and checks it names the call's profile and tenant ({@code wire/transport/tenant.go},
 * {@code catalog.go}).
 *
 * <pre>
 * "CPT1" | 0x01 | key id (16) | lp(profile) | lp(tenant) | signing public key (32) | len (1) | wrapping version id
 *        | created (8, Unix seconds, > 0) | salt (32) | nonce (12) | sealed private keys (96) | tag (16)
 * </pre>
 */
public final class TenantKeys {
    public static final byte[] MAGIC = {'C', 'P', 'T', '1'};
    public static final int VERSION = 1;
    public static final int KEY_ID_LEN = 16;
    public static final int SALT_LEN = 32;

    /** The sealed tail: nonce (12), the storage key and the signing private key (32 + 64), tag (16). */
    public static final int SEALED_LEN = 12 + 32 + 64 + 16;

    /** The largest blob: the longest profile, tenant id and wrapping version id. */
    public static final int MAX_LEN = MAGIC.length + 1 + KEY_ID_LEN + 4 + Grammar.MAX_PROFILE_LEN + 4
            + Grammar.MAX_TENANT_LEN + Ed25519.PUBLIC_KEY_LEN + 1 + 8 + Grammar.MAX_MASTER_VERSION_ID_LEN + SALT_LEN
            + SEALED_LEN;

    private TenantKeys() {}

    /**
     * A blob's header.
     *
     * @param keyId the tenant key's id
     * @param profile the profile it is of
     * @param tenant the tenant it is of
     * @param signingPublicKey the tenant key's signing public key
     * @param wrappingVersion the master version it is wrapped under
     * @param created when it was made, Unix seconds
     */
    public record Header(byte[] keyId, String profile, String tenant, byte[] signingPublicKey,
            String wrappingVersion, long created) {
        /** The fingerprint a client pins this tenant key by. */
        public String fingerprint() {
            return TenantKeys.fingerprint(profile, tenant, keyId, signingPublicKey);
        }
    }

    /** A refusal: not a tenant key blob of this tenant in this profile. */
    public static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;

        Refused(String why) {
            super("cipheron: not a tenant key of this tenant in this profile" + (why.isEmpty() ? "" : ": " + why));
        }
    }

    /** Reads {@code blob}'s header: the magic, version 1, the fields of their rules, the salt and the exact tail. */
    public static Header parse(byte[] blob) throws Refused {
        int m = MAGIC.length;
        if (blob.length <= m || !Arrays.equals(blob, 0, m, MAGIC, 0, m) || (blob[m] & 0xff) != VERSION
                || blob.length > MAX_LEN) {
            throw new Refused("");
        }
        int off = m + 1;
        if (blob.length - off < KEY_ID_LEN) {
            throw new Refused("");
        }
        byte[] keyId = Arrays.copyOfRange(blob, off, off + KEY_ID_LEN);
        off += KEY_ID_LEN;
        byte[] profile = lp(blob, off, Grammar.MAX_PROFILE_LEN);
        if (profile == null || !Grammar.validProfile(Bytes.string(profile))) {
            throw new Refused("");
        }
        off += 4 + profile.length;
        byte[] tenant = lp(blob, off, Grammar.MAX_TENANT_LEN);
        if (tenant == null || !Grammar.validTenant(tenant)) {
            throw new Refused("");
        }
        off += 4 + tenant.length;
        if (blob.length - off < Ed25519.PUBLIC_KEY_LEN) {
            throw new Refused("");
        }
        byte[] pub = Arrays.copyOfRange(blob, off, off + Ed25519.PUBLIC_KEY_LEN);
        off += Ed25519.PUBLIC_KEY_LEN;
        if (blob.length - off < 1) {
            throw new Refused("");
        }
        int n = blob[off] & 0xff;
        if (n == 0 || n > Grammar.MAX_MASTER_VERSION_ID_LEN || n > blob.length - off - 1) {
            throw new Refused("");
        }
        byte[] wv = Arrays.copyOfRange(blob, off + 1, off + 1 + n);
        if (!Grammar.validMasterVersionId(wv)) {
            throw new Refused("");
        }
        off += 1 + n;
        if (blob.length - off < 8) {
            throw new Refused("");
        }
        long created = Bytes.int64(blob, off);
        if (created <= 0) {
            throw new Refused("");
        }
        off += 8;
        int header = off + SALT_LEN;
        if (header > blob.length || blob.length - header != SEALED_LEN) {
            throw new Refused("");
        }
        return new Header(keyId, Bytes.string(profile), Bytes.string(tenant), pub, Bytes.string(wv), created);
    }

    /** Reads {@code blob}'s header and checks it is {@code tenant}'s key in {@code profile}. */
    public static Header check(byte[] blob, String profile, String tenant) throws Refused {
        Header h = parse(blob);
        if (!h.profile().equals(profile) || !h.tenant().equals(tenant)) {
            throw new Refused("it is tenant \"" + h.tenant() + "\"'s key in profile \"" + h.profile() + "\"");
        }
        return h;
    }

    /**
     * What a client pins a tenant key by: {@code sha256:} and the hex SHA-256 of
     * {@code lp("cipheron/v1|tenant-fingerprint") lp(profile) lp(tenant) lp(key id) lp(signing public key)}.
     */
    public static String fingerprint(String profile, String tenant, byte[] keyId, byte[] signingPublicKey) {
        return Grammar.sha256String(Bytes.sha256(Lp.create().add(Labels.TENANT_FINGERPRINT).add(profile).add(tenant)
                .add(keyId).add(signingPublicKey).bytes()));
    }

    /**
     * What a derived profile's key signs for a tenant: {@code lp("cipheron/v1|tenant-signature") lp(profile)
     * lp(tenant) lp(data)}.
     */
    public static byte[] signedMessage(String profile, String tenant, byte[] data) {
        return Lp.create().add(Labels.TENANT_SIGNATURE).add(profile).add(tenant).add(data).bytes();
    }

    private static byte[] lp(byte[] b, int off, int max) {
        if (b.length - off < 4) {
            return null;
        }
        long n = Bytes.uint32(b, off);
        if (n > max || n > b.length - off - 4) {
            return null;
        }
        return Arrays.copyOfRange(b, off + 4, off + 4 + (int) n);
    }
}
