package io.github.nnicora.cipheron;

import io.github.nnicora.cipheron.internal.client.Core;

import java.util.List;

/**
 * A tenant of a perTenant profile: its calls name the tenant, and carry its key blob in a wrapped profile. Made by
 * {@link CipheronClient#tenant}; a handle that cannot be used (a tenant id that is not one, a blob of another tenant)
 * answers its refusal on every call.
 */
public final class Tenant {
    private final CipheronClient client;
    private final Core.TenantRef ref;

    Tenant(CipheronClient client, Core.TenantRef ref) {
        this.client = client;
        this.ref = ref;
    }

    /** The profile. */
    public String profile() {
        return ref.profile();
    }

    /** The tenant id. */
    public String name() {
        return ref.tenant();
    }

    /** The fingerprint of the tenant's key (a wrapped profile's tenant only). */
    public String fingerprint() {
        if (ref.refusal() != null) {
            throw ref.refusal();
        }
        if (ref.header() == null) {
            throw new TenancyException("cipheron: the call is not one of the profile's tenancy: tenant \""
                    + ref.tenant() + "\" of profile \"" + ref.profile() + "\" has no key blob (a derived profile's "
                    + "tenants have none)");
        }
        return ref.header().fingerprint();
    }

    /** Encrypts for the tenant: format 4 or 5 in a derived profile, 3 or 6 in a wrapped one. */
    public byte[] encrypt(byte[] plaintext, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.run(o, call -> client.core().tenantEncrypt(call, ref, plaintext, o.aad));
    }

    /** Decrypts the tenant's ciphertext. */
    public byte[] decrypt(byte[] ciphertext, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.run(o, call -> client.core().tenantDecrypt(call, ref, ciphertext, o.aad));
    }

    /**
     * Re-encrypts the tenant's ciphertext: under the blob {@code to} in a wrapped profile (the same tenant's key,
     * rewrapped or not), with {@code to} null in a derived one.
     */
    public byte[] reEncrypt(byte[] ciphertext, byte[] to, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.run(o, call -> client.core().tenantReEncrypt(call, ref, ciphertext, to, o.aad, o.toAad));
    }

    /** Signs for the tenant: with its key in a wrapped profile, with the profile's key bound to the tenant in a derived one. */
    public Signature sign(byte[] data, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        Core.Signed s = client.run(o, call -> client.core().tenantSign(call, ref, data));
        return new Signature(s.signature(), s.keyId());
    }

    /** Verifies the tenant's signature. */
    public boolean verify(byte[] data, byte[] signature, byte[] keyId, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.run(o, call -> client.core().tenantVerify(call, ref, data, signature, keyId));
    }

    /** Encrypts every item for the tenant in one request. */
    public List<BatchResult> encryptBatch(List<BatchItem> items, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.batch(o, call -> client.core().tenantEncryptBatch(call, ref, CipheronClient.items(items)));
    }

    /** Decrypts every item of the tenant in one request. */
    public List<BatchResult> decryptBatch(List<BatchItem> items, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.batch(o, call -> client.core().tenantDecryptBatch(call, ref, CipheronClient.items(items)));
    }

    /** Re-encrypts every item of the tenant in one request: under the blob {@code to} in a wrapped profile. */
    public List<BatchResult> reEncryptBatch(List<BatchItem> items, byte[] to, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return client.batch(o,
                call -> client.core().tenantReEncryptBatch(call, ref, CipheronClient.items(items), to));
    }

    /** Encrypts a large plaintext for the tenant as a segmented object. */
    public byte[] encryptObject(byte[] plaintext, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return Containers.encryptObject(client.core().plan(), plaintext, o.aad, o.segmentSize,
                items -> encryptBatch(items, CipheronClient.timeoutOf(o)));
    }

    /** Decrypts the tenant's segmented object whole. */
    public byte[] decryptObject(byte[] object, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return Containers.decryptObject(client.core().plan(), object, o.aad,
                items -> decryptBatch(items, CipheronClient.timeoutOf(o)));
    }

    /** Re-encrypts the tenant's segmented object: under the blob {@code to} in a wrapped profile. */
    public byte[] reEncryptObject(byte[] object, byte[] to, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return Containers.reEncryptObject(client.core().plan(), object, o.aad, o.toAad, o.segmentSize,
                items -> reEncryptBatch(items, to, CipheronClient.timeoutOf(o)));
    }

    /** Encrypts the fields {@code pointers} of a JSON document for the tenant. */
    public byte[] encryptJsonFields(byte[] doc, String recordId, List<String> pointers, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return Containers.jsonFields(client.core().plan(), doc, recordId, pointers, o.aad, null,
                Containers.FieldOp.ENCRYPT, items -> encryptBatch(items, CipheronClient.timeoutOf(o)));
    }

    /** Decrypts the tenant's encrypted fields {@code pointers} of a JSON document. */
    public byte[] decryptJsonFields(byte[] doc, String recordId, List<String> pointers, CallOption... opts) {
        CipheronClient.Opts o = CipheronClient.Opts.of(opts);
        return Containers.jsonFields(client.core().plan(), doc, recordId, pointers, o.aad, null,
                Containers.FieldOp.DECRYPT, items -> decryptBatch(items, CipheronClient.timeoutOf(o)));
    }
}
