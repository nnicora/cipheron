package io.github.nnicora.cipheron;

import io.github.nnicora.cipheron.internal.client.Core;
import io.github.nnicora.cipheron.internal.client.Endpoint;
import io.github.nnicora.cipheron.internal.crypto.Ed25519;
import io.github.nnicora.cipheron.internal.wire.Ciphertexts;
import io.github.nnicora.cipheron.internal.wire.Identity;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;
import io.github.nnicora.cipheron.internal.wire.TenantKeys;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** What needs no cipheron: reading a ciphertext's key, verifying a signature under keys already held. */
public final class Cipheron {
    private Cipheron() {}

    /** Which key {@code ciphertext} names, read from its header: {@link InvalidInputException} for no ciphertext. */
    public static CiphertextKey keyId(byte[] ciphertext) {
        try {
            Ciphertexts.KeyId k = Ciphertexts.parse(ciphertext);
            return new CiphertextKey(k.format(), k.masterVersion(), k.tenantKeyId(), k.associatedData());
        } catch (Ciphertexts.Refused e) {
            throw new InvalidInputException("cipheron: invalid input: " + e.getMessage(), e);
        }
    }

    /** Whether {@code signature} is {@code publicKey}'s over {@code data} (Ed25519). Key states are not known here. */
    public static boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        return Ed25519.verify(publicKey, data, signature);
    }

    /** Whether {@code signature} is a derived profile's key's over {@code data} for {@code tenant}. */
    public static boolean verifyTenant(byte[] publicKey, String profile, String tenant, byte[] data, byte[] signature) {
        return Ed25519.verify(publicKey, TenantKeys.signedMessage(profile, tenant, data), signature);
    }

    /**
     * Verifies a shared profile's signature under {@code keys} (as {@link CipheronClient#keys} lists them), honouring
     * the key's state: a revoked key is {@link SigningKeyRevokedException}, a list that is not one profile's is
     * {@link InvalidKeyListException}.
     */
    public static boolean verifyWithKeys(List<SigningKey> keys, byte[] data, byte[] signature, byte[] keyId) {
        return verify(listedKey(keys, keyId).publicKey(), data, signature);
    }

    /** As {@link #verifyWithKeys}, for a derived profile's tenant. */
    public static boolean verifyTenantWithKeys(List<SigningKey> keys, String profile, String tenant, byte[] data,
            byte[] signature, byte[] keyId) {
        return verifyTenant(listedKey(keys, keyId).publicKey(), profile, tenant, data, signature);
    }

    private static SigningKey listedKey(List<SigningKey> keys, byte[] keyId) {
        Set<String> seen = new HashSet<>();
        for (SigningKey k : keys) {
            byte[] pub = k.publicKey();
            boolean badLen = pub.length == 0 || pub.length > Identity.MAX_KEY_LEN
                    || (k.algorithm() == Identity.ALGORITHM_ED25519 && pub.length != Ed25519.PUBLIC_KEY_LEN);
            if (badLen || !Arrays.equals(k.keyId(), SigningKeys.keyIdOf(k.algorithm(), pub))) {
                throw new InvalidKeyListException("cipheron: the signing-key list given is not one profile's list: "
                        + "key id " + hex(k.keyId()) + " is not the id of the public key listed under it");
            }
            if (!seen.add(hex(k.keyId()))) {
                throw new InvalidKeyListException("cipheron: the signing-key list given is not one profile's list: "
                        + "key id " + hex(k.keyId()) + " is listed twice (two lists joined?): pass one list");
            }
        }
        for (SigningKey k : keys) {
            if (Arrays.equals(k.keyId(), keyId)) {
                if (k.state() == SigningKey.State.REVOKED) {
                    throw new SigningKeyRevokedException("cipheron: the signing key is revoked (key id " + hex(keyId)
                            + "): no signature under it is accepted");
                }
                if (k.algorithm() != Identity.ALGORITHM_ED25519) {
                    throw new InvalidKeyListException("cipheron: the signing key's algorithm (number " + k.algorithm()
                            + ") is not one this library implements");
                }
                return k;
            }
        }
        throw new UnknownSigningKeyException("cipheron: the signature names a signing key this client does not know "
                + "(key id " + hex(keyId) + "): the list given does not name it");
    }

    /** What a tenant key blob's header says (not authenticated: only cipheron can check the blob). */
    public record TenantKeyInfo(int version, String profile, String tenant, byte[] keyId, byte[] signingPublicKey,
            String fingerprint, String wrappingVersion, Instant created) {}

    /** Reads a tenant key blob's header: {@link TenantKeyException} for no blob. */
    public static TenantKeyInfo readTenantKey(byte[] blob) {
        try {
            TenantKeys.Header h = TenantKeys.parse(blob);
            return new TenantKeyInfo(TenantKeys.VERSION, h.profile(), h.tenant(), h.keyId(), h.signingPublicKey(),
                    h.fingerprint(), h.wrappingVersion(), Instant.ofEpochSecond(h.created()));
        } catch (TenantKeys.Refused e) {
            throw new TenantKeyException("cipheron: not the tenant's key: " + e.getMessage(), e);
        }
    }

    /** Whether {@code address} names a unix socket rather than {@code host:port}. */
    public static boolean isSocketAddress(String address) {
        return Endpoint.isSocketAddress(address);
    }

    /** The delay cipheron asked for before a retry, if the failure carries one. */
    public static Optional<Duration> retryAfter(Throwable e) {
        return e instanceof CipheronException ce ? ce.retryAfter() : Optional.empty();
    }

    static Keys keysOf(Core.ProfileView v) {
        List<SigningKey> keys = new ArrayList<>();
        for (SigningKeys.Key k : v.signingKeys()) {
            keys.add(CipheronClient.publicKey(k));
        }
        return new Keys(v.profile(), Tenancy.of(v.identity().tenancy()), v.fingerprint(),
                v.identity().fingerprintVersion(), v.contextDigest(), v.identity().hpke(), v.identity().response(),
                keys, v.statement(), v.statementSignature());
    }

    private static String hex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }
}
