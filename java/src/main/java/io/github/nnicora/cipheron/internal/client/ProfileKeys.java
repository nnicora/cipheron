package io.github.nnicora.cipheron.internal.client;

import io.github.nnicora.cipheron.internal.wire.Identity;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;

import java.util.Arrays;
import java.util.List;

/**
 * A profile's keys as this client verified them: its identity, its signing keys, its key-context digest and its
 * latest key statement, and the pin set they were checked under. Immutable: a later fetch replaces the whole value
 * ({@code internal/client/client.go}, {@code Keys}).
 */
final class ProfileKeys {
    final String profile;
    final Identity identity;
    final String fingerprint;
    final List<SigningKeys.Key> signingKeys;
    final String contextDigest;
    final byte[] statement;
    final byte[] statementSignature;
    final List<SigningKeys.Key> statementKeys;
    final long statementAtNanos;
    final boolean statementRevoked;
    final PinSet checkedUnder;

    ProfileKeys(String profile, Identity identity, String fingerprint, List<SigningKeys.Key> signingKeys,
            String contextDigest, byte[] statement, byte[] statementSignature, List<SigningKeys.Key> statementKeys,
            long statementAtNanos, boolean statementRevoked, PinSet checkedUnder) {
        this.profile = profile;
        this.identity = identity;
        this.fingerprint = fingerprint;
        this.signingKeys = List.copyOf(signingKeys);
        this.contextDigest = contextDigest;
        this.statement = statement;
        this.statementSignature = statementSignature;
        this.statementKeys = statementKeys == null ? null : List.copyOf(statementKeys);
        this.statementAtNanos = statementAtNanos;
        this.statementRevoked = statementRevoked;
        this.checkedUnder = checkedUnder;
    }

    String tenancy() {
        return identity.tenancy();
    }

    boolean wrapped() {
        return "perTenantWrapped".equals(identity.tenancy());
    }

    ProfileKeys checkedUnder(PinSet pins) {
        return new ProfileKeys(profile, identity, fingerprint, signingKeys, contextDigest, statement,
                statementSignature, statementKeys, statementAtNanos, statementRevoked, pins);
    }

    ProfileKeys withStatement(byte[] stmt, byte[] sig, List<SigningKeys.Key> keys, long at) {
        return new ProfileKeys(profile, identity, fingerprint, signingKeys, contextDigest, stmt, sig, keys, at, false,
                checkedUnder);
    }

    ProfileKeys withList(List<SigningKeys.Key> keys, String digest, PinSet pins, byte[] stmt, byte[] sig,
            List<SigningKeys.Key> stKeys, long at, boolean revoked) {
        return new ProfileKeys(profile, identity, fingerprint, keys, digest, stmt, sig, stKeys, at, revoked, pins);
    }

    /** The active signing key, or null. */
    SigningKeys.Key active() {
        for (SigningKeys.Key k : signingKeys) {
            if (SigningKeys.ACTIVE.equals(k.state())) {
                return k;
            }
        }
        return null;
    }

    /** The signing key {@code keyId} names, or null. */
    SigningKeys.Key signingKey(byte[] keyId) {
        return find(signingKeys, keyId);
    }

    static SigningKeys.Key find(List<SigningKeys.Key> keys, byte[] keyId) {
        if (keyId == null || keyId.length != SigningKeys.KEY_ID_LEN || keys == null) {
            return null;
        }
        for (SigningKeys.Key k : keys) {
            if (Arrays.equals(k.keyId(), keyId)) {
                return k;
            }
        }
        return null;
    }
}
