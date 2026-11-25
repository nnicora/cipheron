package io.github.nnicora.cipheron.internal.wire;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The signed transcripts and the HPKE seal infos, at transcript version 1, the only one this release reads and
 * writes. The version is never negotiated and never sent: every transcript and seal info binds it as the field
 * {@code lp(u32(1))} ({@code wire/transport/auth.go}, {@code keys.go}, {@code transport.go}).
 */
public final class Transcripts {
    /** The transcript version this release reads and writes. */
    public static final long VERSION = 1;

    private Transcripts() {}

    /**
     * What a caller's request key signs: {@code lp(label) lp(version) lp(profile) lp(operation) lp(timestamp)
     * lp(nonce) lp(digest)}, the timestamp in milliseconds, 8 bytes big-endian.
     */
    public static byte[] request(String profile, String operation, long timestampMs, byte[] nonce, byte[] digest) {
        return Lp.create().add(Labels.SIGNED_REQUEST).addUint32(VERSION).add(profile).add(operation)
                .add(Bytes.int64(timestampMs)).add(nonce).add(digest).bytes();
    }

    /**
     * A response transcript's requester field: the SHA-256 of the request's {@code auth.signature}, or a zero-length
     * field when the request carried none (never 32 zero bytes).
     */
    public static byte[] requester(byte[] requestSignature) {
        if (requestSignature == null || requestSignature.length == 0) {
            return Bytes.EMPTY;
        }
        return Bytes.sha256(requestSignature);
    }

    /**
     * What the profile's response key signs over every answer: {@code lp(label) lp(version) lp(profile)
     * lp(context digest) lp(operation) lp(request nonce) lp(requester) lp(request digest) lp(response digest)}.
     * {@code requestSignature} is the {@code auth.signature} the request carried (the transcript holds
     * {@link #requester} of it).
     */
    public static byte[] response(String profile, String contextDigest, String operation, byte[] requestNonce,
            byte[] requestSignature, byte[] requestDigest, byte[] responseDigest) {
        return Lp.create().add(Labels.SIGNED_RESPONSE).addUint32(VERSION).add(profile).add(contextDigest)
                .add(operation).add(requestNonce).add(requester(requestSignature)).add(requestDigest)
                .add(responseDigest).bytes();
    }

    /** One signing key of a PublicKey answer as received: its id, its state's number, its public key. */
    public record ReceivedKey(byte[] keyId, long state, byte[] publicKey) {}

    /**
     * What the response key signs over a PublicKey answer's signing keys ({@code keys_signature}): {@code lp(label)
     * lp(version) lp(profile) lp(tenancy) lp(context digest) lp(nonce) lp(u32(k))} and each key in ascending key id
     * order: {@code lp(key id) lp(u32(state)) lp(public key)}. The tenancy is its name, the state its number.
     */
    public static byte[] signingKeys(String profile, String tenancy, String contextDigest, byte[] nonce,
            List<ReceivedKey> keys) {
        List<ReceivedKey> sorted = new ArrayList<>(keys);
        sorted.sort((a, b) -> Arrays.compareUnsigned(a.keyId(), b.keyId()));
        Lp t = Lp.create().add(Labels.SIGNED_KEYS).addUint32(VERSION).add(profile).add(tenancy).add(contextDigest)
                .add(nonce).addUint32(sorted.size());
        for (ReceivedKey k : sorted) {
            t.add(k.keyId()).addUint32(k.state()).add(k.publicKey());
        }
        return t.bytes();
    }

    /**
     * The HPKE info a request payload is sealed under: {@code cipheron/v1|request|<profile>|<op>} ({@code |<tenant>}
     * in a perTenant profile), then {@code lp(u32(1))} and {@code lp(SHA-256(request public key))} — a zero-length
     * field without a request key.
     */
    public static byte[] requestSealInfo(String profile, String operation, String tenant, byte[] requestPublicKey) {
        byte[] requester = requestPublicKey == null || requestPublicKey.length == 0 ? Bytes.EMPTY
                : Bytes.sha256(requestPublicKey);
        return Lp.create().raw(context(Labels.REQUEST_CONTEXT, profile, operation, tenant)).addUint32(VERSION)
                .add(requester).bytes();
    }

    /**
     * The HPKE info a Decrypt answer's plaintext is sealed under: {@code cipheron/v1|response|<profile>|<op>}
     * ({@code |<tenant>}), then {@code lp(u32(1))}.
     */
    public static byte[] responseSealInfo(String profile, String operation, String tenant) {
        return Lp.create().raw(context(Labels.RESPONSE_CONTEXT, profile, operation, tenant)).addUint32(VERSION)
                .bytes();
    }

    private static byte[] context(String direction, String profile, String operation, String tenant) {
        StringBuilder b = new StringBuilder(direction).append(profile).append('|').append(operation);
        if (!tenant.isEmpty()) {
            b.append('|').append(tenant);
        }
        return Bytes.utf8(b.toString());
    }
}
