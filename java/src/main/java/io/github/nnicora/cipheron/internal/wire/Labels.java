package io.github.nnicora.cipheron.internal.wire;

/**
 * The protocol's labels: each opens a transcript, digest, fingerprint or associated-data block, names what it covers,
 * and lies in the namespace {@code cipheron/v1|} ({@code wire/format/labels.go}). Only the labels a client computes
 * are here; cipheron's own (keyset, audit, storage) never reach a client.
 */
public final class Labels {
    /** The protocol namespace every label opens with. */
    public static final String NAMESPACE = "cipheron/v1|";

    public static final String SIGNED_REQUEST = NAMESPACE + "signed_request";
    public static final String SIGNED_RESPONSE = NAMESPACE + "signed_response";
    public static final String DIGEST = NAMESPACE + "digest";
    public static final String FINGERPRINT = NAMESPACE + "fingerprint";
    public static final String FINGERPRINT2 = NAMESPACE + "fingerprint2";
    public static final String TENANT_FINGERPRINT = NAMESPACE + "tenant-fingerprint";
    public static final String SIGNED_KEYS = NAMESPACE + "signed_keys";
    public static final String SIGNING_KEY_ID = NAMESPACE + "signing-key-id";
    public static final String SIGNING_KEY_ID2 = NAMESPACE + "signing-key-id2";
    public static final String CONTEXT = NAMESPACE + "context";
    public static final String TENANT_SIGNATURE = NAMESPACE + "tenant-signature";
    public static final String KEY_STATEMENT = NAMESPACE + "key_statement";
    public static final String SEGMENT = NAMESPACE + "segment";
    public static final String JSON_FIELD = NAMESPACE + "json-field";

    /** "cipheron/v1|request|": the context a request payload is sealed under opens with it. */
    static final String REQUEST_CONTEXT = NAMESPACE + "request|";

    /** "cipheron/v1|response|": the context a Decrypt answer is sealed under opens with it. */
    static final String RESPONSE_CONTEXT = NAMESPACE + "response|";

    private Labels() {}
}
