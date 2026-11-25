package io.github.nnicora.cipheron.internal.client;

import io.github.nnicora.cipheron.internal.wire.Refusals;

import java.time.Duration;

/**
 * A call that cipheron, or the path to it, did not answer with a result: a refusal (a status code, and the ErrorInfo
 * and RetryInfo it carried) or a transport failure, read the same from either API. The client decides on the code
 * and the reason; the message is for people.
 */
public final class RpcFailure extends Exception {
    private static final long serialVersionUID = 1L;

    /** gRPC's code numbers the client names. */
    public static final int CANCELLED = 1;
    public static final int UNKNOWN = 2;
    public static final int DEADLINE_EXCEEDED = 4;
    public static final int FAILED_PRECONDITION = 9;

    private final int code;
    private final String statusMessage;
    private final String domain;
    private final String reason;
    private final Duration retryDelay;
    private final boolean retryInfo;
    private final boolean sizeRefusal;
    private final String requestId;
    private transient java.util.Map<String, String> metadata = java.util.Map.of();

    /**
     * @param code the status code's number
     * @param message the status message
     * @param domain the ErrorInfo's domain, null without one
     * @param reason the ErrorInfo's reason, null without one
     * @param retryDelay the RetryInfo's delay, null without one or with an invalid one
     * @param retryInfo whether a RetryInfo was attached at all
     * @param sizeRefusal whether this is gRPC's own refusal of a message too large (no details)
     * @param requestId the call's x-request-id
     * @param cause the transport's exception
     */
    public RpcFailure(int code, String message, String domain, String reason, Duration retryDelay, boolean retryInfo,
            boolean sizeRefusal, String requestId, Throwable cause) {
        super("cipheron: " + message + " (code " + code + ")", cause);
        this.code = code;
        this.statusMessage = message;
        this.domain = domain;
        this.reason = reason;
        this.retryDelay = retryDelay;
        this.retryInfo = retryInfo;
        this.sizeRefusal = sizeRefusal;
        this.requestId = requestId;
    }

    public int code() {
        return code;
    }

    public String statusMessage() {
        return statusMessage;
    }

    public String domain() {
        return domain;
    }

    public String reason() {
        return reason;
    }

    public Duration retryDelay() {
        return retryDelay;
    }

    public boolean hasRetryInfo() {
        return retryInfo;
    }

    public boolean sizeRefusal() {
        return sizeRefusal;
    }

    public String requestId() {
        return requestId;
    }

    /** The ErrorInfo's metadata (CIPHERON_BATCH_LIMIT's maxItems and maxBytes). */
    public java.util.Map<String, String> metadata() {
        return metadata;
    }

    RpcFailure withMetadata(java.util.Map<String, String> m) {
        metadata = java.util.Map.copyOf(m);
        return this;
    }

    /** Whether the refusal names {@code r} in cipheron's domain. */
    public boolean hasReason(String r) {
        return Refusals.DOMAIN.equals(domain) && r.equals(reason);
    }

    /** The refusal's class and retry rule (Refusals.classify). */
    public Refusals.Class classify() {
        return Refusals.classify(code, domain, reason);
    }
}
