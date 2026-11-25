package io.github.nnicora.cipheron;

import java.time.Duration;
import java.util.Optional;

/**
 * Every failure of a cipheron call. Catch a subclass to act on a kind — {@link UnavailableException} and its kinds
 * may succeed later, {@link ServerIdentityException} means the party answering is not the profile's cipheron — and
 * never on the message, which is for people.
 */
public class CipheronException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private String requestId;
    private Duration retryAfter;
    private transient BatchLimits batchLimits;

    public CipheronException(String message) {
        super(message);
    }

    public CipheronException(String message, Throwable cause) {
        super(message, cause);
    }

    /** The {@code x-request-id} the call carried: the id cipheron logs and audits it under. */
    public Optional<String> requestId() {
        return Optional.ofNullable(requestId);
    }

    /** The delay cipheron asked for before a retry (its {@code RetryInfo}), if its refusal named one. */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }

    /**
     * cipheron's batch limits, when it refused a batch as too large for them ({@code CIPHERON_BATCH_LIMIT}): split
     * the batch to fit.
     */
    public Optional<BatchLimits> batchLimits() {
        return Optional.ofNullable(batchLimits);
    }

    /** The batch limits a refusal named. */
    public record BatchLimits(int maxItems, long maxBytes) {}

    /** Sets the refusal's batch limits. Internal: the library sets them once, when it maps the failure. */
    public CipheronException withBatchLimits(BatchLimits l) {
        if (batchLimits == null) {
            batchLimits = l;
        }
        return this;
    }

    /** Sets the call's request id. Internal: the library sets it once, when it maps the failure. */
    public CipheronException withRequestId(String id) {
        if (requestId == null) {
            requestId = id;
        }
        return this;
    }

    /** Sets cipheron's retry delay. Internal: the library sets it once, when it maps the failure. */
    public CipheronException withRetryAfter(Duration d) {
        if (retryAfter == null) {
            retryAfter = d;
        }
        return this;
    }
}
