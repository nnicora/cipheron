package io.github.nnicora.cipheron;

import java.time.Duration;

/**
 * The opt-in retry of refusals that say "later" (busy, no writer, the profile sealed, the audit unavailable, an
 * unavailable connection): each attempt is a new request with a new nonce and signature, after a jittered backoff that
 * is never shorter than cipheron's {@code RetryInfo}, and never past the call's deadline. CreateTenantKey and the
 * rewrap calls are never retried: a second execution makes a second key.
 *
 * @param maxAttempts attempts in all, 2 to 10
 * @param initialBackoff the first backoff, 1 ms to 30 s
 * @param maxBackoff the longest backoff, at least the first, at most 30 s
 */
public record RetryPolicy(int maxAttempts, Duration initialBackoff, Duration maxBackoff) {
    /** 3 attempts, 100 ms doubling to 2 s. */
    public static final RetryPolicy DEFAULT = new RetryPolicy(3, Duration.ofMillis(100), Duration.ofSeconds(2));

    public RetryPolicy {
        if (maxAttempts < 2 || maxAttempts > 10) {
            throw new IllegalArgumentException("a retry policy makes 2 to 10 attempts, not " + maxAttempts);
        }
        if (initialBackoff.compareTo(Duration.ofMillis(1)) < 0 || initialBackoff.compareTo(Duration.ofSeconds(30)) > 0
                || maxBackoff.compareTo(initialBackoff) < 0 || maxBackoff.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("a retry backoff is 1 ms to 30 s, the longest at least the first");
        }
    }
}
