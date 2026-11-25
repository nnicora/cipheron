package io.github.nnicora.cipheron.internal.client;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * A client's configuration, checked: what the public builder resolved its options to
 * ({@code internal/client/options.go}, {@code plan}).
 *
 * @param endpoint where cipheron listens
 * @param http whether the client speaks the JSON API (else gRPC)
 * @param serverUid the socket server's expected uid; null with {@code anyServer} or on the network
 * @param certFile the client certificate (network)
 * @param keyFile its private key (network)
 * @param caFile the CAs the server is checked against (network)
 * @param serverSpiffeId the server's SPIFFE id, or null to check its host name
 * @param requestKey the Ed25519 request key, or null
 * @param requestPublicKey its raw 32-byte public key, or null
 * @param fingerprints the pinned profile identities
 * @param contextPins the pinned key-context digests per profile
 * @param writerPins the pinned writer master versions per profile
 * @param tenantPins the pinned tenant key fingerprints, by {@code profile + "\0" + tenant}
 * @param requirePins whether a profile with no pin is refused
 * @param pinsDir the pins directory, or null
 * @param maxMessage the largest message sent or received
 * @param connections how many connections the pool keeps
 * @param keysMaxAge the oldest signing-key list a verification relies on
 * @param retry the retry policy, or null
 * @param observer told about identity and key events, or null
 * @param defaultTimeout a call's deadline unless it names one
 */
public record Plan(Endpoint endpoint, boolean http, Long serverUid, Path certFile, Path keyFile, Path caFile,
        String serverSpiffeId, PrivateKey requestKey, byte[] requestPublicKey, Map<String, String> fingerprints,
        Map<String, List<String>> contextPins, Map<String, List<String>> writerPins, Map<String, String> tenantPins,
        boolean requirePins, Path pinsDir, int maxMessage, int connections, Duration keysMaxAge, Retry retry,
        BiConsumer<String, String> observer, Duration defaultTimeout) {

    /** The opt-in retry policy. */
    public record Retry(int maxAttempts, Duration initialBackoff, Duration maxBackoff) {}

    /** The largest message unless the builder says otherwise: 64 MiB and 64 KiB. */
    public static final int DEFAULT_MAX_MESSAGE = (64 << 20) + (64 << 10);

    /** What a request carries besides its payload, at most. */
    public static final int WIRE_OVERHEAD = 1 << 10;

    /** The default pool size over gRPC, and over HTTP. */
    public static final int DEFAULT_CONNECTIONS = 2;
    public static final int DEFAULT_HTTP_CONNECTIONS = 8;
    public static final int MAX_CONNECTIONS = 16;

    /** The bounds of the key list's maximum age. */
    public static final Duration DEFAULT_KEYS_MAX_AGE = Duration.ofMinutes(5);
    public static final Duration MIN_KEYS_MAX_AGE = Duration.ofSeconds(5);
    public static final Duration MAX_KEYS_MAX_AGE = Duration.ofHours(24);

    /** The most context digests, and writer versions, one profile is pinned to. */
    public static final int MAX_CONTEXT_PINS = 8;
    public static final int MAX_WRITER_PINS = 8;

    /** The key a tenant pin is stored under. */
    public static String tenantRef(String profile, String tenant) {
        return profile + "\0" + tenant;
    }
}
