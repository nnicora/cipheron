package io.github.nnicora.cipheron.internal.wire;

/**
 * How a client reads cipheron's refusals: by the status code and the ErrorInfo reason (in the domain
 * {@code cipheron.v1} only), never by the message ({@code wire/transport/refusal.go}, {@code transport.go}).
 */
public final class Refusals {
    /** The ErrorInfo domain of cipheron's reasons. */
    public static final String DOMAIN = "cipheron.v1";

    public static final String KEY_VERSION_UNAVAILABLE = "CIPHERON_KEY_VERSION_UNAVAILABLE";
    public static final String BUSY = "CIPHERON_BUSY";
    public static final String NO_WRITER = "CIPHERON_NO_WRITER";
    public static final String ASSOCIATED_DATA = "CIPHERON_ASSOCIATED_DATA";
    public static final String BATCH_LIMIT = "CIPHERON_BATCH_LIMIT";
    public static final String AUDIT_UNAVAILABLE = "CIPHERON_AUDIT_UNAVAILABLE";
    public static final String PROFILE_SEALED = "CIPHERON_PROFILE_SEALED";
    public static final String STARTING = "CIPHERON_STARTING";

    public static final int INVALID_ARGUMENT = 3;
    public static final int PERMISSION_DENIED = 7;
    public static final int RESOURCE_EXHAUSTED = 8;
    public static final int UNIMPLEMENTED = 12;
    public static final int INTERNAL = 13;
    public static final int UNAVAILABLE = 14;

    private Refusals() {}

    /** Whether, and how, a refusal may be sent again. */
    public enum Retry {
        /** Never sent again by the client on its own. */
        NEVER("never"),
        /** Sent again later, or through another replica. */
        TRANSIENT("transient"),
        /** Signed again and sent once more, whatever the operation (the request predates the process). */
        RESIGN("resign");

        private final String wire;

        Retry(String wire) {
            this.wire = wire;
        }

        /** The rule's name, as the conformance kit writes it. */
        public String wire() {
            return wire;
        }
    }

    /**
     * A refusal's class and retry rule.
     *
     * @param name the class's name, as the conformance kit writes it
     * @param retry the retry rule
     */
    public record Class(String name, Retry retry) {}

    /**
     * Classifies a refusal of status {@code code} with an ErrorInfo of {@code domain} and {@code reason} (both null
     * when it has none). A reason counts only in the domain {@code cipheron.v1} and with the code cipheron answers it
     * with; a RetryInfo alone makes nothing retryable.
     */
    public static Class classify(int code, String domain, String reason) {
        boolean hasInfo = domain != null || reason != null;
        String r = hasInfo && DOMAIN.equals(domain) ? reason : "";
        switch (code) {
            case PERMISSION_DENIED:
                return new Class("permissionDenied", Retry.NEVER);
            case INVALID_ARGUMENT:
                if (KEY_VERSION_UNAVAILABLE.equals(r)) {
                    return new Class("keyVersionUnavailable", Retry.NEVER);
                }
                if (ASSOCIATED_DATA.equals(r)) {
                    return new Class("associatedData", Retry.NEVER);
                }
                if (BATCH_LIMIT.equals(r)) {
                    return new Class("batchLimit", Retry.NEVER);
                }
                return new Class("invalidInput", Retry.NEVER);
            case RESOURCE_EXHAUSTED:
                return BUSY.equals(r) ? new Class("busy", Retry.TRANSIENT)
                        : new Class("resourceExhausted", Retry.NEVER);
            case UNAVAILABLE:
                if (STARTING.equals(r)) {
                    return new Class("starting", Retry.RESIGN);
                }
                if (NO_WRITER.equals(r)) {
                    return new Class("noWriter", Retry.TRANSIENT);
                }
                if (PROFILE_SEALED.equals(r)) {
                    return new Class("profileSealed", Retry.TRANSIENT);
                }
                if (AUDIT_UNAVAILABLE.equals(r)) {
                    return new Class("auditUnavailable", Retry.TRANSIENT);
                }
                if (!hasInfo) {
                    return new Class("unavailable", Retry.TRANSIENT);
                }
                return new Class("unavailable", Retry.NEVER);
            case UNIMPLEMENTED:
                return new Class("unsupported", Retry.NEVER);
            case INTERNAL:
                return new Class("internal", Retry.NEVER);
            default:
                return new Class("other", Retry.NEVER);
        }
    }
}
