package io.github.nnicora.cipheron;

/** cipheron is busy: retry after the delay it names (retryAfter). */
public class BusyException extends UnavailableException {
    private static final long serialVersionUID = 1L;

    public BusyException(String message) {
        super(message);
    }

    public BusyException(String message, Throwable cause) {
        super(message, cause);
    }
}
