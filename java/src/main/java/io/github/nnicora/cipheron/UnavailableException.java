package io.github.nnicora.cipheron;

/** cipheron could not answer now; the call may succeed later or on another replica. */
public class UnavailableException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public UnavailableException(String message) {
        super(message);
    }

    public UnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
