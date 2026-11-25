package io.github.nnicora.cipheron;

/** The client is closed. */
public class ClosedException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public ClosedException(String message) {
        super(message);
    }

    public ClosedException(String message, Throwable cause) {
        super(message, cause);
    }
}
