package io.github.nnicora.cipheron;

/** This cipheron does not serve the call. */
public class UnsupportedException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public UnsupportedException(String message) {
        super(message);
    }

    public UnsupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
