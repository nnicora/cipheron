package io.github.nnicora.cipheron;

/** The profile's key context is not one this client pins: the answer came from a replica on another context. */
public class ContextDigestException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public ContextDigestException(String message) {
        super(message);
    }

    public ContextDigestException(String message, Throwable cause) {
        super(message, cause);
    }
}
