package io.github.nnicora.cipheron;

/** The profile has no pin, and the client requires one. */
public class PinRequiredException extends ServerIdentityException {
    private static final long serialVersionUID = 1L;

    public PinRequiredException(String message) {
        super(message);
    }

    public PinRequiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
