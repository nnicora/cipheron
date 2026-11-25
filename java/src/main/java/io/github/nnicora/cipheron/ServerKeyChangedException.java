package io.github.nnicora.cipheron;

/** The profile's identity changed after this client trusted it. The new identity is never adopted: pin it to accept it. */
public class ServerKeyChangedException extends ServerIdentityException {
    private static final long serialVersionUID = 1L;

    public ServerKeyChangedException(String message) {
        super(message);
    }

    public ServerKeyChangedException(String message, Throwable cause) {
        super(message, cause);
    }
}
