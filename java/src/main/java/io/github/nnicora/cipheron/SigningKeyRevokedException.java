package io.github.nnicora.cipheron;

/** The signing key is revoked: no signature under it is accepted. */
public class SigningKeyRevokedException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public SigningKeyRevokedException(String message) {
        super(message);
    }

    public SigningKeyRevokedException(String message, Throwable cause) {
        super(message, cause);
    }
}
