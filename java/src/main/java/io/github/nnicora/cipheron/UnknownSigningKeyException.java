package io.github.nnicora.cipheron;

/** The signature names a signing key this client does not know. */
public class UnknownSigningKeyException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public UnknownSigningKeyException(String message) {
        super(message);
    }

    public UnknownSigningKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
