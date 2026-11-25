package io.github.nnicora.cipheron;

/** The call's input is not one cipheron or this library accepts: a ciphertext of no format, associated data that does not fit it, a tenant key blob of another tenant. */
public class InvalidInputException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public InvalidInputException(String message) {
        super(message);
    }

    public InvalidInputException(String message, Throwable cause) {
        super(message, cause);
    }
}
