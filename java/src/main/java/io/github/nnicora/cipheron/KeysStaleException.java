package io.github.nnicora.cipheron;

/** The profile's signing-key list is older than the client's maximum age and could not be fetched again: the verification fails closed. */
public class KeysStaleException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public KeysStaleException(String message) {
        super(message);
    }

    public KeysStaleException(String message, Throwable cause) {
        super(message, cause);
    }
}
