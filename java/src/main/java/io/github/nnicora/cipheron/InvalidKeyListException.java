package io.github.nnicora.cipheron;

/** The signing-key list given is not one profile's list: an id that is not its key's, a key listed twice. */
public class InvalidKeyListException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public InvalidKeyListException(String message) {
        super(message);
    }

    public InvalidKeyListException(String message, Throwable cause) {
        super(message, cause);
    }
}
