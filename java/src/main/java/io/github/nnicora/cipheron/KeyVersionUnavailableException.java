package io.github.nnicora.cipheron;

/** The master key version the ciphertext names is not one this cipheron has. It is not corruption: another replica, or the version listed again, decrypts it. */
public class KeyVersionUnavailableException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public KeyVersionUnavailableException(String message) {
        super(message);
    }

    public KeyVersionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
