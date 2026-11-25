package io.github.nnicora.cipheron;

/** The message is larger than this client or cipheron accepts. */
public class TooLargeException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public TooLargeException(String message) {
        super(message);
    }

    public TooLargeException(String message, Throwable cause) {
        super(message, cause);
    }
}
