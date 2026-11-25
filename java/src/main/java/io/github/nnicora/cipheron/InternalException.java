package io.github.nnicora.cipheron;

/** cipheron failed internally. */
public class InternalException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public InternalException(String message) {
        super(message);
    }

    public InternalException(String message, Throwable cause) {
        super(message, cause);
    }
}
