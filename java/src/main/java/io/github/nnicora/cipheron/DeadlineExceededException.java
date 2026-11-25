package io.github.nnicora.cipheron;

/** The call's deadline passed before cipheron answered. */
public class DeadlineExceededException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public DeadlineExceededException(String message) {
        super(message);
    }

    public DeadlineExceededException(String message, Throwable cause) {
        super(message, cause);
    }
}
