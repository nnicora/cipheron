package io.github.nnicora.cipheron;

/** Not a valid key statement, or one that does not check against the pin. */
public class KeyStatementException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public KeyStatementException(String message) {
        super(message);
    }

    public KeyStatementException(String message, Throwable cause) {
        super(message, cause);
    }
}
