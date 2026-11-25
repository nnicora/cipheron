package io.github.nnicora.cipheron;

/** Not a JSON document, field or encrypted field the call can use. */
public class JsonFieldException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public JsonFieldException(String message) {
        super(message);
    }

    public JsonFieldException(String message, Throwable cause) {
        super(message, cause);
    }
}
