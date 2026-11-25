package io.github.nnicora.cipheron;

/** The associated data does not match the ciphertext's format, or a re-encryption's target associated data differs from the stored ciphertext's. */
public class AssociatedDataException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public AssociatedDataException(String message) {
        super(message);
    }

    public AssociatedDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
