package io.github.nnicora.cipheron;

/** No master key version writes now: decryption still works. */
public class NoWriterException extends UnavailableException {
    private static final long serialVersionUID = 1L;

    public NoWriterException(String message) {
        super(message);
    }

    public NoWriterException(String message, Throwable cause) {
        super(message, cause);
    }
}
