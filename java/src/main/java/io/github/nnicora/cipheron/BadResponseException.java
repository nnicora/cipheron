package io.github.nnicora.cipheron;

/** cipheron's answer is malformed: a ciphertext of the wrong format or length, a plaintext that does not open. */
public class BadResponseException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public BadResponseException(String message) {
        super(message);
    }

    public BadResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
