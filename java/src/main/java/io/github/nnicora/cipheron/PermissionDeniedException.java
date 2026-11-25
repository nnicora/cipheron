package io.github.nnicora.cipheron;

/** cipheron refused the call: an unknown profile, a caller no entry lists, an operation not granted, a request whose signature, timestamp or nonce does not check. cipheron answers every such case alike, so the cause is not named. */
public class PermissionDeniedException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public PermissionDeniedException(String message) {
        super(message);
    }

    public PermissionDeniedException(String message, Throwable cause) {
        super(message, cause);
    }
}
