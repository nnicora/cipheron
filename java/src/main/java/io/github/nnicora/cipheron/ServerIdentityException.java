package io.github.nnicora.cipheron;

/** The party answering is not the profile's cipheron: a wrong pin, an answer that does not verify, a socket served by another uid, a server certificate that does not check. */
public class ServerIdentityException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public ServerIdentityException(String message) {
        super(message);
    }

    public ServerIdentityException(String message, Throwable cause) {
        super(message, cause);
    }
}
