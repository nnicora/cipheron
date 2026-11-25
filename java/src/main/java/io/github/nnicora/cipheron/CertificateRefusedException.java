package io.github.nnicora.cipheron;

/** cipheron refused this client's certificate during the TLS handshake (an authenticated alert on a TLS 1.3 connection). */
public class CertificateRefusedException extends PermissionDeniedException {
    private static final long serialVersionUID = 1L;

    public CertificateRefusedException(String message) {
        super(message);
    }

    public CertificateRefusedException(String message, Throwable cause) {
        super(message, cause);
    }
}
