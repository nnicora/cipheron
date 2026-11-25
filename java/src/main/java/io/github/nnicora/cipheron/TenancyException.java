package io.github.nnicora.cipheron;

/** The call is not one of the profile's tenancy: a tenant call on a shared profile, a blob for a derived one. */
public class TenancyException extends CipheronException {
    private static final long serialVersionUID = 1L;

    public TenancyException(String message) {
        super(message);
    }

    public TenancyException(String message, Throwable cause) {
        super(message, cause);
    }
}
