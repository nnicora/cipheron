package io.github.nnicora.cipheron;

/** The tenant key blob or the tenant id given is not this tenant's in this profile, or not the pinned one. */
public class TenantKeyException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public TenantKeyException(String message) {
        super(message);
    }

    public TenantKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
