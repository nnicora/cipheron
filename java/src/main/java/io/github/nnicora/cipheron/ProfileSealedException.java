package io.github.nnicora.cipheron;

/** The profile is sealed on this replica: retry later or on another replica. */
public class ProfileSealedException extends UnavailableException {
    private static final long serialVersionUID = 1L;

    public ProfileSealedException(String message) {
        super(message);
    }

    public ProfileSealedException(String message, Throwable cause) {
        super(message, cause);
    }
}
