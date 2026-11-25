package io.github.nnicora.cipheron;

/**
 * One side of a cross-profile re-encryption ({@link CipheronClient#reEncryptAcross}): a profile, and the tenant and
 * its key blob in a perTenant profile.
 *
 * @param profile the profile
 * @param tenant the tenant in a perTenant profile, else null
 * @param tenantKey the tenant's key blob in a wrapped profile, else null
 */
public record Scope(String profile, String tenant, byte[] tenantKey) {
    /** A shared profile. */
    public static Scope shared(String profile) {
        return new Scope(profile, null, null);
    }

    /** A tenant of a perTenant profile: its blob in a wrapped profile, null in a derived one. */
    public static Scope tenant(String profile, String tenant, byte[] blob) {
        return new Scope(profile, tenant, blob);
    }
}
