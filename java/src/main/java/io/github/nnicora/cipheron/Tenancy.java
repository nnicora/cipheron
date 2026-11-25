package io.github.nnicora.cipheron;

/** How a profile keys its data: one key for everyone, or one per tenant. */
public enum Tenancy {
    /** One key context for every caller: calls name no tenant. */
    SHARED("shared"),
    /** A key per tenant, wrapped by cipheron in a blob the application holds and passes with each call. */
    PER_TENANT_WRAPPED("perTenantWrapped"),
    /** A key per tenant, derived by cipheron from the tenant id: calls name the tenant, and carry no blob. */
    PER_TENANT_DERIVED("perTenantDerived");

    private final String wire;

    Tenancy(String wire) {
        this.wire = wire;
    }

    /** The tenancy's name in the protocol: {@code shared}, {@code perTenantWrapped}, {@code perTenantDerived}. */
    public String wire() {
        return wire;
    }

    /** The tenancy the protocol name {@code s} names. */
    public static Tenancy of(String s) {
        for (Tenancy t : values()) {
            if (t.wire.equals(s)) {
                return t;
            }
        }
        throw new IllegalArgumentException("not a tenancy: " + s);
    }
}
