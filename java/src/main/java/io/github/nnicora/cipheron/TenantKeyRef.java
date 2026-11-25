package io.github.nnicora.cipheron;

/**
 * A tenant key to rewrap: the tenant and its blob.
 *
 * @param tenant the tenant
 * @param blob its key blob
 */
public record TenantKeyRef(String tenant, byte[] blob) {}
