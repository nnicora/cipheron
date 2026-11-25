package io.github.nnicora.cipheron;

/**
 * One rewrap's outcome: the rewrapped key, or the refusal cipheron answered for that key alone.
 *
 * @param key the rewrapped key
 * @param error the key's refusal
 */
public record TenantKeyResult(TenantKey key, CipheronException error) {
    /** Whether the key was rewrapped. */
    public boolean ok() {
        return error == null;
    }
}
