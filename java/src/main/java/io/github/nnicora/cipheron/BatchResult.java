package io.github.nnicora.cipheron;

/**
 * One item's outcome: its value, or the refusal cipheron answered for that item alone (the batch's other items are
 * not affected). Exactly one of the two is set.
 *
 * @param value the item's ciphertext or plaintext
 * @param error the item's refusal
 */
public record BatchResult(byte[] value, CipheronException error) {
    /** Whether the item succeeded. */
    public boolean ok() {
        return error == null;
    }
}
