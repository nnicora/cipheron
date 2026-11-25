package io.github.nnicora.cipheron;

/** Not a segmented object, or one that was modified, truncated or reordered. */
public class SegmentedException extends InvalidInputException {
    private static final long serialVersionUID = 1L;

    public SegmentedException(String message) {
        super(message);
    }

    public SegmentedException(String message, Throwable cause) {
        super(message, cause);
    }
}
