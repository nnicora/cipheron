package io.github.nnicora.cipheron.internal.wire;

/**
 * The protocol's names and their rules: profile names, tenant ids, master version ids and the {@code sha256:}
 * strings (fingerprints and key-context digests). Each is a pure check, as {@code wire/transport} has it.
 */
public final class Grammar {
    /** The longest profile name. */
    public static final int MAX_PROFILE_LEN = 63;

    /** The longest tenant id. */
    public static final int MAX_TENANT_LEN = 2048;

    /** The longest master key version id. */
    public static final int MAX_MASTER_VERSION_ID_LEN = 32;

    /** Opens every fingerprint string, and the key-context digest. */
    public static final String FINGERPRINT_PREFIX = "sha256:";

    private Grammar() {}

    /**
     * Whether {@code name} is a profile name: 1 to 63 bytes, a lower-case letter first, then lower-case letters,
     * digits and single hyphens, never one last ({@code ^[a-z][a-z0-9]*(-[a-z0-9]+)*$}).
     */
    public static boolean validProfile(String name) {
        byte[] b = Bytes.utf8(name);
        if (b.length == 0 || b.length > MAX_PROFILE_LEN || b[0] < 'a' || b[0] > 'z') {
            return false;
        }
        for (int i = 1; i < b.length; i++) {
            byte c = b[i];
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                continue;
            }
            if (c == '-' && b[i - 1] != '-' && i < b.length - 1) {
                continue;
            }
            return false;
        }
        return true;
    }

    /** Whether {@code s} is a tenant id: 1 to 2048 bytes, each 0x21 to 0x7E. */
    public static boolean validTenant(String s) {
        return validTenant(Bytes.utf8(s));
    }

    /** Whether {@code b} is a tenant id: 1 to 2048 bytes, each 0x21 to 0x7E. */
    public static boolean validTenant(byte[] b) {
        if (b.length == 0 || b.length > MAX_TENANT_LEN) {
            return false;
        }
        for (byte c : b) {
            if (c < '!' || c > '~') {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code s} is a master key version id: 1 to 32 bytes of {@code [A-Za-z0-9._-]}. */
    public static boolean validMasterVersionId(String s) {
        return validMasterVersionId(Bytes.utf8(s));
    }

    /** Whether {@code b} is a master key version id: 1 to 32 bytes of {@code [A-Za-z0-9._-]}. */
    public static boolean validMasterVersionId(byte[] b) {
        if (b.length == 0 || b.length > MAX_MASTER_VERSION_ID_LEN) {
            return false;
        }
        for (byte c : b) {
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
                    || c == '_' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code s} is written as a fingerprint is: {@code sha256:} and 64 lower-case hex digits. */
    public static boolean validFingerprint(String s) {
        if (s == null || !s.startsWith(FINGERPRINT_PREFIX)) {
            return false;
        }
        String h = s.substring(FINGERPRINT_PREFIX.length());
        if (h.length() != 64) {
            return false;
        }
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /** {@code sha256:} and the lower-case hex of {@code sum}. */
    public static String sha256String(byte[] sum) {
        return FINGERPRINT_PREFIX + Bytes.hex(sum);
    }
}
