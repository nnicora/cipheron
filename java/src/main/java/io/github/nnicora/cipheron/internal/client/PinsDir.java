package io.github.nnicora.cipheron.internal.client;

import io.github.nnicora.cipheron.internal.wire.Grammar;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The pins directory ({@code CIPHERON_PINS_DIR}, {@code pinsDir}): {@code <profile>.fingerprint} holds a profile's
 * fingerprint, {@code <profile>.contextDigest} its key-context digests, one per line. A Kubernetes volume is read
 * through its {@code ..data} link, so an update is seen whole ({@code internal/client/env.go}, {@code livepins.go}).
 */
public final class PinsDir {
    public static final String FINGERPRINT_SUFFIX = ".fingerprint";
    public static final String CONTEXT_DIGEST_SUFFIX = ".contextDigest";
    static final int MAX_PIN_FILE_BYTES = 256;
    static final int MAX_CONTEXT_PIN_FILE_BYTES = Plan.MAX_CONTEXT_PINS * MAX_PIN_FILE_BYTES;
    static final int MAX_PIN_FILES = 4096;
    private static final String KUBE_DATA_LINK = "..data";

    private PinsDir() {}

    /**
     * The pins a directory holds.
     *
     * @param fingerprints profile → fingerprint
     * @param context profile → key-context digests
     * @param target the volume's timestamped directory read, or null for a plain directory
     */
    public record Pins(Map<String, String> fingerprints, Map<String, List<String>> context, String target) {}

    /** Reads {@code dir}: refused unless it is absolute, safe to trust, and holds only pin files of their form. */
    public static Pins read(Path dir) throws IOException {
        if (!dir.isAbsolute()) {
            throw new IOException("CIPHERON_PINS_DIR=\"" + dir + "\": an absolute path");
        }
        Path from = dir.normalize();
        String target = null;
        try {
            Path t = Files.readSymbolicLink(from.resolve(KUBE_DATA_LINK));
            String name = t.toString();
            if (!name.startsWith("..") || name.contains("/") || name.equals("..") || name.equals(KUBE_DATA_LINK)) {
                throw new IOException("pins directory " + dir + ": ..data leads to \"" + name + "\", not to a "
                        + "timestamped directory of the volume itself");
            }
            target = name;
            from = from.resolve(name);
        } catch (NoSuchFileException | NotLinkException e) {
            // A plain directory.
        }
        SafeFiles.checkDirectory(from);
        Map<String, String> fps = new TreeMap<>();
        Map<String, List<String>> ctx = new TreeMap<>();
        Set<String> names = new TreeSet<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(from)) {
            for (Path p : ds) {
                names.add(p.getFileName().toString());
                if (names.size() > MAX_PIN_FILES) {
                    throw new IOException("pins directory " + dir + " holds more than " + MAX_PIN_FILES + " entries");
                }
            }
        }
        List<String> errs = new ArrayList<>();
        for (String name : names) {
            if (name.startsWith("..")) {
                continue;
            }
            boolean fp = name.endsWith(FINGERPRINT_SUFFIX);
            boolean cd = name.endsWith(CONTEXT_DIGEST_SUFFIX);
            if (!fp && !cd) {
                errs.add("\"" + name + "\" is neither <profile>" + FINGERPRINT_SUFFIX + " nor <profile>"
                        + CONTEXT_DIGEST_SUFFIX);
                continue;
            }
            String profile = name.substring(0, name.length() - (fp ? FINGERPRINT_SUFFIX : CONTEXT_DIGEST_SUFFIX).length());
            if (profile.isEmpty()) {
                errs.add("\"" + name + "\" names no profile");
                continue;
            }
            String content = new String(SafeFiles.readPublic(from.resolve(name),
                    fp ? MAX_PIN_FILE_BYTES : MAX_CONTEXT_PIN_FILE_BYTES), StandardCharsets.UTF_8).strip();
            if (fp) {
                fps.put(profile, content);
                continue;
            }
            List<String> ds = new ArrayList<>();
            for (String line : content.split("\n")) {
                line = line.strip();
                if (line.isEmpty()) {
                    continue;
                }
                if (!Grammar.validFingerprint(line)) {
                    errs.add(name + " is not a key-context digest per line (sha256: and 64 lowercase hex digits)");
                    ds = null;
                    break;
                }
                ds.add(line);
            }
            if (ds != null && ds.isEmpty()) {
                errs.add(name + " holds no key-context digest");
            } else if (ds != null) {
                ctx.put(profile, List.copyOf(ds));
            }
        }
        if (!errs.isEmpty()) {
            throw new IOException("pins directory " + dir + ": " + String.join("; ", errs));
        }
        return new Pins(Map.copyOf(fps), Map.copyOf(ctx), target);
    }

    /** Checked reads of the files a client trusts: owned by root or this user, written by nobody else. */
    public static final class SafeFiles {
        private SafeFiles() {}

        /** A directory no one but its owner (root or this user) can write, unless it is sticky. */
        static void checkDirectory(Path dir) throws IOException {
            PosixFileAttributes a = posix(dir);
            if (!a.isDirectory()) {
                throw new IOException(dir + " is not a directory");
            }
            checkOwner(dir, a);
            Set<PosixFilePermission> p = a.permissions();
            if (p.contains(PosixFilePermission.OTHERS_WRITE) || p.contains(PosixFilePermission.GROUP_WRITE)) {
                throw new IOException(dir + " can be written by others than its owner");
            }
        }

        /** A regular file anyone may read but only its owner write, at most {@code max} bytes. */
        public static byte[] readPublic(Path file, int max) throws IOException {
            PosixFileAttributes a = posix(file);
            if (!a.isRegularFile()) {
                throw new IOException(file + " is not a regular file");
            }
            Set<PosixFilePermission> p = a.permissions();
            if (p.contains(PosixFilePermission.OTHERS_WRITE) || p.contains(PosixFilePermission.GROUP_WRITE)) {
                throw new IOException(file + " can be written by others than its owner");
            }
            return readBounded(file, a, max);
        }

        /** A private file (a key): a regular file of this user or root, readable by no one else, at most {@code max}. */
        public static byte[] readPrivate(Path file, int max) throws IOException {
            PosixFileAttributes a = posix(file);
            if (!a.isRegularFile()) {
                throw new IOException(file + " is not a regular file");
            }
            checkOwner(file, a);
            for (PosixFilePermission perm : a.permissions()) {
                switch (perm) {
                    case GROUP_READ, GROUP_WRITE, GROUP_EXECUTE, OTHERS_READ, OTHERS_WRITE, OTHERS_EXECUTE ->
                        throw new IOException(file + " can be read or written by others than its owner (chmod 600)");
                    default -> {
                        // The owner's own permissions.
                    }
                }
            }
            return readBounded(file, a, max);
        }

        private static byte[] readBounded(Path file, PosixFileAttributes a, int max) throws IOException {
            if (a.size() > max) {
                throw new IOException(file + " is larger than " + max + " bytes");
            }
            return Files.readAllBytes(file);
        }

        private static PosixFileAttributes posix(Path p) throws IOException {
            try {
                return Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            } catch (UnsupportedOperationException e) {
                throw new IOException(p + ": the file system has no POSIX permissions to check", e);
            }
        }

        private static void checkOwner(Path p, PosixFileAttributes a) throws IOException {
            String owner = a.owner().getName();
            String me = System.getProperty("user.name");
            if (!owner.equals(me) && !owner.equals("root")) {
                throw new IOException(p + " is owned by " + owner + ", not by this user or root");
            }
        }
    }
}
