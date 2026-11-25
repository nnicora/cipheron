package io.github.nnicora.cipheron;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** The repository's files the tests read: the specification's vectors and frozen set. */
public final class RepoFiles {
    private RepoFiles() {}

    /** The repository's root: the {@code cipheron.repo} property Maven sets, else the parent of the working dir. */
    public static Path root() {
        String p = System.getProperty("cipheron.repo");
        Path root = p != null ? Paths.get(p) : Paths.get("").toAbsolutePath().getParent();
        if (!Files.isDirectory(root.resolve("spec"))) {
            throw new IllegalStateException("not the cipheron repository's root: " + root);
        }
        return root.normalize();
    }

    /** {@code rel} under the repository's root. */
    public static Path path(String rel) {
        return root().resolve(rel);
    }
}
