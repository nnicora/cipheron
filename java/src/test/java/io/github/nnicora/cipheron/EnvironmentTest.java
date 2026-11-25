package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The sidecar's environment, the pins directory and its live reload, and the files a client trusts. */
@Tag("fake")
class EnvironmentTest {
    private static FakeServer fake;
    private static final byte[] DATA = "env".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger");
    }

    @AfterAll
    static void stop() throws Exception {
        if (fake != null) {
            fake.close();
        }
    }

    private static Path pins(Path dir, String fingerprint) throws IOException {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
        Path f = dir.resolve("ledger.fingerprint");
        Path tmp = dir.resolve(".tmp");
        Files.writeString(tmp, fingerprint + "\n");
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        return dir;
    }

    @Test
    void theEnvironmentConfiguresASidecarClient(@TempDir Path dir) throws IOException {
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> CipheronClient.builder("").environment(Map.of()).build());
        assertTrue(missing.getMessage().contains("CIPHERON_SOCKET"));
        assertTrue(missing.getMessage().contains("CIPHERON_PINS_DIR"), "production requires pins");

        try (CipheronClient c = CipheronClient.builder("").environment(Map.of("CIPHERON_SOCKET", fake.socket(),
                "CIPHERON_SERVER_UID", Long.toString(fake.uid()), "CIPHERON_ENVIRONMENT", "development")).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
        }
        pins(dir, fake.fingerprint("ledger"));
        try (CipheronClient c = CipheronClient.builder("").environment(Map.of("CIPHERON_SOCKET", fake.socket(),
                "CIPHERON_SERVER_UID", Long.toString(fake.uid()), "CIPHERON_PINS_DIR", dir.toString())).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
            assertThrows(PinRequiredException.class, () -> c.encrypt("other", DATA), "production requires a pin");
        }
    }

    @Test
    void aRotatedPinIsAdoptedWithoutARestart(@TempDir Path dir) throws Exception {
        pins(dir, fake.fingerprint("ledger"));
        try (CipheronClient c = CipheronClient.builder(fake.socket()).serverUid(fake.uid()).pinsDir(dir)
                .pinsReloadInterval(Duration.ofMillis(100)).defaultTimeout(Duration.ofSeconds(10)).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
            pins(dir, "sha256:" + "0".repeat(64));
            Thread.sleep(600);
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
            pins(dir, fake.fingerprint("ledger"));
            Thread.sleep(600);
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
        }
    }

    @Test
    void aKeyFileOthersCanReadIsRefused(@TempDir Path dir) throws IOException {
        Path key = dir.resolve("request.key");
        Files.copy(fake.file("requestKey"), key);
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-r--r--"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CipheronClient.builder(fake.socket()).serverUid(fake.uid()).requestKeyFile(key).build());
        assertTrue(e.getMessage().contains("chmod 600"), e.getMessage());
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
        CipheronClient.builder(fake.socket()).serverUid(fake.uid()).requestKeyFile(key).build().close();
    }
}
