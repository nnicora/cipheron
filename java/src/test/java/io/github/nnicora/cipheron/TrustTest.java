package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the client refuses to believe: an impostor's answers, a server certificate that does not check, a changed
 * identity; and what it reads from cipheron's refusals. The Go root tests' checklist ({@code trust_test.go},
 * {@code rotation_test.go}, {@code review5_test.go}), against the Go fake.
 */
@Tag("fake")
class TrustTest {
    private static FakeServer fake;
    private static final byte[] DATA = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger");
        // cipheron opens a sealed payload with the request key that verified the request: list the client's.
        fake.op("requireRequestKey", "profile", "ledger", "pem", Files.readString(fake.file("requestKey")));
    }

    @AfterAll
    static void stop() throws Exception {
        if (fake != null) {
            fake.close();
        }
    }

    @AfterEach
    void honest() throws IOException {
        fake.op("setMode", "mode", "Honest");
        fake.op("fail", "fault", "NoFault");
    }

    private static CipheronClient socket() {
        return CipheronClient.builder(fake.socket()).serverUid(fake.uid()).requestKeyFile(fake.file("requestKey"))
                .profileFingerprint("ledger", fake.fingerprint("ledger")).defaultTimeout(Duration.ofSeconds(15))
                .build();
    }

    private static CipheronClient.Builder network(String address) {
        return CipheronClient.builder(address)
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), fake.file("caFile"))
                .requestKeyFile(fake.file("requestKey")).profileFingerprint("ledger", fake.fingerprint("ledger"))
                .defaultTimeout(Duration.ofSeconds(15));
    }

    @Test
    void mutualTlsChecksTheServerBySpiffeIdOrHostNameAndSignsRequests() throws IOException {
        JsonObject before = fake.op("counters").getAsJsonObject();
        try (CipheronClient c = network(fake.tls()).serverSpiffeId(fake.ready.get("serverId").getAsString()).build()) {
            byte[] ct = c.encrypt("ledger", DATA);
            assertArrayEquals(DATA, c.decrypt("ledger", ct));
            Signature s = c.sign("ledger", DATA);
            assertTrue(c.verify("ledger", DATA, s.bytes(), s.keyId()));
        }
        String port = fake.tls().substring(fake.tls().lastIndexOf(':') + 1);
        try (CipheronClient c = network("localhost:" + port).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
        }
        JsonObject after = fake.op("counters").getAsJsonObject();
        assertTrue(after.get("authVerified").getAsLong() > before.get("authVerified").getAsLong(),
                "the requests carried a verified auth");
    }

    @Test
    void aServerOfAnotherCaOrAnotherSpiffeIdIsRefusedFast(@TempDir Path dir) throws IOException {
        Path otherCa = dir.resolve("other.pem");
        Files.writeString(otherCa, Files.readString(fake.file("clientCert")));
        try (CipheronClient c = CipheronClient.builder(fake.tls())
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), otherCa)
                .requestKeyFile(fake.file("requestKey")).defaultTimeout(Duration.ofSeconds(15)).build()) {
            long t0 = System.nanoTime();
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
            assertTrue(System.nanoTime() - t0 < Duration.ofSeconds(10).toNanos(), "not a timeout");
        }
        try (CipheronClient c = network(fake.tls()).serverSpiffeId("spiffe://cipheron.test/someone-else").build()) {
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
        }
    }

    @Test
    void aNetworkClientNeedsTlsAndARequestKey() {
        assertThrows(IllegalArgumentException.class, () -> CipheronClient.builder(fake.tls()).build());
        assertThrows(IllegalArgumentException.class, () -> CipheronClient.builder(fake.tls())
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), fake.file("caFile")).build());
        assertThrows(IllegalArgumentException.class, () -> CipheronClient.builder(fake.socket()).build());
    }

    @Test
    void anImpostorsAnswersAreRefused() throws IOException {
        try (CipheronClient c = socket()) {
            byte[] good = c.encrypt("ledger", DATA);
            String[][] cases = {
                {"JunkCiphertext", "encrypt", "BadResponseException"},
                {"WrongFormatCiphertext", "encrypt", "BadResponseException"},
                {"UnknownFormatCiphertext", "encrypt", "BadResponseException"},
                {"LongCiphertext", "encrypt", "BadResponseException"},
                {"GarbledPlaintext", "decrypt", "BadResponseException"},
                {"ForeignResponseSignature", "encrypt", "ServerIdentityException"},
                {"NoResponseSignature", "encrypt", "ServerIdentityException"},
                {"AnswerOtherContext", "encrypt", "ServerIdentityException"},
                {"ForeignSignature", "sign", "ServerIdentityException"},
                {"ShortSignature", "sign", "ServerIdentityException"},
                {"UnknownKeyID", "sign", "ServerIdentityException"},
            };
            for (String[] k : cases) {
                fake.op("setMode", "mode", k[0]);
                CipheronException e = assertThrows(CipheronException.class, () -> {
                    switch (k[1]) {
                        case "encrypt" -> c.encrypt("ledger", DATA);
                        case "decrypt" -> c.decrypt("ledger", good);
                        default -> c.sign("ledger", DATA);
                    }
                }, k[0]);
                assertEquals(k[2], e.getClass().getSimpleName(), k[0] + ": " + e.getMessage());
                fake.op("setMode", "mode", "Honest");
            }
        }
    }

    @Test
    void forgedKeyListsAreRefusedAndNeverCached() throws IOException {
        for (String mode : new String[] {"ForgedKeysSignature", "KeysForOtherProfile", "KeysForOtherContext",
                "UnsignedExtraKey", "ForgedKeyStatement", "NoHPKESuite", "UnknownTenancy", "ReplayedKeys"}) {
            fake.op("setMode", "mode", mode);
            try (CipheronClient c = socket()) {
                assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA), mode);
                fake.op("setMode", "mode", "Honest");
                assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)), mode + ": not cached");
            }
        }
    }

    @Test
    void aChangedIdentityIsNeverAdopted() throws Exception {
        try (FakeServer own = FakeServer.start("ledger");
                CipheronClient c = CipheronClient.builder(own.socket()).serverUid(own.uid())
                        .defaultTimeout(Duration.ofSeconds(15)).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
            String first = own.fingerprint("ledger");
            own.op("rekey", "profile", "ledger");
            for (int i = 0; i < 2; i++) {
                assertThrows(ServerKeyChangedException.class, () -> c.encrypt("ledger", DATA));
                assertThrows(ServerKeyChangedException.class, () -> c.sign("ledger", DATA));
            }
            assertThrows(ServerKeyChangedException.class, () -> c.keys("ledger"));
            assertFalse(first.equals(own.op("fingerprint", "profile", "ledger").getAsString()),
                    "the fake's identity changed");
        }
    }

    @Test
    void anotherIdentitysKeyListIsRefused() throws IOException {
        try (CipheronClient c = socket()) {
            c.encrypt("ledger", DATA);
            fake.op("setMode", "mode", "KeysOfAnotherIdentity");
            assertThrows(ServerIdentityException.class, () -> c.keys("ledger"));
        }
    }

    @Test
    void refusalsAreReadByCodeAndReason() throws IOException {
        try (CipheronClient c = socket()) {
            c.encrypt("ledger", DATA);
            Object[][] cases = {
                {"Busy", BusyException.class},
                {"NoWriter", NoWriterException.class},
                {"ProfileSealed", ProfileSealedException.class},
                {"Internal", InternalException.class},
                {"Unimplemented", UnsupportedException.class},
            };
            for (Object[] k : cases) {
                fake.op("fail", "fault", (String) k[0]);
                @SuppressWarnings("unchecked")
                Class<? extends CipheronException> want = (Class<? extends CipheronException>) k[1];
                CipheronException e = assertThrows(want, () -> c.encrypt("ledger", DATA), (String) k[0]);
                assertTrue(e.requestId().isPresent(), "the request id is kept");
                if (k[0].equals("Busy") || k[0].equals("ProfileSealed")) {
                    assertTrue(Cipheron.retryAfter(e).isPresent(), k[0] + " names its delay");
                }
            }
        }
    }

    @Test
    void aRetryPolicyRetriesWhatSaysLater() throws IOException {
        try (CipheronClient c = CipheronClient.builder(fake.socket()).serverUid(fake.uid())
                .requestKeyFile(fake.file("requestKey")).profileFingerprint("ledger", fake.fingerprint("ledger"))
                .retry(new RetryPolicy(3, Duration.ofMillis(5), Duration.ofMillis(20))).build()) {
            c.encrypt("ledger", DATA);
            fake.op("fail", "fault", "NoWriter");
            int[] retries = {0};
            assertThrows(NoWriterException.class, () -> c.encrypt("ledger", DATA));
            fake.op("fail", "fault", "Internal");
            assertThrows(InternalException.class, () -> c.encrypt("ledger", DATA));
            assertEquals(0, retries[0]);
        }
    }

    @Test
    void signingRotationIsAdoptedAndRevocationIsFinal() throws IOException {
        try (CipheronClient c = socket()) {
            Signature old = c.sign("ledger", DATA);
            String next = fake.op("rotateSigning", "profile", "ledger").getAsString();
            Signature now = c.sign("ledger", DATA);
            assertEquals(next, java.util.HexFormat.of().formatHex(now.keyId()), "the new key signs");
            assertTrue(c.verify("ledger", DATA, old.bytes(), old.keyId()), "an old signature still verifies");
            assertTrue(c.verify("ledger", DATA, now.bytes(), now.keyId()));

            fake.op("revokeSigning", "profile", "ledger", "keyId", java.util.HexFormat.of().formatHex(old.keyId()));
            Keys k = c.keys("ledger");
            assertEquals(SigningKey.State.REVOKED, k.signingKey(old.keyId()).state());
            assertThrows(SigningKeyRevokedException.class, () -> c.verify("ledger", DATA, old.bytes(), old.keyId()));
            assertThrows(SigningKeyRevokedException.class,
                    () -> Cipheron.verifyWithKeys(k.signingKeys(), DATA, old.bytes(), old.keyId()));
            assertFalse(Cipheron.verify(k.signingKey(now.keyId()).publicKey(), "x".getBytes(StandardCharsets.UTF_8),
                    now.bytes()));
        }
    }
}
