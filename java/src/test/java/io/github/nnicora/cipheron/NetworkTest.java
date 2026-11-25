package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The network listener over both APIs: the JSON API over mutual TLS, and cipheron refusing this client's certificate
 * in the TLS 1.3 handshake — at once, as {@link CertificateRefusedException}, without marking the client
 * ({@code internal/client/refusal_test.go}).
 */
@Tag("fake")
class NetworkTest {
    private static FakeServer fake;
    private static final byte[] DATA = "over the network".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger,docs:wrapped,people:derived");
        String key = Files.readString(fake.file("requestKey"));
        for (String p : List.of("ledger", "docs", "people")) {
            fake.op("requireRequestKey", "profile", p, "pem", key);
        }
    }

    @AfterAll
    static void stop() throws Exception {
        if (fake != null) {
            fake.close();
        }
    }

    @AfterEach
    void admit() throws IOException {
        fake.refuseCertificates(false);
    }

    private static CipheronClient.Builder network(String address) {
        return CipheronClient.builder(address)
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), fake.file("caFile"))
                .serverSpiffeId(fake.serverId()).requestKeyFile(fake.file("requestKey"))
                .profileFingerprint("ledger", fake.fingerprint("ledger"))
                .profileFingerprint("docs", fake.fingerprint("docs"))
                .profileFingerprint("people", fake.fingerprint("people")).defaultTimeout(Duration.ofSeconds(20));
    }

    @Test
    void everyOperationWorksOverJsonOnMutualTls() {
        try (CipheronClient c = network(fake.httpTls()).transport(Transport.HTTP).build()) {
            byte[] aad = "k".getBytes(StandardCharsets.UTF_8);
            byte[] ct = c.encrypt("ledger", DATA, CallOption.associatedData(aad));
            assertArrayEquals(DATA, c.decrypt("ledger", ct, CallOption.associatedData(aad)));
            assertArrayEquals(DATA, c.decrypt("ledger", c.reEncrypt("ledger", c.encrypt("ledger", DATA))));
            Signature s = c.sign("ledger", DATA);
            assertTrue(c.verify("ledger", DATA, s.bytes(), s.keyId()));
            List<BatchResult> b = c.encryptBatch("ledger", List.of(BatchItem.of(DATA), BatchItem.of(DATA)));
            assertArrayEquals(DATA, c.decryptBatch("ledger", List.of(BatchItem.of(b.get(1).value()))).get(0).value());

            TenantKey k = c.createTenantKey("docs", "acme");
            Tenant t = c.tenant("docs", "acme", k.blob());
            assertArrayEquals(DATA, t.decrypt(t.encrypt(DATA)));
            Tenant p = c.tenant("people", "eve", null);
            assertArrayEquals(DATA, p.decrypt(p.encrypt(DATA)));
        }
    }

    @Test
    void theJsonApiChecksTheServerByHostNameOrSpiffeIdAndItsCa(@TempDir Path dir) throws IOException {
        String port = fake.httpTls().substring(fake.httpTls().lastIndexOf(':') + 1);
        try (CipheronClient c = CipheronClient.builder("localhost:" + port).transport(Transport.HTTP)
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), fake.file("caFile"))
                .requestKeyFile(fake.file("requestKey")).profileFingerprint("ledger", fake.fingerprint("ledger"))
                .defaultTimeout(Duration.ofSeconds(15)).build()) {
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
        }
        Path otherCa = dir.resolve("other.pem");
        Files.writeString(otherCa, Files.readString(fake.file("clientCert")));
        try (CipheronClient c = CipheronClient.builder(fake.httpTls()).transport(Transport.HTTP)
                .tlsFiles(fake.file("clientCert"), fake.file("clientKey"), otherCa)
                .requestKeyFile(fake.file("requestKey")).defaultTimeout(Duration.ofSeconds(15)).build()) {
            long start = System.nanoTime();
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(10)) < 0);
        }
        try (CipheronClient c = network(fake.httpTls()).transport(Transport.HTTP)
                .serverSpiffeId("spiffe://cipheron.test/someone-else").build()) {
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
        }
    }

    @Test
    void aRefusedCertificateFailsGrpcCallsAtOnceAndDoesNotStick() throws Exception {
        // cipheron checks a certificate in the handshake: only a new connection is refused.
        fake.refuseCertificates(true);
        try (CipheronClient c = network(fake.tls()).connections(1).build()) {
            refusedFast(c);
            fake.refuseCertificates(false);
            long start = System.nanoTime();
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(3)) < 0,
                    "the first calls after the client was admitted waited out a backoff");
        }
    }

    @Test
    void aRefusedCertificateFailsJsonCallsAtOnceAndDoesNotStick() throws Exception {
        fake.refuseCertificates(true);
        try (CipheronClient c = network(fake.httpTls()).transport(Transport.HTTP).build()) {
            refusedFast(c);
            fake.refuseCertificates(false);
            assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
        }
    }

    @Test
    void aConnectionMadeBeforeTheRefusalKeepsServing() throws Exception {
        for (Transport t : Transport.values()) {
            try (CipheronClient c = network(t == Transport.HTTP ? fake.httpTls() : fake.tls()).transport(t)
                    .connections(1).build()) {
                assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)));
                fake.refuseCertificates(true);
                assertArrayEquals(DATA, c.decrypt("ledger", c.encrypt("ledger", DATA)), t.name());
                fake.refuseCertificates(false);
            }
        }
    }

    /**
     * Six refused calls in a row, each a fresh connection attempt, then eight at once: every one fails as a refused
     * certificate (which is a permission refusal), well before its deadline.
     */
    private static void refusedFast(CipheronClient c) throws Exception {
        long sequence = System.nanoTime();
        for (int i = 0; i < 6; i++) {
            long start = System.nanoTime();
            CipheronException e = assertThrows(CipheronException.class, () -> c.encrypt("ledger", DATA));
            assertInstanceOf(CertificateRefusedException.class, e, "call " + i);
            assertInstanceOf(PermissionDeniedException.class, e);
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0,
                    "call " + i + " waited");
        }
        assertTrue(Duration.ofNanos(System.nanoTime() - sequence).compareTo(Duration.ofSeconds(5)) < 0,
                "six refused calls waited out the connection backoff");
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<CipheronException>> calls = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                calls.add(pool.submit(() -> assertThrows(CipheronException.class, () -> c.encrypt("ledger", DATA))));
            }
            for (Future<CipheronException> f : calls) {
                assertInstanceOf(CertificateRefusedException.class, f.get());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
