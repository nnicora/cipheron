package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** The JSON API over HTTP/1.1 on the fake's HTTP socket: the same operations and checks as gRPC's. */
@Tag("fake")
class HttpTest {
    private static FakeServer fake;
    private static final byte[] DATA = "over json".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger,docs:wrapped,people:derived");
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

    private static CipheronClient client() {
        return CipheronClient.builder(fake.httpSocket()).serverUid(fake.uid()).transport(Transport.HTTP)
                .profileFingerprint("ledger", fake.fingerprint("ledger"))
                .profileFingerprint("docs", fake.fingerprint("docs"))
                .profileFingerprint("people", fake.fingerprint("people"))
                .defaultTimeout(Duration.ofSeconds(20)).build();
    }

    @Test
    void everyOperationWorksOverJson() {
        try (CipheronClient c = client()) {
            byte[] aad = "k".getBytes(StandardCharsets.UTF_8);
            byte[] ct = c.encrypt("ledger", DATA, CallOption.associatedData(aad));
            assertArrayEquals(DATA, c.decrypt("ledger", ct, CallOption.associatedData(aad)));
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
    void refusalsAreReadAsOverGrpc() throws IOException {
        try (CipheronClient c = client()) {
            c.encrypt("ledger", DATA);
            Object[][] cases = {
                {"Busy", BusyException.class},
                {"NoWriter", NoWriterException.class},
                {"Internal", InternalException.class},
                {"Unimplemented", UnsupportedException.class},
                {"Overloaded", CipheronException.class},
            };
            for (Object[] k : cases) {
                fake.op("fail", "fault", (String) k[0]);
                @SuppressWarnings("unchecked")
                Class<? extends CipheronException> want = (Class<? extends CipheronException>) k[1];
                assertThrows(want, () -> c.encrypt("ledger", DATA), (String) k[0]);
            }
        }
    }

    @Test
    void anImpostorIsRefusedOverJsonToo() throws IOException {
        try (CipheronClient c = client()) {
            c.encrypt("ledger", DATA);
            fake.op("setMode", "mode", "ForeignResponseSignature");
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
            fake.op("setMode", "mode", "JunkCiphertext");
            assertThrows(BadResponseException.class, () -> c.encrypt("ledger", DATA));
        }
        try (CipheronClient c = CipheronClient.builder(fake.httpSocket()).serverUid(fake.uid() + 7)
                .transport(Transport.HTTP).build()) {
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
        }
    }

    @Test
    void theTransportIsChosenOnce() {
        assertThrows(IllegalArgumentException.class, () -> CipheronClient.builder(fake.httpSocket())
                .serverUid(fake.uid()).transport(Transport.HTTP).transport(Transport.GRPC).build());
        assertEquals(true, Cipheron.isSocketAddress(fake.httpSocket()));
        assertEquals(false, Cipheron.isSocketAddress("cipheron.example:8443"));
    }
}
