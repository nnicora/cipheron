package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Batches and cross-profile re-encryption against the Go fake: every answer checked as a single one would be. */
@Tag("fake")
class BatchTest {
    private static FakeServer fake;

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger,archive,people:derived,docs:wrapped");
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
    }

    private static CipheronClient client() {
        CipheronClient.Builder b = CipheronClient.builder(fake.socket()).serverUid(fake.uid())
                .defaultTimeout(Duration.ofSeconds(20));
        for (String p : new String[] {"ledger", "archive", "people", "docs"}) {
            b.profileFingerprint(p, fake.fingerprint(p));
        }
        return b.build();
    }

    private static List<BatchItem> items(int n, byte[] aad) {
        List<BatchItem> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(BatchItem.of(("item " + i).getBytes(StandardCharsets.UTF_8), aad));
        }
        return out;
    }

    @Test
    void aSharedBatchRoundTripsItemByItem() {
        try (CipheronClient c = client()) {
            byte[] aad = "rows".getBytes(StandardCharsets.UTF_8);
            List<BatchItem> plain = items(5, aad);
            List<BatchResult> enc = c.encryptBatch("ledger", plain);
            assertEquals(5, enc.size());
            List<BatchItem> cts = new ArrayList<>();
            for (BatchResult r : enc) {
                assertTrue(r.ok());
                assertEquals(5, Cipheron.keyId(r.value()).format());
                cts.add(BatchItem.of(r.value(), aad));
            }
            List<BatchResult> re = c.reEncryptBatch("ledger", cts);
            List<BatchItem> again = new ArrayList<>();
            for (BatchResult r : re) {
                again.add(BatchItem.of(r.value(), aad));
            }
            List<BatchResult> dec = c.decryptBatch("ledger", again);
            for (int i = 0; i < 5; i++) {
                assertArrayEquals(plain.get(i).data(), dec.get(i).value());
            }
        }
    }

    @Test
    void tenantBatchesAndTheRewrapBatchWork() {
        try (CipheronClient c = client()) {
            Tenant bob = c.tenant("people", "bob", null);
            List<BatchResult> enc = bob.encryptBatch(items(3, null));
            List<BatchItem> cts = new ArrayList<>();
            enc.forEach(r -> cts.add(BatchItem.of(r.value())));
            List<BatchResult> dec = bob.decryptBatch(cts);
            assertArrayEquals("item 2".getBytes(StandardCharsets.UTF_8), dec.get(2).value());

            TenantKey k1 = c.createTenantKey("docs", "t1");
            TenantKey k2 = c.createTenantKey("docs", "t2");
            List<TenantKeyResult> rw = c.rewrapTenantKeyBatch("docs",
                    List.of(new TenantKeyRef("t1", k1.blob()), new TenantKeyRef("t2", k2.blob())));
            assertEquals(2, rw.size());
            assertArrayEquals(k1.keyId(), rw.get(0).key().keyId());
            assertEquals(k2.fingerprint(), rw.get(1).key().fingerprint());

            Tenant t1 = c.tenant("docs", "t1", k1.blob());
            List<BatchResult> wenc = t1.encryptBatch(items(2, null));
            List<BatchItem> wct = new ArrayList<>();
            wenc.forEach(r -> wct.add(BatchItem.of(r.value())));
            List<BatchResult> wre = t1.reEncryptBatch(wct, rw.get(0).key().blob());
            assertArrayEquals("item 1".getBytes(StandardCharsets.UTF_8),
                    c.tenant("docs", "t1", rw.get(0).key().blob()).decrypt(wre.get(1).value()));
        }
    }

    @Test
    void aBatchAnswerIsCheckedAsSingleAnswersAre() throws IOException {
        try (CipheronClient c = client()) {
            c.encryptBatch("ledger", items(2, null));
            fake.op("setMode", "mode", "ShortBatch");
            assertThrows(CipheronException.class, () -> c.encryptBatch("ledger", items(3, null)));
            fake.op("setMode", "mode", "JunkCiphertext");
            assertThrows(BadResponseException.class, () -> c.encryptBatch("ledger", items(2, null)));
            fake.op("setMode", "mode", "ForeignResponseSignature");
            assertThrows(ServerIdentityException.class, () -> c.encryptBatch("ledger", items(2, null)));
        }
    }

    @Test
    void aBatchOverTheServersLimitNamesTheLimit() throws IOException {
        try (CipheronClient c = client()) {
            fake.send(limit(3));
            CipheronException e = assertThrows(InvalidInputException.class,
                    () -> c.encryptBatch("ledger", items(4, null)));
            assertEquals(3, e.batchLimits().orElseThrow().maxItems());
            fake.send(limit(128));
            assertThrows(InvalidInputException.class, () -> c.encryptBatch("ledger", List.of()));
        }
    }

    private static com.google.gson.JsonObject limit(int n) {
        com.google.gson.JsonObject o = new com.google.gson.JsonObject();
        o.addProperty("op", "setBatchMaxItems");
        o.addProperty("n", n);
        return o;
    }

    @Test
    void aCiphertextMovesAcrossProfilesSignedByBoth() throws IOException {
        try (CipheronClient c = client()) {
            byte[] ct = c.encrypt("ledger", "move me".getBytes(StandardCharsets.UTF_8));
            com.google.gson.JsonObject g = new com.google.gson.JsonObject();
            g.addProperty("op", "grant");
            g.addProperty("profile", "ledger");
            com.google.gson.JsonArray ops = new com.google.gson.JsonArray();
            for (String o : new String[] {"encrypt", "decrypt", "sign", "reencrypt", "provision", "export", "import",
                    "retenant"}) {
                ops.add(o);
            }
            g.add("ops", ops);
            fake.send(g);
            g.addProperty("profile", "archive");
            fake.send(g);
            byte[] moved = c.reEncryptAcross(Scope.shared("ledger"), Scope.shared("archive"), ct);
            assertArrayEquals("move me".getBytes(StandardCharsets.UTF_8), c.decrypt("archive", moved));
            assertThrows(TenancyException.class,
                    () -> c.reEncryptAcross(Scope.shared("ledger"), Scope.shared("ledger"), ct));
            fake.op("setMode", "mode", "NoSecondSignature");
            assertThrows(ServerIdentityException.class,
                    () -> c.reEncryptAcross(Scope.shared("ledger"), Scope.shared("archive"), ct));
        }
    }
}
