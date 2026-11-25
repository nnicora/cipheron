package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** The Java client against the Go fake over the gRPC unix socket: every operation, checked end to end. */
@Tag("fake")
class SocketRoundTripTest {
    private static FakeServer fake;

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger,people:derived,docs:wrapped");
    }

    @AfterAll
    static void stop() throws Exception {
        if (fake != null) {
            fake.close();
        }
    }

    private static CipheronClient client() {
        return CipheronClient.builder(fake.socket()).serverUid(fake.uid())
                .profileFingerprint("ledger", fake.fingerprint("ledger"))
                .profileFingerprint("people", fake.fingerprint("people"))
                .profileFingerprint("docs", fake.fingerprint("docs"))
                .defaultTimeout(Duration.ofSeconds(20)).build();
    }

    private static final byte[] DATA = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

    @Test
    void aSharedProfileEncryptsDecryptsReEncryptsSignsAndVerifies() {
        try (CipheronClient c = client()) {
            byte[] ct = c.encrypt("ledger", DATA);
            assertEquals(4, Cipheron.keyId(ct).format());
            assertArrayEquals(DATA, c.decrypt("ledger", ct));

            byte[] re = c.reEncrypt("ledger", ct);
            assertArrayEquals(DATA, c.decrypt("ledger", re));

            Signature s = c.sign("ledger", DATA);
            assertTrue(c.verify("ledger", DATA, s.bytes(), s.keyId()));
            assertFalse(c.verify("ledger", "other".getBytes(StandardCharsets.UTF_8), s.bytes(), s.keyId()));

            Keys k = c.keys("ledger");
            assertEquals(Tenancy.SHARED, k.tenancy());
            assertEquals(fake.fingerprint("ledger"), k.fingerprint());
            assertEquals(1, k.fingerprintVersion());
            assertNotNull(k.active());
            assertTrue(Cipheron.verifyWithKeys(k.signingKeys(), DATA, s.bytes(), s.keyId()));
        }
    }

    @Test
    void associatedDataIsBoundAndRequired() {
        try (CipheronClient c = client()) {
            byte[] aad = "row-42".getBytes(StandardCharsets.UTF_8);
            byte[] ct = c.encrypt("ledger", DATA, CallOption.associatedData(aad));
            assertEquals(5, Cipheron.keyId(ct).format());
            assertArrayEquals(DATA, c.decrypt("ledger", ct, CallOption.associatedData(aad)));
            assertThrows(AssociatedDataException.class, () -> c.decrypt("ledger", ct));
            assertThrows(AssociatedDataException.class,
                    () -> c.reEncrypt("ledger", ct, CallOption.associatedData(aad)));
            byte[] re = c.reEncrypt("ledger", ct, CallOption.associatedData(aad),
                    CallOption.targetAssociatedData(aad));
            assertArrayEquals(DATA, c.decrypt("ledger", re, CallOption.associatedData(aad)));
        }
    }

    @Test
    void aDerivedProfilesTenantsAreBoundToTheirTenant() {
        try (CipheronClient c = client()) {
            Tenant alice = c.tenant("people", "alice", null);
            byte[] ct = alice.encrypt(DATA);
            assertArrayEquals(DATA, alice.decrypt(ct));
            Signature s = alice.sign(DATA);
            assertTrue(alice.verify(DATA, s.bytes(), s.keyId()));
            assertFalse(c.tenant("people", "bob", null).verify(DATA, s.bytes(), s.keyId()));
            assertThrows(TenancyException.class, () -> c.encrypt("people", DATA));
        }
    }

    @Test
    void aWrappedProfilesTenantKeysAreCreatedRewrappedAndUsed() {
        try (CipheronClient c = client()) {
            TenantKey key = c.createTenantKey("docs", "acme");
            assertEquals("acme", Cipheron.readTenantKey(key.blob()).tenant());
            Tenant t = c.tenant("docs", "acme", key.blob());
            assertEquals(key.fingerprint(), t.fingerprint());
            byte[] ct = t.encrypt(DATA);
            assertEquals(3, Cipheron.keyId(ct).format());
            assertArrayEquals(DATA, t.decrypt(ct));
            Signature s = t.sign(DATA);
            assertTrue(t.verify(DATA, s.bytes(), s.keyId()));

            TenantKey rewrapped = c.rewrapTenantKey("docs", "acme", key.blob());
            assertArrayEquals(key.keyId(), rewrapped.keyId());
            assertEquals(key.fingerprint(), rewrapped.fingerprint());
            byte[] re = t.reEncrypt(ct, rewrapped.blob());
            assertArrayEquals(DATA, c.tenant("docs", "acme", rewrapped.blob()).decrypt(re));

            assertThrows(TenantKeyException.class, () -> c.tenant("docs", "other", key.blob()).encrypt(DATA));
        }
    }

    @Test
    void aWrongPinIsRefusedAsTheServersIdentity() {
        try (CipheronClient c = CipheronClient.builder(fake.socket()).serverUid(fake.uid())
                .profileFingerprint("ledger", fake.fingerprint("people")).build()) {
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
        }
    }

    @Test
    void aSocketServedByAnotherUidFailsFastAsTheServersIdentity() {
        try (CipheronClient c = CipheronClient.builder(fake.socket()).serverUid(fake.uid() + 1)
                .defaultTimeout(Duration.ofSeconds(20)).build()) {
            long t0 = System.nanoTime();
            assertThrows(ServerIdentityException.class, () -> c.encrypt("ledger", DATA));
            assertTrue(System.nanoTime() - t0 < Duration.ofSeconds(10).toNanos(), "not a timeout");
        }
    }

    @Test
    void aClosedClientRefusesEveryCall() {
        CipheronClient c = client();
        c.close();
        assertThrows(ClosedException.class, () -> c.encrypt("ledger", DATA));
    }
}
