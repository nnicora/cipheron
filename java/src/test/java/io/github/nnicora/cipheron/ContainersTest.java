package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Segmented objects, their streams, and encrypted JSON fields, against the Go fake. */
@Tag("fake")
class ContainersTest {
    private static FakeServer fake;

    @BeforeAll
    static void start() throws Exception {
        fake = FakeServer.start("ledger,people:derived");
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
                .profileFingerprint("people", fake.fingerprint("people")).defaultTimeout(Duration.ofSeconds(30))
                .build();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        new Random(42).nextBytes(b);
        return b;
    }

    @Test
    void anObjectOfManySegmentsRoundTripsAndKeepsItsOrder() {
        try (CipheronClient c = client()) {
            byte[] pt = random(5 * 1024 + 17);
            byte[] aad = "file-7".getBytes(StandardCharsets.UTF_8);
            byte[] obj = c.encryptObject("ledger", pt, CallOption.segmentSize(1024), CallOption.associatedData(aad));
            assertArrayEquals(pt, c.decryptObject("ledger", obj, CallOption.associatedData(aad)));
            byte[] re = c.reEncryptObject("ledger", obj, CallOption.associatedData(aad),
                    CallOption.targetAssociatedData(aad));
            assertArrayEquals(pt, c.decryptObject("ledger", re, CallOption.associatedData(aad)));

            assertThrows(SegmentedException.class, () -> c.decryptObject("ledger", Arrays.copyOf(obj, obj.length - 1),
                    CallOption.associatedData(aad)));
            byte[] other = c.encryptObject("ledger", pt, CallOption.segmentSize(1024), CallOption.associatedData(aad));
            byte[] spliced = obj.clone();
            int at = 4 + 1 + 16 + 8 + 4;
            System.arraycopy(other, at, spliced, at, 100);
            assertThrows(SegmentedException.class, () -> c.decryptObject("ledger", spliced,
                    CallOption.associatedData(aad)));
            assertThrows(SegmentedException.class, () -> c.decryptObject("ledger", obj));

            byte[] empty = c.encryptObject("ledger", new byte[0]);
            assertEquals(0, c.decryptObject("ledger", empty).length);
        }
    }

    @Test
    void streamsWriteWhatObjectsHold() {
        try (CipheronClient c = client()) {
            byte[] pt = random(3 * 1024 + 5);
            ByteArrayOutputStream enc = new ByteArrayOutputStream();
            long n = c.encryptStream("ledger", enc, new ByteArrayInputStream(pt), pt.length,
                    CallOption.segmentSize(1024));
            assertEquals(enc.size(), n);
            assertArrayEquals(pt, c.decryptObject("ledger", enc.toByteArray()));

            ByteArrayOutputStream dec = new ByteArrayOutputStream();
            assertEquals(pt.length, c.decryptStream("ledger", dec, new ByteArrayInputStream(enc.toByteArray())));
            assertArrayEquals(pt, dec.toByteArray());

            ByteArrayOutputStream re = new ByteArrayOutputStream();
            c.reEncryptStream("ledger", re, new ByteArrayInputStream(enc.toByteArray()));
            assertArrayEquals(pt, c.decryptObject("ledger", re.toByteArray()));

            assertThrows(InvalidInputException.class, () -> c.encryptStream("ledger", new ByteArrayOutputStream(),
                    new ByteArrayInputStream(pt), pt.length + 1, CallOption.segmentSize(1024)));
        }
    }

    @Test
    void jsonFieldsAreEncryptedInPlaceAndBoundToTheirRecordAndPointer() {
        try (CipheronClient c = client()) {
            String doc = "{\"name\":\"Ada\",\"card\":{\"pan\":\"4111111111111111\",\"exp\":1234567890123456789},"
                    + "\"tags\":[\"a\",\"b\"],\"note\":\"<b>&</b>\"}";
            List<String> ptrs = List.of("/card/pan", "/card/exp", "/tags/1", "/note");
            byte[] enc = c.encryptJsonFields("ledger", doc.getBytes(StandardCharsets.UTF_8), "user-1", ptrs);
            JsonObject e = JsonParser.parseString(new String(enc, StandardCharsets.UTF_8)).getAsJsonObject();
            assertEquals("Ada", e.get("name").getAsString());
            assertTrue(CipheronClient.isJsonField(e.getAsJsonObject("card").get("pan").getAsString()));
            assertFalse(CipheronClient.isJsonField(e.getAsJsonArray("tags").get(0).getAsString()));

            byte[] dec = c.decryptJsonFields("ledger", enc, "user-1", ptrs);
            assertEquals(JsonParser.parseString(doc), JsonParser.parseString(new String(dec, StandardCharsets.UTF_8)));
            assertTrue(new String(dec, StandardCharsets.UTF_8).contains("1234567890123456789"), "a number as written");

            assertThrows(CipheronException.class, () -> c.decryptJsonFields("ledger", enc, "user-2", ptrs));
            assertThrows(JsonFieldException.class, () -> c.encryptJsonFields("ledger", enc, "user-1", ptrs));
            assertThrows(JsonFieldException.class, () -> c.encryptJsonFields("ledger",
                    doc.getBytes(StandardCharsets.UTF_8), "user-1", List.of("/card", "/card/pan")));
            byte[] re = c.reEncryptJsonFields("ledger", enc, "user-1", ptrs);
            assertEquals(JsonParser.parseString(doc), JsonParser.parseString(new String(
                    c.decryptJsonFields("ledger", re, "user-1", ptrs), StandardCharsets.UTF_8)));
        }
    }

    @Test
    void aTenantsObjectsAndFieldsAreItsOwn() {
        try (CipheronClient c = client()) {
            Tenant ann = c.tenant("people", "ann", null);
            byte[] pt = random(2500);
            byte[] obj = ann.encryptObject(pt, CallOption.segmentSize(1024));
            assertArrayEquals(pt, ann.decryptObject(obj));
            assertThrows(CipheronException.class, () -> c.tenant("people", "ben", null).decryptObject(obj));
            byte[] f = ann.encryptJsonFields("{\"ssn\":\"123\"}".getBytes(StandardCharsets.UTF_8), "r",
                    List.of("/ssn"));
            assertEquals("{\"ssn\":\"123\"}", new String(ann.decryptJsonFields(f, "r", List.of("/ssn")),
                    StandardCharsets.UTF_8));
        }
    }
}
