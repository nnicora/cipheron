package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Key statements: handed out by a client, imported by a party that only holds the pin, and verified offline. */
@Tag("fake")
class KeyStatementTest {
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

    @Test
    void aStatementTravelsAndVerifiesOffline() {
        byte[] data = "contract".getBytes(StandardCharsets.UTF_8);
        String pin = fake.fingerprint("ledger");
        try (CipheronClient c = CipheronClient.builder(fake.socket()).serverUid(fake.uid())
                .profileFingerprint("ledger", pin).defaultTimeout(Duration.ofSeconds(15)).build()) {
            Signature s = c.sign("ledger", data);
            KeyStatement st = c.keyStatement("ledger");
            assertEquals("ledger", st.profile());
            assertEquals(pin, st.fingerprint());
            String exported = st.export();
            assertEquals(KeyStatement.FORMAT,
                    JsonParser.parseString(exported).getAsJsonObject().get("format").getAsString());

            KeyStatement imported = KeyStatement.importExported(exported, "ledger", pin, Duration.ofMinutes(5));
            assertTrue(imported.verify(data, s.bytes(), s.keyId()));
            assertFalse(imported.verify("other".getBytes(StandardCharsets.UTF_8), s.bytes(), s.keyId()));
            assertTrue(imported.jwks().contains("\"crv\": \"Ed25519\""));

            assertThrows(KeyStatementException.class,
                    () -> KeyStatement.importAnyAge(exported, "ledger", fake.fingerprint("people")));
            assertThrows(KeyStatementException.class,
                    () -> KeyStatement.importAnyAge(exported, "people", pin));
            String tampered = exported.replace("\"statement\": \"", "\"statement\": \"AA");
            assertThrows(KeyStatementException.class, () -> KeyStatement.importAnyAge(tampered, "ledger", pin));
            assertThrows(KeyStatementException.class,
                    () -> KeyStatement.importExported(exported, "ledger", pin, Duration.ZERO));
        }
    }
}
