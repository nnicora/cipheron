package io.github.nnicora.cipheron;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The frozen set ({@code spec/frozen/manifest.json}: what cipheron wrote for fixed inputs) through the public offline
 * API: every ciphertext's key, every signature under its listed key (a derived tenant's only for that tenant), every
 * tenant key blob's header. The Go library's {@code frozen_test.go}, in Java.
 */
class FrozenSetTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] hex(JsonObject o, String name) {
        JsonElement e = o.get(name);
        return e == null || e.isJsonNull() ? new byte[0] : HEX.parseHex(e.getAsString());
    }

    private static String str(JsonObject o, String name) {
        JsonElement e = o.get(name);
        return e == null || e.isJsonNull() ? "" : e.getAsString();
    }

    private static void checkKey(JsonObject c, byte[] tenantKeyId) {
        CiphertextKey k = Cipheron.keyId(hex(c, "ciphertext"));
        String want = tenantKeyId != null ? "tenant-key:" + HEX.formatHex(tenantKeyId) : str(c, "version");
        assertEquals(c.get("format").getAsInt(), k.format());
        assertEquals(want, k.toString());
        assertEquals(hex(c, "associatedData").length > 0, k.associatedData());
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void theFrozenSetThroughThePublicApi() throws IOException {
        JsonObject set = JsonParser.parseString(Files.readString(RepoFiles.path("spec/frozen/manifest.json")))
                .getAsJsonObject();
        JsonArray profiles = set.getAsJsonArray("profiles");
        assertEquals(3, profiles.size());
        int n = 0;
        for (JsonElement pe : profiles) {
            JsonObject d = pe.getAsJsonObject();
            String name = str(d, "name");
            Map<String, byte[]> pub = new HashMap<>();
            if (d.has("signingKeys") && !d.get("signingKeys").isJsonNull()) {
                for (JsonElement k : d.getAsJsonArray("signingKeys")) {
                    JsonObject ko = k.getAsJsonObject();
                    pub.put(str(ko, "keyId"), hex(ko, "publicKey"));
                }
            }
            for (JsonElement c : arr(d, "ciphertexts")) {
                checkKey(c.getAsJsonObject(), null);
            }
            for (JsonElement se : arr(d, "signatures")) {
                JsonObject sg = se.getAsJsonObject();
                byte[] p = pub.get(str(sg, "keyId"));
                byte[] data = utf8(str(sg, "data"));
                byte[] sig = hex(sg, "signature");
                String tenant = str(sg, "tenant");
                if (tenant.isEmpty()) {
                    assertTrue(Cipheron.verify(p, data, sig), name + ": " + str(sg, "data"));
                    assertFalse(Cipheron.verifyTenant(p, name, "t", data, sig));
                } else {
                    assertTrue(Cipheron.verifyTenant(p, name, tenant, data, sig), name + "/" + tenant);
                    assertFalse(Cipheron.verifyTenant(p, name, tenant + "x", data, sig));
                    assertFalse(Cipheron.verify(p, data, sig));
                }
                n++;
            }
            for (JsonElement te : arr(d, "tenants")) {
                JsonObject b = te.getAsJsonObject();
                Cipheron.TenantKeyInfo info = Cipheron.readTenantKey(hex(b, "blob"));
                assertEquals(1, info.version());
                assertEquals(name, info.profile());
                assertEquals(str(b, "tenant"), info.tenant());
                assertArrayEquals(hex(b, "keyId"), info.keyId());
                assertEquals(str(b, "fingerprint"), info.fingerprint());
                assertEquals(str(b, "wrappingVersion"), info.wrappingVersion());
                assertEquals(str(b, "created"), DateTimeFormatter.ISO_INSTANT.format(info.created()));
                for (JsonElement c : arr(b, "ciphertexts")) {
                    checkKey(c.getAsJsonObject(), hex(b, "keyId"));
                }
                for (JsonElement se : arr(b, "signatures")) {
                    JsonObject sg = se.getAsJsonObject();
                    assertTrue(Cipheron.verify(info.signingPublicKey(), utf8(str(sg, "data")), hex(sg, "signature")));
                    n++;
                }
            }
        }
        assertEquals(11, n, "the frozen set's signatures");
    }

    private static JsonArray arr(JsonObject o, String name) {
        JsonElement e = o.get(name);
        return e == null || e.isJsonNull() ? new JsonArray() : e.getAsJsonArray();
    }
}
