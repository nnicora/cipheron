package io.github.nnicora.cipheron;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.nnicora.cipheron.internal.wire.KeyStatements;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * A profile's key statement: its identity and signing keys at a moment, signed by its response key. A party that
 * never talks to cipheron checks it against the pin alone ({@link #importExported}) and verifies signatures with
 * it ({@link #verify}). Exported as JSON ({@code "format": "cipheron-key-statement/1"}) or as a JWKS.
 */
public final class KeyStatement {
    /** The export's format token. */
    public static final String FORMAT = "cipheron-key-statement/1";

    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final KeyStatements.Statement st;
    private final String fingerprint;
    private final byte[] raw;
    private final byte[] signature;

    KeyStatement(KeyStatements.Statement st, String fingerprint, byte[] raw, byte[] signature) {
        this.st = st;
        this.fingerprint = fingerprint;
        this.raw = raw.clone();
        this.signature = signature.clone();
    }

    /** The profile. */
    public String profile() {
        return st.profile();
    }

    /** Its tenancy. */
    public Tenancy tenancy() {
        return Tenancy.of(st.identity().tenancy());
    }

    /** When cipheron made it. */
    public Instant issuedAt() {
        return Instant.ofEpochMilli(st.issuedAtMs());
    }

    /** The key-context digest of the cipheron that made it. */
    public String contextDigest() {
        return st.contextDigest();
    }

    /** The identity's fingerprint: the pin it was checked against. */
    public String fingerprint() {
        return fingerprint;
    }

    /** The signing keys it lists. */
    public List<SigningKey> signingKeys() {
        List<SigningKey> out = new ArrayList<>();
        for (SigningKeys.Key k : st.signingKeys()) {
            out.add(CipheronClient.publicKey(k));
        }
        return out;
    }

    /** The statement's bytes. */
    public byte[] raw() {
        return raw.clone();
    }

    /** The response key's signature over {@link #raw}. */
    public byte[] signature() {
        return signature.clone();
    }

    /** The statement as JSON: format, profile, fingerprint, statement and signature (base64). */
    public String export() {
        JsonObject o = new JsonObject();
        o.addProperty("format", FORMAT);
        o.addProperty("profile", st.profile());
        o.addProperty("fingerprint", fingerprint);
        o.addProperty("statement", Base64.getEncoder().encodeToString(raw));
        o.addProperty("signature", Base64.getEncoder().encodeToString(signature));
        return PRETTY.toJson(o);
    }

    /** The usable signing keys as a JWKS (RFC 7517): OKP Ed25519 keys, their id hex. */
    public String jwks() {
        JsonArray keys = new JsonArray();
        for (SigningKeys.Key k : st.signingKeys()) {
            if (!k.usable()) {
                continue;
            }
            JsonObject j = new JsonObject();
            j.addProperty("kty", "OKP");
            j.addProperty("crv", "Ed25519");
            j.addProperty("x", Base64.getUrlEncoder().withoutPadding().encodeToString(k.publicKey()));
            j.addProperty("kid", HexFormat.of().formatHex(k.keyId()));
            j.addProperty("alg", "EdDSA");
            j.addProperty("use", "sig");
            JsonArray ops = new JsonArray();
            ops.add("verify");
            j.add("key_ops", ops);
            keys.add(j);
        }
        JsonObject o = new JsonObject();
        o.add("keys", keys);
        return PRETTY.toJson(o);
    }

    /** Verifies a shared profile's signature with the keys this statement lists, honouring their states. */
    public boolean verify(byte[] data, byte[] sig, byte[] keyId) {
        if (tenancy() != Tenancy.SHARED) {
            throw new TenancyException("cipheron: the call is not one of the profile's tenancy: the key statement of "
                    + "profile \"" + profile() + "\" is " + st.identity().tenancy() + ": verify checks a shared "
                    + "profile's signature (verifyTenant a derived profile's)");
        }
        return Cipheron.verifyWithKeys(signingKeys(), data, sig, keyId);
    }

    /** Verifies a derived profile's tenant's signature with the keys this statement lists. */
    public boolean verifyTenant(String tenant, byte[] data, byte[] sig, byte[] keyId) {
        if (tenancy() != Tenancy.PER_TENANT_DERIVED) {
            throw new TenancyException("cipheron: the call is not one of the profile's tenancy: the key statement of "
                    + "profile \"" + profile() + "\" is " + st.identity().tenancy() + ": verifyTenant checks a derived "
                    + "profile's signature (verify a shared profile's)");
        }
        return Cipheron.verifyTenantWithKeys(signingKeys(), profile(), tenant, data, sig, keyId);
    }

    /**
     * Imports an exported statement and checks it against the pin ({@code fingerprint}) and its age: issued within
     * {@code maxAge} of now, and at most a minute in the future.
     */
    public static KeyStatement importExported(String exported, String profile, String fingerprint, Duration maxAge) {
        if (maxAge.isNegative() || maxAge.isZero()) {
            throw new KeyStatementException("cipheron: not a valid key statement: maxAge is " + maxAge + "; it must be "
                    + "positive (importAnyAge checks no age)");
        }
        KeyStatement s = importAnyAge(exported, profile, fingerprint);
        Duration age = Duration.between(s.issuedAt(), Instant.now());
        if (age.compareTo(maxAge) > 0 || age.compareTo(Duration.ofMinutes(-1)) < 0) {
            throw new KeyStatementException("cipheron: not a valid key statement: issued at " + s.issuedAt()
                    + ", which is not within " + maxAge + " of now");
        }
        return s;
    }

    /** Imports an exported statement and checks it against the pin, whatever its age. */
    public static KeyStatement importAnyAge(String exported, String profile, String fingerprint) {
        JsonObject o;
        try {
            JsonElement e = JsonParser.parseString(exported);
            o = e.getAsJsonObject();
        } catch (RuntimeException e) {
            throw notExported();
        }
        if (!Set.of("format", "profile", "fingerprint", "statement", "signature").containsAll(o.keySet())
                || !o.has("format") || !FORMAT.equals(str(o, "format"))) {
            throw notExported();
        }
        byte[] raw;
        byte[] sig;
        try {
            raw = Base64.getDecoder().decode(str(o, "statement"));
            sig = Base64.getDecoder().decode(str(o, "signature"));
        } catch (IllegalArgumentException e) {
            throw new KeyStatementException("cipheron: not a valid key statement: " + e.getMessage(), e);
        }
        try {
            return new KeyStatement(KeyStatements.verify(raw, sig, profile, fingerprint), fingerprint, raw, sig);
        } catch (KeyStatements.Refused e) {
            throw new KeyStatementException(e.getMessage(), e);
        }
    }

    /** As {@link #importAnyAge}, from the export's bytes. */
    public static KeyStatement importAnyAge(byte[] exported, String profile, String fingerprint) {
        return importAnyAge(new String(exported, StandardCharsets.UTF_8), profile, fingerprint);
    }

    private static String str(JsonObject o, String name) {
        JsonElement e = o.get(name);
        return e == null || !e.isJsonPrimitive() ? "" : e.getAsString();
    }

    private static KeyStatementException notExported() {
        return new KeyStatementException("cipheron: not a valid key statement: not an exported key statement ("
                + FORMAT + ")");
    }
}
