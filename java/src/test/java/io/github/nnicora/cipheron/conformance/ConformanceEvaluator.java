package io.github.nnicora.cipheron.conformance;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import io.github.nnicora.cipheron.internal.crypto.Ed25519;
import io.github.nnicora.cipheron.internal.wire.AssociatedData;
import io.github.nnicora.cipheron.internal.wire.Bytes;
import io.github.nnicora.cipheron.internal.wire.Ciphertexts;
import io.github.nnicora.cipheron.internal.wire.Digests;
import io.github.nnicora.cipheron.internal.wire.Grammar;
import io.github.nnicora.cipheron.internal.wire.Identity;
import io.github.nnicora.cipheron.internal.wire.KeyStatements;
import io.github.nnicora.cipheron.internal.wire.Refusals;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;
import io.github.nnicora.cipheron.internal.wire.TenantKeys;
import io.github.nnicora.cipheron.internal.wire.Transcripts;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The conformance kit's kinds, computed by this library ({@code spec/api.md}, "Conformance kit"). Each case's input
 * is read strictly — a field the kind does not have, or a hex string with an upper-case digit, is an error, as the
 * reference's decoder has it — and its output is the JSON value a conforming implementation computes.
 */
public final class ConformanceEvaluator {
    private static final Map<String, Integer> STATUS_CODES = Map.ofEntries(Map.entry("OK", 0),
            Map.entry("CANCELLED", 1), Map.entry("UNKNOWN", 2), Map.entry("INVALID_ARGUMENT", 3),
            Map.entry("DEADLINE_EXCEEDED", 4), Map.entry("NOT_FOUND", 5), Map.entry("ALREADY_EXISTS", 6),
            Map.entry("PERMISSION_DENIED", 7), Map.entry("RESOURCE_EXHAUSTED", 8),
            Map.entry("FAILED_PRECONDITION", 9), Map.entry("ABORTED", 10), Map.entry("OUT_OF_RANGE", 11),
            Map.entry("UNIMPLEMENTED", 12), Map.entry("INTERNAL", 13), Map.entry("UNAVAILABLE", 14),
            Map.entry("DATA_LOSS", 15), Map.entry("UNAUTHENTICATED", 16));

    private ConformanceEvaluator() {}

    /** A case's input that the kind refuses to read (an error answer, never a refusal). */
    public static final class BadInput extends Exception {
        private static final long serialVersionUID = 1L;

        BadInput(String why) {
            super(why);
        }
    }

    /** The output of a case of {@code kind} with {@code input}. */
    public static JsonObject evaluate(String kind, JsonObject in) throws BadInput {
        switch (kind) {
            case "digest": {
                fields(in, "fields");
                JsonArray a = array(in, "fields");
                byte[][] f = new byte[a.size()][];
                for (int i = 0; i < a.size(); i++) {
                    f[i] = hex(a.get(i));
                }
                return obj("digest", Digests.digest(f));
            }
            case "requestTranscript": {
                fields(in, "profile", "operation", "timestampMs", "nonce", "digest");
                return obj("transcript", Transcripts.request(str(in, "profile"), str(in, "operation"),
                        int64(in, "timestampMs"), hex(in, "nonce"), digest32(hex(in, "digest"))));
            }
            case "requestSignature":
            case "responseSignature": {
                fields(in, "publicKey", "transcript", "signature");
                return valid(Ed25519.verify(hex(in, "publicKey"), hex(in, "transcript"), hex(in, "signature")));
            }
            case "requestSealInfo": {
                fields(in, "profile", "operation", "tenant", "requestPublicKey");
                return obj("info", Transcripts.requestSealInfo(str(in, "profile"), str(in, "operation"),
                        str(in, "tenant"), hex(in, "requestPublicKey")));
            }
            case "responseSealInfo": {
                fields(in, "profile", "operation", "tenant");
                return obj("info", Transcripts.responseSealInfo(str(in, "profile"), str(in, "operation"),
                        str(in, "tenant")));
            }
            case "responseTranscript": {
                fields(in, "profile", "contextDigest", "operation", "requestNonce", "requestSignature",
                        "requestDigest", "responseDigest");
                return obj("transcript", Transcripts.response(str(in, "profile"), str(in, "contextDigest"),
                        str(in, "operation"), hex(in, "requestNonce"), hex(in, "requestSignature"),
                        digest32(hex(in, "requestDigest")), digest32(hex(in, "responseDigest"))));
            }
            case "signingKeysTranscript": {
                fields(in, "profile", "tenancy", "contextDigest", "nonce", "keys");
                List<Transcripts.ReceivedKey> keys = new ArrayList<>();
                for (JsonElement e : array(in, "keys")) {
                    JsonObject k = object(e);
                    fields(k, "keyId", "state", "publicKey");
                    long code = SigningKeys.code(str(k, "state"));
                    if (code == 0) {
                        throw new BadInput("a signing key's state \"" + str(k, "state") + "\" is not one of three");
                    }
                    keys.add(new Transcripts.ReceivedKey(hex(k, "keyId"), code, hex(k, "publicKey")));
                }
                return obj("transcript", Transcripts.signingKeys(str(in, "profile"), str(in, "tenancy"),
                        str(in, "contextDigest"), hex(in, "nonce"), keys));
            }
            case "fingerprint": {
                fields(in, "profile", "tenancy", "hpkeSuite", "hpkePublicKey", "responseAlgorithm",
                        "responsePublicKey", "additional");
                List<Identity.Key> additional = new ArrayList<>();
                if (in.has("additional") && !in.get("additional").isJsonNull()) {
                    for (JsonElement e : array(in, "additional")) {
                        JsonObject a = object(e);
                        fields(a, "role", "suite", "algorithm", "publicKey");
                        additional.add(new Identity.Key(uint(a, "role"), suite(object(a.get("suite"))),
                                uint(a, "algorithm"), hex(a, "publicKey")));
                    }
                }
                Identity id = new Identity(str(in, "tenancy"), hex(in, "hpkePublicKey"),
                        suite(object(in.get("hpkeSuite"))), hex(in, "responsePublicKey"),
                        uint(in, "responseAlgorithm"), additional);
                JsonObject out = new JsonObject();
                out.addProperty("fingerprint", id.fingerprint(str(in, "profile")));
                return out;
            }
            case "keyStatement": {
                fields(in, "statement", "signature", "profile", "fingerprint");
                boolean ok;
                try {
                    KeyStatements.verify(hex(in, "statement"), hex(in, "signature"), str(in, "profile"),
                            str(in, "fingerprint"));
                    ok = true;
                } catch (KeyStatements.Refused e) {
                    ok = false;
                }
                return valid(ok);
            }
            case "ciphertextKeyID": {
                fields(in, "ciphertext");
                try {
                    Ciphertexts.KeyId k = Ciphertexts.parse(hex(in, "ciphertext"));
                    JsonObject out = new JsonObject();
                    out.addProperty("keyId", k.toString());
                    return out;
                } catch (Ciphertexts.Refused e) {
                    return refused();
                }
            }
            case "tenantKey": {
                fields(in, "blob", "profile", "tenant");
                try {
                    TenantKeys.Header h = TenantKeys.check(hex(in, "blob"), str(in, "profile"), str(in, "tenant"));
                    JsonObject out = new JsonObject();
                    out.addProperty("keyId", Bytes.hex(h.keyId()));
                    out.addProperty("signingPublicKey", Bytes.hex(h.signingPublicKey()));
                    out.addProperty("wrappingVersion", h.wrappingVersion());
                    out.addProperty("created", h.created());
                    out.addProperty("fingerprint", h.fingerprint());
                    return out;
                } catch (TenantKeys.Refused e) {
                    return refused();
                }
            }
            case "tenantFingerprint": {
                fields(in, "profile", "tenant", "keyId", "signingPublicKey");
                JsonObject out = new JsonObject();
                out.addProperty("fingerprint", TenantKeys.fingerprint(str(in, "profile"), str(in, "tenant"),
                        hex(in, "keyId"), hex(in, "signingPublicKey")));
                return out;
            }
            case "tenantSignedMessage": {
                fields(in, "profile", "tenant", "data");
                return obj("message", TenantKeys.signedMessage(str(in, "profile"), str(in, "tenant"),
                        hex(in, "data")));
            }
            case "tenantId": {
                fields(in, "tenant");
                return valid(Grammar.validTenant(str(in, "tenant")));
            }
            case "errorClass": {
                fields(in, "code", "errorInfo", "retryDelayMs");
                Integer code = STATUS_CODES.get(str(in, "code"));
                if (code == null) {
                    throw new BadInput("\"" + str(in, "code") + "\" is not a status code's canonical name");
                }
                String domain = null;
                String reason = null;
                if (in.has("errorInfo") && !in.get("errorInfo").isJsonNull()) {
                    JsonObject ei = object(in.get("errorInfo"));
                    fields(ei, "domain", "reason");
                    domain = str(ei, "domain");
                    reason = str(ei, "reason");
                }
                Refusals.Class c = Refusals.classify(code, domain, reason);
                long wait = 0;
                if (in.has("retryDelayMs") && !in.get("retryDelayMs").isJsonNull()
                        && c.retry() != Refusals.Retry.NEVER) {
                    wait = int64(in, "retryDelayMs");
                    if (wait < 0) {
                        throw new BadInput("a RetryInfo delay is not negative");
                    }
                }
                JsonObject out = new JsonObject();
                out.addProperty("class", c.name());
                out.addProperty("retry", c.retry().wire());
                out.addProperty("minWaitMs", wait);
                return out;
            }
            case "signingKeyID": {
                fields(in, "algorithm", "publicKey");
                return obj("keyId", SigningKeys.keyIdOf(uint(in, "algorithm"), hex(in, "publicKey")));
            }
            case "segmentAssociatedData": {
                fields(in, "objectId", "index", "final", "associatedData");
                return obj("associatedData", AssociatedData.segment(hex(in, "objectId"), uint(in, "index"),
                        bool(in, "final"), hex(in, "associatedData")));
            }
            case "jsonFieldAssociatedData": {
                fields(in, "recordId", "pointer", "associatedData");
                return obj("associatedData", AssociatedData.jsonField(str(in, "recordId"), str(in, "pointer"),
                        hex(in, "associatedData")));
            }
            case "reEncryptAssociatedData": {
                fields(in, "associatedData", "toAssociatedData");
                return valid(Ciphertexts.checkReEncryptAssociatedData(hex(in, "associatedData"),
                        hex(in, "toAssociatedData")) == null);
            }
            default:
                return null;
        }
    }

    private static Identity.Suite suite(JsonObject s) throws BadInput {
        fields(s, "kem", "kdf", "aead");
        return new Identity.Suite((int) uint(s, "kem"), (int) uint(s, "kdf"), (int) uint(s, "aead"));
    }

    private static JsonObject obj(String name, byte[] value) {
        JsonObject out = new JsonObject();
        out.addProperty(name, Bytes.hex(value));
        return out;
    }

    private static JsonObject valid(boolean v) {
        JsonObject out = new JsonObject();
        out.addProperty("valid", v);
        return out;
    }

    private static JsonObject refused() {
        JsonObject out = new JsonObject();
        out.addProperty("refused", true);
        return out;
    }

    /** Refuses a field of {@code o} that is not one of {@code allowed}. */
    private static void fields(JsonObject o, String... allowed) throws BadInput {
        Set<String> a = Set.of(allowed);
        for (String k : o.keySet()) {
            if (!a.contains(k)) {
                throw new BadInput("json: unknown field \"" + k + "\"");
            }
        }
    }

    private static JsonObject object(JsonElement e) throws BadInput {
        if (e == null || !e.isJsonObject()) {
            throw new BadInput("not a JSON object");
        }
        return e.getAsJsonObject();
    }

    private static JsonArray array(JsonObject o, String name) throws BadInput {
        JsonElement e = o.get(name);
        if (e == null || e.isJsonNull()) {
            return new JsonArray();
        }
        if (!e.isJsonArray()) {
            throw new BadInput(name + " is not an array");
        }
        return e.getAsJsonArray();
    }

    private static String str(JsonObject o, String name) throws BadInput {
        JsonElement e = o.get(name);
        if (e == null || e.isJsonNull()) {
            return "";
        }
        if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
            throw new BadInput(name + " is not a string");
        }
        return e.getAsString();
    }

    private static byte[] hex(JsonObject o, String name) throws BadInput {
        JsonElement e = o.get(name);
        if (e == null || e.isJsonNull()) {
            return Bytes.EMPTY;
        }
        return hex(e);
    }

    private static byte[] hex(JsonElement e) throws BadInput {
        if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
            throw new BadInput("a byte string is a hex string");
        }
        String s = e.getAsString();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                throw new BadInput("hex \"" + s + "\": lower-case only");
            }
        }
        if (s.length() % 2 != 0) {
            throw new BadInput("hex \"" + s + "\": odd length");
        }
        return Bytes.unhex(s);
    }

    private static long int64(JsonObject o, String name) throws BadInput {
        JsonElement e = o.get(name);
        if (e == null || e.isJsonNull()) {
            return 0;
        }
        JsonPrimitive p = e.isJsonPrimitive() ? e.getAsJsonPrimitive() : null;
        if (p == null || !p.isNumber()) {
            throw new BadInput(name + " is not a number");
        }
        try {
            return p.getAsBigDecimal().longValueExact();
        } catch (ArithmeticException ex) {
            throw new BadInput(name + " is not an integer");
        }
    }

    private static long uint(JsonObject o, String name) throws BadInput {
        long v = int64(o, name);
        if (v < 0 || v > 0xffffffffL) {
            throw new BadInput(name + " is not a 32-bit unsigned integer");
        }
        return v;
    }

    private static boolean bool(JsonObject o, String name) throws BadInput {
        JsonElement e = o.get(name);
        if (e == null || e.isJsonNull()) {
            return false;
        }
        if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isBoolean()) {
            throw new BadInput(name + " is not a boolean");
        }
        return e.getAsBoolean();
    }

    private static byte[] digest32(byte[] b) throws BadInput {
        if (b.length != 32) {
            throw new BadInput("a digest is 32 bytes");
        }
        return b;
    }
}
