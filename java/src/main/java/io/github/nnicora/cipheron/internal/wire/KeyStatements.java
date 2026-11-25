package io.github.nnicora.cipheron.internal.wire;

import io.github.nnicora.cipheron.internal.crypto.Ed25519;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Key statements: a profile's identity and signing keys at a moment, signed by its response key, which a party that
 * never talks to cipheron can check against the pin alone ({@code wire/transport/statement.go}). A statement is
 * canonical: parsing it and writing it again gives the same bytes, so one statement has one encoding.
 */
public final class KeyStatements {
    /** The statement version this release reads and writes. */
    public static final long VERSION = 1;

    /** The largest statement read. */
    public static final int MAX_LEN = 1 << 20;

    private KeyStatements() {}

    /**
     * A parsed statement.
     *
     * @param profile the profile it is of
     * @param issuedAtMs when it was made, Unix milliseconds
     * @param contextDigest the key-context digest of the cipheron that made it
     * @param identity the profile's identity
     * @param signingKeys the profile's signing keys
     */
    public record Statement(String profile, long issuedAtMs, String contextDigest, Identity identity,
            List<SigningKeys.Key> signingKeys) {}

    /** A refusal of a statement; its message names why. */
    public static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;

        Refused(String why) {
            super("cipheron: not a valid key statement: " + why);
        }
    }

    /** {@code s}'s canonical bytes. */
    public static byte[] marshal(Statement s) throws Refused {
        Identity id = s.identity();
        Lp t = Lp.create().add(Labels.KEY_STATEMENT).addUint32(VERSION).add(s.profile()).add(id.tenancy())
                .add(Bytes.int64(s.issuedAtMs())).add(s.contextDigest()).add(id.effectiveSuite().bytes())
                .add(id.hpke()).addUint32(id.effectiveResponseAlgorithm()).add(id.response())
                .addUint32(id.additional().size());
        for (byte[] e : id.sortedAdditional()) {
            t.raw(e);
        }
        List<SigningKeys.Key> keys = new ArrayList<>(s.signingKeys());
        keys.sort((a, b) -> Arrays.compareUnsigned(a.keyId(), b.keyId()));
        t.addUint32(keys.size());
        for (SigningKeys.Key k : keys) {
            long code = SigningKeys.code(k.state());
            if (code == 0) {
                throw new Refused("a signing key's state is not active, verifyOnly or revoked");
            }
            t.add(k.keyId()).addUint32(code).addUint32(k.effectiveAlgorithm()).add(k.publicKey());
        }
        return t.bytes();
    }

    /**
     * Parses {@code b}: strict (nothing after the last field), the suite and algorithms written and never 0, a
     * profile name, a context digest, a valid identity and signing-key list, and canonical.
     */
    public static Statement parse(byte[] b) throws Refused {
        if (b.length > MAX_LEN) {
            throw new Refused("more than " + MAX_LEN + " bytes");
        }
        Reader r = new Reader(b);
        if (!Labels.KEY_STATEMENT.equals(Bytes.string(r.field()))) {
            throw new Refused("not a key statement of version " + VERSION);
        }
        long v = r.uint32();
        if (r.err || v != VERSION) {
            throw new Refused("not a key statement of version " + VERSION);
        }
        String profile = Bytes.string(r.field());
        String tenancy = Bytes.string(r.field());
        byte[] ts = r.field();
        long issuedAt = 0;
        if (ts.length == 8) {
            issuedAt = Bytes.int64(ts, 0);
        } else {
            r.err = true;
        }
        String contextDigest = Bytes.string(r.field());
        Identity.Suite suite = r.suite();
        byte[] hpke = r.field().clone();
        long responseAlgorithm = r.uint32();
        byte[] response = r.field().clone();
        long n = r.uint32();
        if (n > Identity.MAX_ADDITIONAL_KEYS) {
            r.err = true;
        }
        List<Identity.Key> additional = new ArrayList<>();
        for (long i = 0; i < n && !r.err; i++) {
            long role = r.uint32();
            Identity.Suite s = Identity.Suite.NONE;
            long alg = 0;
            if (role == Identity.ROLE_HPKE) {
                s = r.suite();
            } else {
                alg = r.uint32();
            }
            additional.add(new Identity.Key(role, s, alg, r.field().clone()));
        }
        long k = r.uint32();
        if (k > SigningKeys.MAX_SIGNING_KEYS) {
            r.err = true;
        }
        List<SigningKeys.Key> keys = new ArrayList<>();
        for (long i = 0; i < k && !r.err; i++) {
            byte[] keyId = r.field().clone();
            String state = SigningKeys.stateOf(r.uint32());
            long alg = r.uint32();
            byte[] pub = r.field().clone();
            if (alg == 0) {
                r.err = true;
            }
            keys.add(new SigningKeys.Key(keyId, state == null ? "" : state, pub, alg));
        }
        if (r.err || r.remaining() != 0) {
            throw new Refused("malformed");
        }
        if (suite.equals(Identity.Suite.NONE) || responseAlgorithm == 0) {
            throw new Refused("the suite and the response algorithm are written, never 0");
        }
        if (!Grammar.validProfile(profile)) {
            throw new Refused("\"" + profile + "\" is not a profile name");
        }
        if (!Grammar.validFingerprint(contextDigest)) {
            throw new Refused("\"" + contextDigest + "\" is not a key-context digest");
        }
        Identity id = new Identity(tenancy, hpke, suite, response, responseAlgorithm, additional);
        String why = id.validateReceived();
        if (why != null) {
            throw new Refused(why);
        }
        why = SigningKeys.validateReceived(tenancy, keys);
        if (why != null) {
            throw new Refused(why);
        }
        Statement s = new Statement(profile, issuedAt, contextDigest, id, keys);
        if (!Arrays.equals(marshal(s), b)) {
            throw new Refused("not in canonical form");
        }
        return s;
    }

    /**
     * Parses {@code statement} and checks it against the pin: it is {@code profile}'s, its identity is the one
     * {@code fingerprint} names, its response key is Ed25519, and {@code signature} is that key's over it.
     */
    public static Statement verify(byte[] statement, byte[] signature, String profile, String fingerprint)
            throws Refused {
        Statement s = parse(statement);
        if (!s.profile().equals(profile)) {
            throw new Refused("it is profile \"" + s.profile() + "\"'s, not \"" + profile + "\"'s");
        }
        if (!Grammar.validFingerprint(fingerprint) || !s.identity().matches(profile, fingerprint)) {
            throw new Refused("its identity is " + s.identity().fingerprint(profile) + ", not the pinned "
                    + fingerprint);
        }
        if (s.identity().effectiveResponseAlgorithm() != Identity.ALGORITHM_ED25519) {
            throw new Refused("its response key's algorithm is not implemented here");
        }
        if (!Ed25519.verify(s.identity().response(), statement, signature)) {
            throw new Refused("the signature is not the profile's response key's");
        }
        return s;
    }

    /** A reader of length-prefixed fields that remembers the first error. */
    private static final class Reader {
        private final byte[] b;
        private int off;
        boolean err;

        Reader(byte[] b) {
            this.b = b;
        }

        byte[] field() {
            if (err || b.length - off < 4) {
                err = true;
                return Bytes.EMPTY;
            }
            long n = Bytes.uint32(b, off);
            if (n > b.length - off - 4) {
                err = true;
                return Bytes.EMPTY;
            }
            byte[] f = Arrays.copyOfRange(b, off + 4, off + 4 + (int) n);
            off += 4 + (int) n;
            return f;
        }

        long uint32() {
            byte[] f = field();
            if (f.length != 4) {
                err = true;
                return 0;
            }
            return Bytes.uint32(f, 0);
        }

        Identity.Suite suite() {
            byte[] f = field();
            if (f.length != 6) {
                err = true;
                return Identity.Suite.NONE;
            }
            return new Identity.Suite(((f[0] & 0xff) << 8) | (f[1] & 0xff), ((f[2] & 0xff) << 8) | (f[3] & 0xff),
                    ((f[4] & 0xff) << 8) | (f[5] & 0xff));
        }

        int remaining() {
            return b.length - off;
        }
    }
}
