package io.github.nnicora.cipheron;

import io.github.nnicora.cipheron.internal.client.Core;
import io.github.nnicora.cipheron.internal.client.Dial;
import io.github.nnicora.cipheron.internal.client.Endpoint;
import io.github.nnicora.cipheron.internal.client.Plan;
import io.github.nnicora.cipheron.internal.client.RpcFailure;
import io.github.nnicora.cipheron.internal.crypto.Ed25519;
import io.github.nnicora.cipheron.internal.wire.Grammar;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * A client of cipheron: it encrypts, decrypts, re-encrypts and signs through a cipheron, and checks every answer —
 * the profile's identity against its pin, every answer's signature, every ciphertext's format — before it returns it.
 *
 * <pre>{@code
 * try (CipheronClient c = CipheronClient.builder("/run/cipheron/c.sock")
 *         .serverUid(10443)
 *         .profileFingerprint("ledger", "sha256:…")
 *         .build()) {
 *     byte[] ct = c.encrypt("ledger", plaintext);
 *     byte[] pt = c.decrypt("ledger", ct);
 * }
 * }</pre>
 *
 * A client is safe for concurrent use; it connects on its first call. Every call has a deadline: the builder's
 * {@code defaultTimeout} (30 seconds) unless the call names one ({@link CallOption#timeout}).
 */
public final class CipheronClient implements AutoCloseable {
    private final Core core;

    private CipheronClient(Core core) {
        this.core = core;
    }

    /** A builder of a client of the cipheron at {@code address}: a socket path, or {@code host:port}. */
    public static Builder builder(String address) {
        return new Builder(address);
    }

    /** Closes the client's connections; every later call fails with {@link ClosedException}. Idempotent. */
    @Override
    public void close() {
        core.close();
    }

    // ── calls ────────────────────────────────────────────────────────────────────────────────────────────

    @FunctionalInterface
    interface Body<T> {
        T run(Core.Call call) throws RpcFailure;
    }

    <T> T run(Opts o, Body<T> body) {
        Core.Call call = Core.Call.of(o.timeout != null ? o.timeout : core().plan().defaultTimeout());
        try {
            return body.run(call);
        } catch (RpcFailure | RuntimeException e) {
            throw Dial.map(core, call, e);
        }
    }

    Core core() {
        return core;
    }

    /** Encrypts {@code plaintext} under a shared profile: a ciphertext of format 4 (5 with associated data). */
    public byte[] encrypt(String profile, byte[] plaintext, CallOption... opts) {
        Opts o = Opts.of(opts);
        return run(o, call -> core.encrypt(call, profile, plaintext, o.aad));
    }

    /** Decrypts a ciphertext of a shared profile; its associated data, if it has some, is given again. */
    public byte[] decrypt(String profile, byte[] ciphertext, CallOption... opts) {
        Opts o = Opts.of(opts);
        return run(o, call -> core.decrypt(call, profile, ciphertext, o.aad));
    }

    /**
     * Re-encrypts a ciphertext under the profile's current master version, without the plaintext leaving cipheron.
     * A ciphertext made with associated data needs it twice: {@link CallOption#associatedData} and the same bytes as
     * {@link CallOption#targetAssociatedData}.
     */
    public byte[] reEncrypt(String profile, byte[] ciphertext, CallOption... opts) {
        Opts o = Opts.of(opts);
        return run(o, call -> core.reEncrypt(call, profile, ciphertext, o.aad, o.toAad));
    }

    /** Signs {@code data} with the shared profile's active signing key; store the signature and its key id. */
    public Signature sign(String profile, byte[] data, CallOption... opts) {
        Opts o = Opts.of(opts);
        Core.Signed s = run(o, call -> core.sign(call, profile, data));
        return new Signature(s.signature(), s.keyId());
    }

    /**
     * Verifies a signature of a shared profile under the listed key {@code keyId} names: {@code true} or
     * {@code false} on the bytes, or {@link SigningKeyRevokedException}, {@link UnknownSigningKeyException},
     * {@link KeysStaleException} when the key cannot vouch for anything.
     */
    public boolean verify(String profile, byte[] data, byte[] signature, byte[] keyId, CallOption... opts) {
        Opts o = Opts.of(opts);
        return run(o, call -> core.verify(call, profile, data, signature, keyId));
    }

    /** The profile's keys, fetched and verified if this client has none yet. */
    public Keys keys(String profile, CallOption... opts) {
        Opts o = Opts.of(opts);
        Core.ProfileView v = run(o, call -> core.keysOf(call, profile));
        return Cipheron.keysOf(v);
    }

    /**
     * The profile's key statement, as this client verified it: hand it to a party that checks signatures offline
     * ({@link KeyStatement#export}). None is handed out older than the keys' maximum age, or disagreeing with the
     * signing-key list this client holds.
     */
    public KeyStatement keyStatement(String profile, CallOption... opts) {
        Opts o = Opts.of(opts);
        byte[][] rs = new byte[2][];
        io.github.nnicora.cipheron.internal.wire.KeyStatements.Statement st =
                run(o, call -> core.keyStatement(call, profile, rs));
        return new KeyStatement(st, keys(profile, opts).fingerprint(), rs[0], rs[1]);
    }

    /** The key-context digest of the cipheron that last answered the profile's keys. */
    public String contextDigest(String profile, CallOption... opts) {
        return keys(profile, opts).contextDigest();
    }

    /** Creates a wrapped profile's tenant key: never retried, as a second execution makes a second key. */
    public TenantKey createTenantKey(String profile, String tenant, CallOption... opts) {
        Opts o = Opts.of(opts);
        Core.TenantKeyOut t = run(o, call -> core.createTenantKeyCall(call, profile, tenant));
        return new TenantKey(t.blob(), t.keyId(), t.signingPublicKey(), t.fingerprint());
    }

    /** Rewraps a tenant key under the profile's current master version: the same key, a new blob. */
    public TenantKey rewrapTenantKey(String profile, String tenant, byte[] blob, CallOption... opts) {
        Opts o = Opts.of(opts);
        Core.TenantKeyOut t = run(o, call -> core.rewrapTenantKeyCall(call, profile, tenant, blob));
        return new TenantKey(t.blob(), t.keyId(), t.signingPublicKey(), t.fingerprint());
    }

    /**
     * A handle on a tenant of a perTenant profile: {@code blob} is the tenant's key blob in a wrapped profile, null
     * in a derived one. A handle that cannot be used answers its refusal on every call.
     */
    public Tenant tenant(String profile, String tenant, byte[] blob) {
        return new Tenant(this, core.tenant(profile, tenant, blob));
    }

    // ── batches ──────────────────────────────────────────────────────────────────────────────────────────

    /** Encrypts every item in one request: one result per item, in order; an item's refusal fails it alone. */
    public List<BatchResult> encryptBatch(String profile, List<BatchItem> items, CallOption... opts) {
        Opts o = Opts.of(opts);
        return batch(o, call -> core.encryptBatch(call, profile, items(items)));
    }

    /** Decrypts every item in one request. */
    public List<BatchResult> decryptBatch(String profile, List<BatchItem> items, CallOption... opts) {
        Opts o = Opts.of(opts);
        return batch(o, call -> core.decryptBatch(call, profile, items(items)));
    }

    /** Re-encrypts every item in one request (an item's target associated data is its associated data). */
    public List<BatchResult> reEncryptBatch(String profile, List<BatchItem> items, CallOption... opts) {
        Opts o = Opts.of(opts);
        return batch(o, call -> core.reEncryptBatch(call, profile, items(items)));
    }

    /** Rewraps many tenant keys of a wrapped profile in one request: never retried. */
    public List<TenantKeyResult> rewrapTenantKeyBatch(String profile, List<TenantKeyRef> keys, CallOption... opts) {
        Opts o = Opts.of(opts);
        List<Core.KeyRef> refs = new ArrayList<>();
        for (TenantKeyRef r : keys) {
            refs.add(new Core.KeyRef(r.tenant(), r.blob()));
        }
        return run(o, call -> {
            List<TenantKeyResult> out = new ArrayList<>();
            for (Core.KeyResult r : core.rewrapTenantKeyBatch(call, profile, refs)) {
                out.add(r.error() != null ? new TenantKeyResult(null, Dial.mapItem(core, call, r.error()))
                        : new TenantKeyResult(new TenantKey(r.key().blob(), r.key().keyId(),
                                r.key().signingPublicKey(), r.key().fingerprint()), null));
            }
            return out;
        });
    }

    /**
     * Re-encrypts a ciphertext of one profile under another (its tenant, in a perTenant one), without the plaintext
     * leaving cipheron: the answer is signed by both profiles, and both signatures are checked.
     */
    public byte[] reEncryptAcross(Scope from, Scope to, byte[] ciphertext, CallOption... opts) {
        Opts o = Opts.of(opts);
        return run(o, call -> core.reEncryptAcross(call, side(from), side(to), ciphertext, o.aad, o.toAad));
    }

    // ── objects, streams, JSON fields ───────────────────────────────────────────────────────────────────

    /** Encrypts a large plaintext as a segmented object (CPS1): segments of {@link CallOption#segmentSize}, in batches. */
    public byte[] encryptObject(String profile, byte[] plaintext, CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.encryptObject(core.plan(), plaintext, o.aad, o.segmentSize,
                items -> encryptBatch(profile, items, timeoutOf(o)));
    }

    /** Decrypts a segmented object whole: nothing is returned unless every segment is its position's. */
    public byte[] decryptObject(String profile, byte[] object, CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.decryptObject(core.plan(), object, o.aad, items -> decryptBatch(profile, items, timeoutOf(o)));
    }

    /** Re-encrypts a segmented object, segment by segment, keeping its id and segment size. */
    public byte[] reEncryptObject(String profile, byte[] object, CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.reEncryptObject(core.plan(), object, o.aad, o.toAad, o.segmentSize,
                items -> reEncryptBatch(profile, items, timeoutOf(o)));
    }

    /** Encrypts {@code size} bytes of {@code src} into {@code dst} as a segmented object; answers the bytes written. */
    public long encryptStream(String profile, java.io.OutputStream dst, java.io.InputStream src, long size,
            CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.encryptStream(core.plan(), dst, src, size, o.aad, o.segmentSize,
                items -> encryptBatch(profile, items, timeoutOf(o)));
    }

    /**
     * Decrypts a segmented object from {@code src} into {@code dst} a batch at a time. An object modified further on
     * fails when that point is reached, AFTER the plaintext before it was written: on any error, discard what was
     * written. When nothing may be released before the whole object is checked, use {@link #decryptObject}.
     */
    public long decryptStream(String profile, java.io.OutputStream dst, java.io.InputStream src, CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.decryptStream(core.plan(), dst, src, o.aad, items -> decryptBatch(profile, items, timeoutOf(o)));
    }

    /** Re-encrypts a segmented object from {@code src} into {@code dst}. */
    public long reEncryptStream(String profile, java.io.OutputStream dst, java.io.InputStream src, CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.reEncryptStream(core.plan(), dst, src, o.aad, o.toAad, o.segmentSize,
                items -> reEncryptBatch(profile, items, timeoutOf(o)));
    }

    /**
     * Encrypts the fields {@code pointers} (RFC 6901) of a JSON document: each value, as compact JSON, becomes
     * {@code "cipheron:v1:" + base64(ciphertext)}, bound to {@code recordId} and its pointer. All or nothing.
     */
    public byte[] encryptJsonFields(String profile, byte[] doc, String recordId, List<String> pointers,
            CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.jsonFields(core.plan(), doc, recordId, pointers, o.aad, null, Containers.FieldOp.ENCRYPT,
                items -> encryptBatch(profile, items, timeoutOf(o)));
    }

    /** Decrypts the encrypted fields {@code pointers} of a JSON document. */
    public byte[] decryptJsonFields(String profile, byte[] doc, String recordId, List<String> pointers,
            CallOption... opts) {
        Opts o = Opts.of(opts);
        return Containers.jsonFields(core.plan(), doc, recordId, pointers, o.aad, null, Containers.FieldOp.DECRYPT,
                items -> decryptBatch(profile, items, timeoutOf(o)));
    }

    /** Re-encrypts the encrypted fields {@code pointers} of a JSON document. */
    public byte[] reEncryptJsonFields(String profile, byte[] doc, String recordId, List<String> pointers,
            CallOption... opts) {
        Opts o = Opts.of(opts);
        Core.reEncryptCheck(o.aad, o.toAad);
        return Containers.jsonFields(core.plan(), doc, recordId, pointers, o.aad, o.toAad,
                Containers.FieldOp.RE_ENCRYPT, items -> reEncryptBatch(profile, items, timeoutOf(o)));
    }

    /** Whether {@code value} is an encrypted JSON field ({@code cipheron:v1:…}). */
    public static boolean isJsonField(String value) {
        return value != null && value.startsWith(Containers.JSON_FIELD_PREFIX);
    }

    static CallOption[] timeoutOf(Opts o) {
        return o.timeout == null ? new CallOption[0] : new CallOption[] {CallOption.timeout(o.timeout)};
    }

    private static Core.Side side(Scope s) {
        return new Core.Side(s.profile(), s.tenant() == null ? "" : s.tenant(), s.tenantKey());
    }

    static List<Core.Item> items(List<BatchItem> items) {
        List<Core.Item> out = new ArrayList<>();
        for (BatchItem it : items) {
            out.add(new Core.Item(it.data(), it.associatedData(), it.toAssociatedData()));
        }
        return out;
    }

    @FunctionalInterface
    interface BatchBody {
        List<Core.ItemResult> run(Core.Call call) throws RpcFailure;
    }

    List<BatchResult> batch(Opts o, BatchBody body) {
        return run(o, call -> {
            List<BatchResult> out = new ArrayList<>();
            for (Core.ItemResult r : body.run(call)) {
                out.add(r.error() != null ? new BatchResult(null, Dial.mapItem(core, call, r.error()))
                        : new BatchResult(r.value(), null));
            }
            return out;
        });
    }

    /** A call's options, read. */
    static final class Opts {
        byte[] aad;
        byte[] toAad;
        int segmentSize;
        Duration timeout;

        static Opts of(CallOption... opts) {
            Opts o = new Opts();
            for (CallOption c : opts) {
                if (c == null) {
                    continue;
                }
                if (c.aad != null) {
                    o.aad = c.aad;
                }
                if (c.toAad != null) {
                    o.toAad = c.toAad;
                }
                if (c.segmentSize != 0) {
                    o.segmentSize = c.segmentSize;
                }
                if (c.timeout != null) {
                    o.timeout = c.timeout;
                }
            }
            int max = 64 << 10;
            if ((o.aad != null && o.aad.length > max) || (o.toAad != null && o.toAad.length > max)) {
                throw new AssociatedDataException("cipheron: the associated data does not match the ciphertext's "
                        + "format: associated data is at most " + max + " bytes");
            }
            return o;
        }
    }

    // ── the builder ──────────────────────────────────────────────────────────────────────────────────────

    /**
     * How a client is made. Each option given twice with different values fails {@link #build}, except pins of
     * context digests and writer versions, which join.
     */
    public static final class Builder {
        private final String address;
        private final List<String> errors = new ArrayList<>();
        private Long serverUid;
        private boolean anyServer;
        private Path certFile;
        private Path keyFile;
        private Path caFile;
        private String spiffeId;
        private PrivateKey requestKey;
        private byte[] requestPub;
        private final Map<String, String> fingerprints = new HashMap<>();
        private final Map<String, List<String>> contextPins = new HashMap<>();
        private final Map<String, List<String>> writerPins = new HashMap<>();
        private final Map<String, String> tenantPins = new HashMap<>();
        private boolean requirePins;
        private int maxMessage = Plan.DEFAULT_MAX_MESSAGE;
        private int connections;
        private Duration keysMaxAge = Plan.DEFAULT_KEYS_MAX_AGE;
        private RetryPolicy retry;
        private Transport transport;
        private BiConsumer<String, String> observer;
        private Duration defaultTimeout = Duration.ofSeconds(30);
        private Path pinsDir;
        private Duration pinsReload = Duration.ofSeconds(10);
        private Map<String, String> environment;

        private Builder(String address) {
            this.address = address;
        }

        /**
         * The socket's server check: the process serving the socket must run as {@code uid} (cipheron's image runs
         * as 10443). 0, 65534 and the values meaning "no uid" are refused.
         */
        public Builder serverUid(long uid) {
            if (uid < 0 || uid > 0xffffffffL || uid == 0 || uid == 65534 || uid >= 4294967294L) {
                errors.add("serverUid(" + uid + "): a uid that names no one in particular is no check");
            } else if (serverUid != null && serverUid != uid) {
                errors.add("serverUid is given twice, with different uids");
            }
            serverUid = uid;
            return this;
        }

        /** Turns the socket's server check off: for tests and development only. */
        public Builder anyServer() {
            anyServer = true;
            return this;
        }

        /**
         * The network's mutual TLS: this client's certificate and key (PEM, re-read on every handshake) and the CAs
         * the server is checked against (never the system's roots). TLS 1.3.
         */
        public Builder tlsFiles(Path cert, Path key, Path ca) {
            certFile = cert;
            keyFile = key;
            caFile = ca;
            return this;
        }

        /** Checks the server by its SPIFFE id (exactly one URI SAN, equal to it) instead of its host name. */
        public Builder serverSpiffeId(String id) {
            spiffeId = id;
            return this;
        }

        /** The request key, from a PEM PKCS #8 Ed25519 private key file: it signs every request but PublicKey. */
        public Builder requestKeyFile(Path path) {
            try {
                byte[] pem = io.github.nnicora.cipheron.internal.client.PinsDir.SafeFiles.readPrivate(path, 64 << 10);
                try {
                    return requestKey(readEd25519(pem));
                } finally {
                    Arrays.fill(pem, (byte) 0);
                }
            } catch (IOException | GeneralSecurityException e) {
                errors.add("requestKeyFile " + path + ": " + e.getMessage());
                return this;
            }
        }

        /** The request key: an Ed25519 private key. Required on the network. */
        public Builder requestKey(PrivateKey key) {
            if (!(key instanceof EdECPrivateKey ed) || ed.getBytes().isEmpty()) {
                errors.add("requestKey: an Ed25519 private key");
                return this;
            }
            try {
                byte[] seed = ed.getBytes().get();
                KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
                g.initialize(NamedParameterSpec.ED25519, new FixedRandom(seed));
                requestPub = Ed25519.raw(g.generateKeyPair().getPublic());
                Arrays.fill(seed, (byte) 0);
                requestKey = key;
            } catch (GeneralSecurityException e) {
                errors.add("requestKey: " + e.getMessage());
            }
            return this;
        }

        /** Pins a profile's identity: {@code sha256:} and 64 lower-case hex digits, as {@code keygen ensure} prints. */
        public Builder profileFingerprint(String profile, String fingerprint) {
            if (!Grammar.validProfile(profile) || !Grammar.validFingerprint(fingerprint)) {
                errors.add("profileFingerprint(" + profile + "): not a profile name and a sha256: fingerprint");
            } else if (fingerprints.containsKey(profile) && !fingerprints.get(profile).equals(fingerprint)) {
                errors.add("profileFingerprint(" + profile + ") is given twice, with different fingerprints");
            }
            fingerprints.put(profile, fingerprint);
            return this;
        }

        /** Pins the key contexts a profile's answers may come from: at most 8; joined when given twice. */
        public Builder contextDigestPin(String profile, String... digests) {
            List<String> l = new ArrayList<>(contextPins.getOrDefault(profile, List.of()));
            for (String d : digests) {
                if (!Grammar.validFingerprint(d)) {
                    errors.add("contextDigestPin(" + profile + "): \"" + d + "\" is not a key-context digest");
                } else if (!l.contains(d)) {
                    l.add(d);
                }
            }
            if (l.size() > Plan.MAX_CONTEXT_PINS) {
                errors.add("contextDigestPin(" + profile + "): at most " + Plan.MAX_CONTEXT_PINS + " digests");
            }
            contextPins.put(profile, List.copyOf(l));
            return this;
        }

        /** Pins the master versions new data of a profile may be made under: at most 8; joined when given twice. */
        public Builder writerVersionPin(String profile, String... versions) {
            List<String> l = new ArrayList<>(writerPins.getOrDefault(profile, List.of()));
            for (String v : versions) {
                if (!Grammar.validMasterVersionId(v)) {
                    errors.add("writerVersionPin(" + profile + "): \"" + v + "\" is not a master key version id");
                } else if (!l.contains(v)) {
                    l.add(v);
                }
            }
            if (l.size() > Plan.MAX_WRITER_PINS) {
                errors.add("writerVersionPin(" + profile + "): at most " + Plan.MAX_WRITER_PINS + " versions");
            }
            writerPins.put(profile, List.copyOf(l));
            return this;
        }

        /** Pins a wrapped tenant's key: a blob of another key is refused before anything is sent. */
        public Builder tenantFingerprint(String profile, String tenant, String fingerprint) {
            if (!Grammar.validFingerprint(fingerprint) || !Grammar.validTenant(tenant)) {
                errors.add("tenantFingerprint(" + profile + "): not a tenant id and a sha256: fingerprint");
            }
            String ref = Plan.tenantRef(profile, tenant);
            if (tenantPins.containsKey(ref) && !tenantPins.get(ref).equals(fingerprint)) {
                errors.add("tenantFingerprint(" + profile + ") is given twice for one tenant, differently");
            }
            tenantPins.put(ref, fingerprint);
            return this;
        }

        /** A profile with no pin is refused ({@link PinRequiredException}) rather than trusted on first use. */
        public Builder requiredPins() {
            requirePins = true;
            return this;
        }

        /** The largest message sent or received: 4096 bytes to 2 GiB − 1; 64 MiB + 64 KiB by default. */
        public Builder maxMessageBytes(int n) {
            if (n < 4096) {
                errors.add("maxMessageBytes(" + n + "): from 4096");
            }
            maxMessage = n;
            return this;
        }

        /** The pool's size: 1 to 16 (2 over gRPC, 8 over HTTP by default). */
        public Builder connections(int n) {
            if (n < 1 || n > Plan.MAX_CONNECTIONS) {
                errors.add("connections(" + n + "): from 1 to " + Plan.MAX_CONNECTIONS);
            }
            connections = n;
            return this;
        }

        /** The oldest signing-key list a verification relies on: 5 seconds to 24 hours; 5 minutes by default. */
        public Builder keysMaxAge(Duration d) {
            if (d.compareTo(Plan.MIN_KEYS_MAX_AGE) < 0 || d.compareTo(Plan.MAX_KEYS_MAX_AGE) > 0) {
                errors.add("keysMaxAge(" + d + "): from 5s to 24h");
            }
            keysMaxAge = d;
            return this;
        }

        /** Retries refusals that say "later" ({@link RetryPolicy}). Off by default. */
        public Builder retry(RetryPolicy p) {
            if (retry != null && !retry.equals(p)) {
                errors.add("retry is given twice, with different policies");
            }
            retry = p;
            return this;
        }

        /** The API the client speaks: gRPC (the default) or the JSON API over HTTP/1.1. */
        public Builder transport(Transport t) {
            if (transport != null && transport != t) {
                errors.add("transport is given twice, with different values");
            }
            transport = t;
            return this;
        }

        /**
         * Told, per profile, of {@code context_digest}, {@code server_key_changed}, {@code server_identity},
         * {@code keys_stale} and {@code retry} events. It runs on the calling thread: keep it short.
         */
        public Builder observer(BiConsumer<String, String> o) {
            observer = o;
            return this;
        }

        /**
         * Reads the profiles' pins from a directory ({@code <profile>.fingerprint}, {@code <profile>.contextDigest};
         * a Kubernetes volume through its {@code ..data} link) and re-reads it every 10 seconds: a pin rotated in the
         * volume is adopted without a restart; a read that fails keeps the last good pins.
         */
        public Builder pinsDir(Path dir) {
            pinsDir = dir;
            return this;
        }

        /** How often the pins directory is re-read: 10 seconds by default. */
        public Builder pinsReloadInterval(Duration d) {
            pinsReload = d;
            return this;
        }

        /**
         * Configures the client from the environment the cipheron-sidecar chart sets: {@code CIPHERON_SOCKET},
         * {@code CIPHERON_SERVER_UID}, {@code CIPHERON_REQUEST_KEY}, {@code CIPHERON_PINS_DIR} and
         * {@code CIPHERON_ENVIRONMENT} (production unless {@code development}: production requires pins). The
         * builder's address is then "".
         */
        public Builder environment() {
            return environment(System.getenv());
        }

        /** As {@link #environment()}, from {@code env}. */
        public Builder environment(Map<String, String> env) {
            environment = Map.copyOf(env);
            return this;
        }

        /** The deadline of a call that names none: 30 seconds by default. */
        public Builder defaultTimeout(Duration d) {
            if (d.isNegative() || d.isZero()) {
                errors.add("defaultTimeout(" + d + "): positive");
            }
            defaultTimeout = d;
            return this;
        }

        /** The client. Nothing is connected yet; a configuration error fails here. */
        public CipheronClient build() {
            String where = address;
            if (environment != null) {
                where = fromEnvironment();
            }
            Map<String, String> inlineFingerprints = Map.copyOf(fingerprints);
            Map<String, List<String>> inlineContext = copy(contextPins);
            if (pinsDir != null) {
                try {
                    io.github.nnicora.cipheron.internal.client.PinsDir.Pins d =
                            io.github.nnicora.cipheron.internal.client.PinsDir.read(pinsDir);
                    d.fingerprints().forEach(this::profileFingerprint);
                    d.context().forEach((k, v) -> contextDigestPin(k, v.toArray(new String[0])));
                    if (requirePins && fingerprints.isEmpty()) {
                        errors.add("the pins directory " + pinsDir + " holds no <profile>.fingerprint, and no option "
                                + "pins a profile: no profile can be used");
                    }
                } catch (IOException ex) {
                    errors.add(ex.getMessage());
                }
            }
            if (!errors.isEmpty()) {
                throw new IllegalArgumentException("cipheron: " + String.join("; ", errors));
            }
            Endpoint e;
            try {
                e = Endpoint.parse(where);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(ex.getMessage(), ex);
            }
            if (e.isSocket()) {
                if (serverUid == null && !anyServer) {
                    errors.add("a socket client checks its server: serverUid(uid), or anyServer() for development");
                }
                if (serverUid != null && anyServer) {
                    errors.add("serverUid and anyServer are both given: pass one");
                }
                if (certFile != null || spiffeId != null) {
                    errors.add("TLS options are for a network address, not a socket");
                }
            } else {
                if (certFile == null) {
                    errors.add("a network client speaks mutual TLS: tlsFiles(cert, key, ca)");
                }
                if (requestKey == null) {
                    errors.add("a network client signs its requests: requestKeyFile(path) or requestKey(key)");
                }
                if (serverUid != null || anyServer) {
                    errors.add("serverUid and anyServer are for a socket, not a network address");
                }
            }
            if (!errors.isEmpty()) {
                throw new IllegalArgumentException("cipheron: " + String.join("; ", errors));
            }
            Plan.Retry r = retry == null ? null
                    : new Plan.Retry(retry.maxAttempts(), retry.initialBackoff(), retry.maxBackoff());
            Plan plan = new Plan(e, transport == Transport.HTTP, anyServer ? null : serverUid, certFile, keyFile, caFile,
                    spiffeId, requestKey, requestPub, Map.copyOf(fingerprints), copy(contextPins), copy(writerPins),
                    Map.copyOf(tenantPins), requirePins, null, maxMessage, connections, keysMaxAge, r, observer,
                    defaultTimeout);
            Core core = Dial.dial(plan);
            if (pinsDir != null) {
                core.watchPins(pinsDir.toAbsolutePath().normalize(), pinsReload, inlineFingerprints, inlineContext);
            }
            return new CipheronClient(core);
        }

        private String fromEnvironment() {
            if (!address.isEmpty()) {
                errors.add("an address (\"" + address + "\") and CIPHERON_SOCKET are two answers to one question: "
                        + "pass \"\" as the address");
            }
            String socket = env("CIPHERON_SOCKET", true);
            String uid = env("CIPHERON_SERVER_UID", true);
            String key = env("CIPHERON_REQUEST_KEY", false);
            String pins = env("CIPHERON_PINS_DIR", false);
            String mode = env("CIPHERON_ENVIRONMENT", false);
            if (!"development".equals(mode)) {
                requirePins = true;
                if (pins == null) {
                    errors.add("CIPHERON_PINS_DIR is not set, and the environment is production: a production client "
                            + "never trusts a profile's identity on first use — mount the pins, or on a development "
                            + "machine only set CIPHERON_ENVIRONMENT=development");
                }
            }
            if (socket != null && !Path.of(socket.startsWith("unix://") ? socket.substring(7) : socket).isAbsolute()) {
                errors.add("CIPHERON_SOCKET=\"" + socket + "\": cipheron's socket, an absolute path");
            }
            if (uid != null) {
                try {
                    serverUid(Long.parseLong(uid));
                } catch (NumberFormatException ex) {
                    errors.add("CIPHERON_SERVER_UID=\"" + uid + "\": a uid, in decimal");
                }
            }
            if (key != null) {
                requestKeyFile(Path.of(key));
            }
            if (pins != null) {
                pinsDir = Path.of(pins);
            }
            return socket == null ? "" : socket;
        }

        private String env(String name, boolean required) {
            String v = environment.get(name);
            if (v == null && required) {
                errors.add(name + " is not set (the cipheron-sidecar chart sets it in the application's container)");
            } else if (v != null && v.isBlank()) {
                errors.add(name + " is set and empty");
                return null;
            }
            return v;
        }

        private static Map<String, List<String>> copy(Map<String, List<String>> m) {
            Map<String, List<String>> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(k, List.copyOf(v)));
            return Map.copyOf(out);
        }

        private static PrivateKey readEd25519(byte[] pem) throws GeneralSecurityException {
            String s = new String(pem, java.nio.charset.StandardCharsets.US_ASCII).trim();
            String begin = "-----BEGIN PRIVATE KEY-----";
            String end = "-----END PRIVATE KEY-----";
            if (!s.startsWith(begin) || !s.endsWith(end)) {
                throw new GeneralSecurityException("expected one PEM \"PRIVATE KEY\" block and nothing else");
            }
            byte[] der = Base64.getMimeDecoder().decode(s.substring(begin.length(), s.length() - end.length()));
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
    }

    /** A SecureRandom that answers one fixed seed: derives an Ed25519 key pair's public key from its seed. */
    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;

        FixedRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(seed, 0, bytes, 0, Math.min(seed.length, bytes.length));
        }
    }

    static SigningKey publicKey(SigningKeys.Key k) {
        return new SigningKey(k.keyId(), SigningKey.State.of(k.state()), k.publicKey(), k.effectiveAlgorithm());
    }
}
