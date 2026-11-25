package io.github.nnicora.cipheron.internal.client;

import cipheron.v1.Cipheron;
import com.google.protobuf.ByteString;
import io.github.nnicora.cipheron.BadResponseException;
import io.github.nnicora.cipheron.CipheronException;
import io.github.nnicora.cipheron.ClosedException;
import io.github.nnicora.cipheron.ContextDigestException;
import io.github.nnicora.cipheron.DeadlineExceededException;
import io.github.nnicora.cipheron.KeysStaleException;
import io.github.nnicora.cipheron.PinRequiredException;
import io.github.nnicora.cipheron.ServerIdentityException;
import io.github.nnicora.cipheron.ServerKeyChangedException;
import io.github.nnicora.cipheron.SigningKeyRevokedException;
import io.github.nnicora.cipheron.TooLargeException;
import io.github.nnicora.cipheron.UnknownSigningKeyException;
import io.github.nnicora.cipheron.internal.crypto.Ed25519;
import io.github.nnicora.cipheron.internal.crypto.Hpke;
import io.github.nnicora.cipheron.internal.wire.Bytes;
import io.github.nnicora.cipheron.internal.wire.Ciphertexts;
import io.github.nnicora.cipheron.internal.wire.Grammar;
import io.github.nnicora.cipheron.internal.wire.Identity;
import io.github.nnicora.cipheron.internal.wire.KeyStatements;
import io.github.nnicora.cipheron.internal.wire.Refusals;
import io.github.nnicora.cipheron.internal.wire.SigningKeys;
import io.github.nnicora.cipheron.internal.wire.TenantKeys;
import io.github.nnicora.cipheron.internal.wire.Transcripts;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/**
 * The client: one pool of connections, the profiles' verified keys, and every check the protocol asks of a client
 * before it believes an answer ({@code spec/api.md}, "Doing it by hand, in another language";
 * {@code internal/client/client.go}). Server answers that are not results arrive as {@link RpcFailure}; what the
 * client decides itself is thrown as the public exceptions.
 */
public final class Core implements AutoCloseable {
    /** Verify's re-fetch for an unknown key id, and a failed refresh's memory, are this far apart at least. */
    static final Duration MIN_VERIFY_REFRESH = Duration.ofSeconds(5);

    /** The longest {@code CIPHERON_STARTING} wait the client re-signs and resends after, unasked. */
    static final Duration MAX_STARTING_WAIT = Duration.ofSeconds(1);

    private static final SecureRandom RANDOM = new SecureRandom();

    final Plan plan;
    private final Rpc[] rpcs;
    private final AtomicLong next = new AtomicLong();
    final IdentityState id;
    private final AtomicReference<PinSet> pins;
    private final AtomicBoolean closed = new AtomicBoolean();

    private final ConcurrentHashMap<String, ProfileKeys> keys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> refused = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<String>> seen = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> fetched = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Freshness> fresh = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<ProfileKeys>> inflight = new ConcurrentHashMap<>();

    Core(Plan plan, Rpc[] rpcs, IdentityState id) {
        this.plan = plan;
        this.rpcs = rpcs;
        this.id = id;
        this.pins = new AtomicReference<>(new PinSet(plan.fingerprints(), plan.contextPins(), plan.writerPins()));
    }

    /** One call's deadline and request id: the same for every attempt of the call. */
    public record Call(Instant deadline, String requestId) {
        /** A call ending {@code timeout} from now, with a new request id. */
        public static Call of(Duration timeout) {
            byte[] b = new byte[16];
            RANDOM.nextBytes(b);
            return new Call(Instant.now().plus(timeout), Bytes.hex(b));
        }

        boolean ended() {
            return !Instant.now().isBefore(deadline);
        }

        Duration remaining() {
            return Duration.between(Instant.now(), deadline);
        }
    }

    /** What a call acts on: a profile's keys, and its tenant and blob in a perTenant profile. */
    record Scope(String profile, ProfileKeys k, String tenant, byte[] blob, TenantKeys.Header h, boolean fresh) {
        Scope withKeys(ProfileKeys nk) {
            return new Scope(profile, nk, tenant, blob, h, true);
        }

        String who() {
            return tenant.isEmpty() ? "profile \"" + profile + "\""
                    : "tenant \"" + tenant + "\" of profile \"" + profile + "\"";
        }
    }

    /** A step that may be refused by cipheron. */
    @FunctionalInterface
    interface Attempt<T> {
        T run() throws RpcFailure;
    }

    // ── lifecycle ──────────────────────────────────────────────────────────────────────────────────────────

    /** The client's configuration. */
    public Plan plan() {
        return plan;
    }

    /** Fails with {@link ClosedException} once the client is closed. */
    public void open() {
        if (closed.get()) {
            throw new ClosedException("cipheron: the client is closed");
        }
    }

    public boolean closed() {
        return closed.get();
    }

    private java.util.concurrent.ScheduledExecutorService reloader;

    /**
     * Re-reads the pins directory every {@code every}: the directory's pins replace the last ones read, the inline
     * pins stay; a read that fails keeps the last good pins and tells the observer ({@code pins_reload_failed}),
     * never failing open.
     */
    public void watchPins(java.nio.file.Path dir, java.time.Duration every, java.util.Map<String, String> inlineFps,
            java.util.Map<String, List<String>> inlineCtx) {
        java.util.concurrent.ScheduledExecutorService ex = java.util.concurrent.Executors
                .newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "cipheron-pins");
                    t.setDaemon(true);
                    return t;
                });
        reloader = ex;
        ex.scheduleWithFixedDelay(() -> {
            try {
                PinsDir.Pins d = PinsDir.read(dir);
                java.util.Map<String, String> fps = new java.util.HashMap<>(inlineFps);
                for (java.util.Map.Entry<String, String> e : d.fingerprints().entrySet()) {
                    String inline = inlineFps.get(e.getKey());
                    if (inline != null && !inline.equals(e.getValue())) {
                        throw new java.io.IOException("the directory pins " + e.getKey() + " to another fingerprint "
                                + "than the client's own option");
                    }
                    fps.put(e.getKey(), e.getValue());
                }
                java.util.Map<String, List<String>> ctx = new java.util.HashMap<>(inlineCtx);
                d.context().forEach((k, v) -> {
                    List<String> joined = new ArrayList<>(ctx.getOrDefault(k, List.of()));
                    v.stream().filter(x -> !joined.contains(x)).forEach(joined::add);
                    ctx.put(k, List.copyOf(joined));
                });
                PinSet next = new PinSet(fps, ctx, plan.writerPins());
                PinSet cur = pins.get();
                if (!next.equals(cur)) {
                    pins.set(next);
                }
            } catch (java.io.IOException | RuntimeException e) {
                tell("", "pins_reload_failed");
            }
        }, every.toMillis(), every.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (reloader != null) {
            reloader.shutdownNow();
        }
        for (Rpc r : rpcs) {
            r.close();
        }
    }

    /** The last identity refusal of a connection attempt, or null. */
    public Throwable lastIdentityFailure() {
        return id.last();
    }

    Rpc pick() {
        int n = rpcs.length;
        if (n == 1) {
            return rpcs[0];
        }
        long start = next.incrementAndGet();
        for (int i = 0; i < n; i++) {
            Rpc r = rpcs[Math.floorMod(start + i, n)];
            if (r.usable()) {
                return r;
            }
        }
        return rpcs[Math.floorMod(start, n)];
    }

    void tell(String profile, String kind) {
        if (plan.observer() != null) {
            plan.observer().accept(profile, kind);
        }
    }

    /** Tells the observer the kind of {@code e}, if it has one. */
    public void observe(String profile, Throwable e) {
        if (plan.observer() == null || e == null) {
            return;
        }
        if (e instanceof ServerKeyChangedException) {
            tell(profile, "server_key_changed");
        } else if (e instanceof ServerIdentityException) {
            tell(profile, "server_identity");
        } else if (e instanceof ContextDigestException) {
            tell(profile, "context_digest");
        } else if (e instanceof KeysStaleException) {
            tell(profile, "keys_stale");
        }
    }

    // ── errors the client decides ──────────────────────────────────────────────────────────────────────────

    static ServerIdentityException identityFailure(String why) {
        return new ServerIdentityException("cipheron: not the profile's cipheron: " + why);
    }

    static ServerKeyChangedException keyChanged(String profile) {
        return new ServerKeyChangedException("cipheron: the profile's identity changed (profile \"" + profile
                + "\"): cipheron: not the profile's cipheron");
    }

    static PinRequiredException pinRequired(String profile) {
        return new PinRequiredException("cipheron: the profile has no pin, and the client requires one (profile \""
                + profile + "\": pin it with profileFingerprint)");
    }

    static BadResponseException badResponse(String why) {
        return new BadResponseException("cipheron: malformed answer: " + why);
    }

    // ── retries ────────────────────────────────────────────────────────────────────────────────────────────

    /** Runs {@code a}, and once more after {@code CIPHERON_STARTING} (re-signed: {@code a} signs anew). */
    <T> T afterStart(Call call, String profile, Attempt<T> a) throws RpcFailure {
        try {
            return a.run();
        } catch (RpcFailure f) {
            Refusals.Class c = f.classify();
            Duration wait = f.retryDelay() == null ? Duration.ZERO : f.retryDelay();
            if (!"starting".equals(c.name()) || wait.compareTo(MAX_STARTING_WAIT) > 0 || closed.get()
                    || call.remaining().compareTo(wait) <= 0) {
                throw f;
            }
            tell(profile, "retry");
            sleep(wait);
            return a.run();
        }
    }

    /** Runs {@code a} under the retry policy (if any), and always under {@link #afterStart}. */
    <T> T retryCall(Call call, String profile, Attempt<T> a) throws RpcFailure {
        Plan.Retry p = plan.retry();
        if (p == null) {
            return afterStart(call, profile, a);
        }
        Duration backoff = p.initialBackoff();
        for (int n = 1;; n++) {
            try {
                return afterStart(call, profile, a);
            } catch (RpcFailure f) {
                if (n >= p.maxAttempts() || closed.get()) {
                    throw f;
                }
                Refusals.Class c = f.classify();
                if (c.retry() == Refusals.Retry.NEVER) {
                    throw f;
                }
                if ("unavailable".equals(c.name()) && id.last() != null) {
                    throw f;
                }
                Duration hint = f.retryDelay() == null ? Duration.ZERO : f.retryDelay();
                if (hint.compareTo(p.maxBackoff()) > 0) {
                    throw f;
                }
                long half = backoff.toNanos() / 2;
                Duration jitter = Duration.ofNanos(half + ThreadLocalRandom.current().nextLong(half + 1));
                Duration wait = jitter.compareTo(hint) > 0 ? jitter : hint;
                if (call.remaining().compareTo(wait) <= 0) {
                    throw f;
                }
                tell(profile, "retry");
                sleep(wait);
                Duration doubled = backoff.multipliedBy(2);
                backoff = doubled.compareTo(p.maxBackoff()) < 0 ? doubled : p.maxBackoff();
            }
        }
    }

    private static void sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis(), d.toNanosPart() % 1_000_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CipheronException("cipheron: interrupted", e);
        }
    }

    // ── keys ───────────────────────────────────────────────────────────────────────────────────────────────

    PinSet pinsNow() {
        return pins.get();
    }

    /** Replaces the pins (the pins directory). */
    void setPins(PinSet p) {
        pins.set(p);
    }

    private void refuseContext(String profile) {
        refused.put(profile, Boolean.TRUE);
    }

    private boolean contextRefused(String profile) {
        return refused.containsKey(profile);
    }

    private void sawContext(String profile, String d) {
        seen.compute(profile, (p, l) -> {
            List<String> out = l == null ? new ArrayList<>() : new ArrayList<>(l);
            out.remove(d);
            out.add(d);
            while (out.size() > Plan.MAX_CONTEXT_PINS) {
                out.remove(0);
            }
            return List.copyOf(out);
        });
    }

    private List<String> seenContexts(String profile) {
        List<String> l = seen.get(profile);
        return l == null ? List.of() : l;
    }

    /** The profile's keys: cached ones, checked against the pins in force, or fetched now. */
    ProfileKeys keys(Call call, String profile) throws RpcFailure {
        return cachedOrFetched(call, profile).keys;
    }

    record Fetched(ProfileKeys keys, boolean fresh) {}

    Fetched cachedOrFetched(Call call, String profile) throws RpcFailure {
        ProfileKeys k = keys.get(profile);
        if (k != null && !contextRefused(profile)) {
            return checkCachedPins(call, profile, k);
        }
        k = load(call, profile);
        Fetched f = checkCachedPins(call, profile, k);
        return new Fetched(f.keys, true);
    }

    private Fetched checkCachedPins(Call call, String profile, ProfileKeys k) throws RpcFailure {
        PinSet p = pinsNow();
        if (k.checkedUnder == p) {
            return new Fetched(k, false);
        }
        String fp = p.fingerprint(profile);
        if (fp != null && !k.identity.matches(profile, fp)) {
            throw identityFailure("the identity cached for profile \"" + profile + "\" is " + k.fingerprint
                    + ", not the pinned " + fp);
        }
        List<String> ds = p.contextDigests(profile);
        if (ds != null && !ds.contains(k.contextDigest)) {
            ProfileKeys fk = load(call, profile);
            if (!ds.contains(fk.contextDigest)) {
                refuseContext(profile);
                throw new ContextDigestException("cipheron: profile \"" + profile + "\" holds key-context digest "
                        + fk.contextDigest + "; this client pins " + String.join(", ", ds));
            }
            return new Fetched(fk, true);
        }
        ProfileKeys stamped = k.checkedUnder(p);
        keys.replace(profile, k, stamped);
        return new Fetched(stamped, false);
    }

    ProfileKeys load(Call call, String profile) throws RpcFailure {
        return loadUnless(call, profile, null);
    }

    ProfileKeys loadUnless(Call call, String profile, Predicate<ProfileKeys> have) throws RpcFailure {
        return holdToPins(profile, loadShared(call, profile, have));
    }

    private ProfileKeys holdToPins(String profile, ProfileKeys k) {
        PinSet p = pinsNow();
        if (k.checkedUnder == p) {
            return k;
        }
        String fp = p.fingerprint(profile);
        if (fp != null && !k.identity.matches(profile, fp)) {
            throw identityFailure("the identity answered for profile \"" + profile + "\" is " + k.fingerprint
                    + ", not the pinned " + fp);
        }
        List<String> ds = p.contextDigests(profile);
        if (ds != null && !ds.contains(k.contextDigest)) {
            refuseContext(profile);
            throw new ContextDigestException("cipheron: profile \"" + profile + "\" answered key-context digest "
                    + k.contextDigest + "; this client pins " + String.join(", ", ds));
        }
        ProfileKeys stamped = k.checkedUnder(p);
        keys.replace(profile, k, stamped);
        return stamped;
    }

    /** A leader's fetch that ended because the leader's own deadline did. */
    private static final class LeaderEnded extends RuntimeException {
        private static final long serialVersionUID = 1L;

        LeaderEnded(Throwable cause) {
            super(cause);
        }
    }

    /** One fetch of a profile's keys at a time: concurrent callers share it. */
    private ProfileKeys loadShared(Call call, String profile, Predicate<ProfileKeys> have) throws RpcFailure {
        while (true) {
            CompletableFuture<ProfileKeys> mine = new CompletableFuture<>();
            CompletableFuture<ProfileKeys> f = inflight.putIfAbsent(profile, mine);
            if (f == null) {
                try {
                    ProfileKeys cached = keys.get(profile);
                    ProfileKeys k = have != null && cached != null && have.test(cached) ? cached
                            : fetchKeys(call, profile);
                    mine.complete(k);
                    return k;
                } catch (RpcFailure | RuntimeException e) {
                    mine.completeExceptionally(call.ended() ? new LeaderEnded(e) : e);
                    throw e;
                } finally {
                    inflight.remove(profile, mine);
                }
            }
            try {
                long ns = Math.max(call.remaining().toNanos(), 1);
                return f.get(ns, TimeUnit.NANOSECONDS);
            } catch (TimeoutException e) {
                throw new DeadlineExceededException("cipheron: the call's deadline passed while the profile's keys "
                        + "were fetched");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CipheronException("cipheron: interrupted", e);
            } catch (ExecutionException e) {
                Throwable c = e.getCause();
                if (c instanceof LeaderEnded le) {
                    if (!call.ended()) {
                        continue;
                    }
                    c = le.getCause();
                }
                if (c instanceof RpcFailure rf) {
                    throw rf;
                }
                if (c instanceof RuntimeException re) {
                    throw re;
                }
                throw new CipheronException(String.valueOf(c.getMessage()), c);
            }
        }
    }

    private static String tenancyOf(int v) {
        return switch (v) {
            case 1 -> "shared";
            case 2 -> "perTenantWrapped";
            case 3 -> "perTenantDerived";
            default -> null;
        };
    }

    private static Identity.Suite suiteOf(Cipheron.HpkeSuite s) {
        if (s.getKemId() > 0xffff || s.getKdfId() > 0xffff || s.getAeadId() > 0xffff) {
            return new Identity.Suite(0xffff, 0xffff, 0xffff);
        }
        return new Identity.Suite(s.getKemId(), s.getKdfId(), s.getAeadId());
    }

    private static boolean sameKeys(List<SigningKeys.Key> a, List<SigningKeys.Key> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            SigningKeys.Key x = a.get(i);
            SigningKeys.Key y = b.get(i);
            if (!Arrays.equals(x.keyId(), y.keyId()) || !x.state().equals(y.state())
                    || !Arrays.equals(x.publicKey(), y.publicKey()) || x.effectiveAlgorithm() != y.effectiveAlgorithm()) {
                return false;
            }
        }
        return true;
    }

    private static boolean covers(List<SigningKeys.Key> keys, List<SigningKeys.Key> old) {
        for (SigningKeys.Key o : old) {
            SigningKeys.Key n = ProfileKeys.find(keys, o.keyId());
            if (n == null || !Arrays.equals(n.publicKey(), o.publicKey())) {
                return false;
            }
        }
        return true;
    }

    @SafeVarargs
    private static List<SigningKeys.Key> keepRevoked(List<SigningKeys.Key> keys, List<SigningKeys.Key>... from) {
        List<SigningKeys.Key> out = new ArrayList<>();
        for (SigningKeys.Key k : keys) {
            String state = k.state();
            for (List<SigningKeys.Key> l : from) {
                SigningKeys.Key o = ProfileKeys.find(l, k.keyId());
                if (o != null && SigningKeys.REVOKED.equals(o.state())) {
                    state = SigningKeys.REVOKED;
                }
            }
            out.add(new SigningKeys.Key(k.keyId(), state, k.publicKey(), k.algorithm()));
        }
        return out;
    }

    private static boolean revokesUsable(List<SigningKeys.Key> keys, List<SigningKeys.Key> other) {
        for (SigningKeys.Key k : keys) {
            SigningKeys.Key o = ProfileKeys.find(other, k.keyId());
            if (o != null && SigningKeys.REVOKED.equals(k.state()) && o.usable()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Fetches and checks a profile's keys (PublicKey): the tenancy, the identity, its pin (or trust on first use),
     * the signed signing-key list under this request's nonce, the key statement against the identity, the
     * context digest against its pins; a later list is adopted only when it still names every key held, and a key
     * once seen revoked stays revoked.
     */
    private ProfileKeys fetchKeys(Call call, String profile) throws RpcFailure {
        PinSet p = pinsNow();
        if (plan.requirePins() && p.fingerprint(profile) == null) {
            throw pinRequired(profile);
        }
        byte[][] nonce = new byte[1][];
        Cipheron.PublicKeyResponse resp = retryCall(call, profile, () -> {
            nonce[0] = newNonce();
            return pick().call(Op.PUBLIC_KEY, Cipheron.PublicKeyRequest.newBuilder().setProfile(profile)
                    .setRequestNonce(ByteString.copyFrom(nonce[0])).build(), call.requestId(), call.deadline());
        });
        String tenancy = tenancyOf(resp.getTenancyValue());
        if (tenancy == null) {
            throw identityFailure("profile \"" + profile + "\" answered tenancy number " + resp.getTenancyValue()
                    + ", which this client does not have: the answer cannot be authenticated");
        }
        List<Identity.Key> additional = new ArrayList<>();
        if (resp.getAdditionalIdentityKeysCount() > Identity.MAX_ADDITIONAL_KEYS) {
            for (int i = 0; i <= Identity.MAX_ADDITIONAL_KEYS; i++) {
                additional.add(new Identity.Key(0, null, 0, Bytes.EMPTY));
            }
        } else {
            for (Cipheron.IdentityKey a : resp.getAdditionalIdentityKeysList()) {
                additional.add(new Identity.Key(a.getRoleValue(), a.hasHpkeSuite() ? suiteOf(a.getHpkeSuite()) : null,
                        a.getSignatureAlgorithmValue(), a.getPublicKey().toByteArray()));
            }
        }
        Identity d = new Identity(tenancy, resp.getHpkePublicKey().toByteArray(),
                resp.hasHpkeSuite() ? suiteOf(resp.getHpkeSuite()) : null, resp.getResponsePublicKey().toByteArray(),
                resp.getResponseKeyAlgorithmValue(), additional);
        String why = d.validateReceived();
        if (why != null) {
            throw identityFailure("the identity answered for profile \"" + profile + "\": " + why);
        }
        if (!resp.hasHpkeSuite() || resp.getResponseKeyAlgorithmValue() == 0) {
            throw identityFailure("the keys answered for profile \"" + profile + "\" name no HPKE suite or no response "
                    + "key algorithm");
        }
        ProfileKeys prev = keys.get(profile);
        if (prev != null && !prev.identity.sameAs(d)) {
            throw keyChanged(profile);
        }
        String pin = p.fingerprint(profile);
        if (pin != null && !d.matches(profile, pin)) {
            throw identityFailure("the identity answered for profile \"" + profile + "\" is " + d.fingerprint(profile)
                    + ", not the pinned " + pin);
        }
        if (d.effectiveResponseAlgorithm() != Identity.ALGORITHM_ED25519) {
            throw identityFailure("the response key of profile \"" + profile + "\" is of algorithm "
                    + d.effectiveResponseAlgorithm() + ", which this client does not implement");
        }
        if (resp.getSigningKeysCount() > SigningKeys.MAX_SIGNING_KEYS) {
            throw identityFailure("the keys answered for profile \"" + profile + "\" list "
                    + resp.getSigningKeysCount() + " signing keys; at most " + SigningKeys.MAX_SIGNING_KEYS);
        }
        List<Transcripts.ReceivedKey> received = new ArrayList<>();
        List<SigningKeys.Key> listed = new ArrayList<>();
        for (Cipheron.SigningKey s : resp.getSigningKeysList()) {
            if (s.getAlgorithmValue() == 0) {
                throw identityFailure("a signing key answered for profile \"" + profile + "\" names no algorithm");
            }
            received.add(new Transcripts.ReceivedKey(s.getKeyId().toByteArray(), s.getStateValue() & 0xffffffffL,
                    s.getPublicKey().toByteArray()));
            String st = SigningKeys.stateOf(s.getStateValue() & 0xffffffffL);
            listed.add(new SigningKeys.Key(s.getKeyId().toByteArray(), st == null ? "" : st,
                    s.getPublicKey().toByteArray(), s.getAlgorithmValue()));
        }
        listed.sort((a, b) -> Arrays.compareUnsigned(a.keyId(), b.keyId()));
        String ctx = resp.getContextDigest();
        byte[] keysSig = resp.getKeysSignature().toByteArray();
        if (!Ed25519.verify(d.response(), Transcripts.signingKeys(profile, tenancy, ctx, nonce[0], received), keysSig)) {
            throw identityFailure("the signing keys answered for profile \"" + profile + "\" are not its identity's");
        }
        for (Transcripts.ReceivedKey r : received) {
            if (SigningKeys.stateOf(r.state()) == null) {
                throw badResponse("signing key " + Bytes.hex(r.keyId()) + " of profile \"" + profile
                        + "\" is in state " + r.state() + ", which is not active, verifyOnly or revoked");
            }
        }
        if (!Grammar.validFingerprint(ctx)) {
            throw identityFailure("\"" + ctx + "\" is not a key-context digest");
        }
        why = SigningKeys.validateReceived(tenancy, listed);
        if (why != null) {
            throw identityFailure("the signing keys answered for profile \"" + profile + "\": " + why);
        }
        byte[] stmt = resp.getKeyStatement().toByteArray();
        byte[] stSig = resp.getKeyStatementSignature().toByteArray();
        KeyStatements.Statement st;
        try {
            st = KeyStatements.verify(stmt, stSig, profile, d.fingerprint(profile));
        } catch (KeyStatements.Refused e) {
            throw identityFailure("the key statement answered for profile \"" + profile + "\": " + e.getMessage());
        }
        if (!st.identity().sameAs(d) || !st.contextDigest().equals(ctx) || !sameKeys(st.signingKeys(), listed)) {
            throw identityFailure("the key statement answered for profile \"" + profile + "\" is not the answer's "
                    + "identity, key-context digest and signing keys");
        }
        sawContext(profile, ctx);
        List<String> ds = p.contextDigests(profile);
        if (ds != null && !ds.contains(ctx)) {
            refuseContext(profile);
            throw new ContextDigestException("cipheron: profile \"" + profile + "\" answered key-context digest " + ctx
                    + "; this client pins " + String.join(", ", ds));
        }
        long now = System.nanoTime();
        if (prev != null) {
            List<SigningKeys.Key> kept = prev.signingKeys;
            String digest = prev.contextDigest;
            if (covers(listed, prev.signingKeys)) {
                kept = listed;
                digest = ctx;
            }
            kept = keepRevoked(kept, prev.signingKeys, listed);
            boolean freshList = sameKeys(listed, kept);
            if (sameKeys(prev.signingKeys, kept) && prev.contextDigest.equals(digest)) {
                if (prev.checkedUnder != p || freshList) {
                    ProfileKeys s = prev.checkedUnder(p);
                    if (freshList) {
                        s = s.withStatement(stmt, stSig, listed, now);
                    }
                    if (keys.replace(profile, prev, s)) {
                        prev = s;
                    }
                }
                refused.remove(profile);
                stored(profile);
                return prev;
            }
            ProfileKeys k;
            if (freshList) {
                k = prev.withList(kept, digest, p, stmt, stSig, listed, now, false);
            } else if (prev.statement != null && sameKeys(prev.statementKeys, kept)) {
                k = prev.withList(kept, digest, p, prev.statement, prev.statementSignature, prev.statementKeys,
                        prev.statementAtNanos, false);
            } else {
                boolean revoked = revokesUsable(kept, listed)
                        || (prev.statement != null && revokesUsable(kept, prev.statementKeys));
                k = prev.withList(kept, digest, p, null, null, null, 0, revoked);
            }
            keys.put(profile, k);
            refused.remove(profile);
            stored(profile);
            return k;
        }
        ProfileKeys k = new ProfileKeys(profile, d, d.fingerprint(profile), listed, ctx, stmt, stSig, listed, now,
                false, p);
        keys.put(profile, k);
        refused.remove(profile);
        stored(profile);
        return k;
    }

    private void stored(String profile) {
        long now = System.nanoTime();
        fetched.computeIfAbsent(profile, x -> new AtomicLong(Long.MIN_VALUE)).set(now);
        freshness(profile).verifiedAt(now);
    }

    // ── freshness ──────────────────────────────────────────────────────────────────────────────────────────

    /** When a profile's list last verified, and the last refresh for Verify's maximum age that failed. */
    private static final class Freshness {
        private volatile long verified = Long.MIN_VALUE;
        private long failedAt;
        private RuntimeException cause;

        synchronized void verifiedAt(long t) {
            verified = t;
            cause = null;
        }

        synchronized void failed(long t, RuntimeException e) {
            failedAt = t;
            cause = e;
        }

        synchronized RuntimeException recentFailure(long now) {
            if (cause != null && now - failedAt < MIN_VERIFY_REFRESH.toNanos()) {
                return cause;
            }
            return null;
        }
    }

    private Freshness freshness(String profile) {
        return fresh.computeIfAbsent(profile, x -> new Freshness());
    }

    /** Claims Verify's re-fetch for an unknown key id: at most one per {@link #MIN_VERIFY_REFRESH}. */
    private boolean claimVerifyFetch(String profile) {
        AtomicLong stamp = fetched.computeIfAbsent(profile, x -> new AtomicLong(Long.MIN_VALUE));
        long last = stamp.get();
        long now = System.nanoTime();
        if (last != Long.MIN_VALUE && now - last < MIN_VERIFY_REFRESH.toNanos()) {
            return false;
        }
        return stamp.compareAndSet(last, now);
    }

    /** The scope with a key list no older than the maximum age: re-fetched when older; fails closed. */
    Scope current(Call call, Scope s) throws RpcFailure {
        if (s.fresh()) {
            return s;
        }
        Freshness f = freshness(s.profile());
        long now = System.nanoTime();
        long verified = f.verified;
        boolean known = verified != Long.MIN_VALUE;
        if (known && now - verified <= plan.keysMaxAge().toNanos()) {
            return s;
        }
        RuntimeException recent = f.recentFailure(now);
        if (recent != null) {
            throw stale(s, known, now - verified, recent);
        }
        try {
            return s.withKeys(load(call, s.profile()));
        } catch (RpcFailure e) {
            RuntimeException mapped = new CipheronException(e.getMessage(), e);
            if (!call.ended()) {
                f.failed(System.nanoTime(), mapped);
            }
            throw stale(s, known, now - verified, mapped);
        } catch (RuntimeException e) {
            if (!call.ended()) {
                f.failed(System.nanoTime(), e);
            }
            throw stale(s, known, now - verified, e);
        }
    }

    private KeysStaleException stale(Scope s, boolean known, long ageNanos, Throwable cause) {
        String when = known ? "was last verified " + Duration.ofNanos(ageNanos).toSeconds() + "s ago"
                : "has no age this client can measure";
        return new KeysStaleException("cipheron: the profile's signing-key list is too old and could not be fetched "
                + "again (" + s.who() + ": the key list " + when + ", and the maximum is " + plan.keysMaxAge() + "): "
                + cause.getMessage(), cause);
    }

    // ── requests and answers ───────────────────────────────────────────────────────────────────────────────

    static byte[] newNonce() {
        byte[] n = new byte[16];
        RANDOM.nextBytes(n);
        return n;
    }

    /** The message-size bound: refused before anything is sent. */
    void fits(String profile, long payload) {
        long limit = (long) plan.maxMessage() - Plan.WIRE_OVERHEAD - Bytes.utf8(profile).length;
        if (payload > limit) {
            throw new TooLargeException("cipheron: too large: " + payload + " bytes, and this client's messages carry "
                    + "at most " + Math.max(limit, 0) + " (maxMessageBytes)");
        }
    }

    /** The request's auth, signed now; null without a request key. */
    Cipheron.RequestAuth auth(String profile, String op, byte[] nonce, byte[] digest) {
        open();
        if (plan.requestKey() == null) {
            return null;
        }
        long ts = System.currentTimeMillis();
        try {
            byte[] sig = Ed25519.sign(plan.requestKey(), Transcripts.request(profile, op, ts, nonce, digest));
            return Cipheron.RequestAuth.newBuilder().setTimestampMs(ts).setSignature(ByteString.copyFrom(sig)).build();
        } catch (GeneralSecurityException e) {
            throw new CipheronException("cipheron: signing the request: " + e.getMessage(), e);
        }
    }

    static byte[] sigOf(Cipheron.RequestAuth a) {
        return a == null ? Bytes.EMPTY : a.getSignature().toByteArray();
    }

    /** Re-fetches the keys after a refusal that may be an identity change: the change wins over the refusal. */
    RpcFailure suspect(Call call, String profile, RpcFailure orig) throws RpcFailure {
        try {
            load(call, profile);
        } catch (ServerKeyChangedException e) {
            throw e;
        } catch (RpcFailure | RuntimeException e) {
            // Not a key change: the refusal stands.
        }
        return orig;
    }

    /**
     * Verifies an answer's response signature under the context digests this client accepts: the pinned ones, else
     * every one the profile's verified PublicKey answers gave; one it has not seen is learnt by a fetch.
     */
    void verifyResponse(Call call, String profile, ProfileKeys k, String op, byte[] nonce, Cipheron.RequestAuth sent,
            byte[] reqDigest, byte[] respDigest, byte[] sig) throws RpcFailure {
        if (sig.length == 0) {
            throw suspectIdentity(call, profile, identityFailure("the " + op + " answer for profile \"" + profile
                    + "\" carries no response signature"));
        }
        byte[] sentSig = sigOf(sent);
        Predicate<String> verifies = dg -> Ed25519.verify(k.identity.response(),
                Transcripts.response(profile, dg, op, nonce, sentSig, reqDigest, respDigest), sig);
        List<String> pinned = pinsNow().contextDigests(profile);
        List<String> accepted = new ArrayList<>();
        if (pinned != null) {
            accepted.addAll(pinned);
        } else {
            accepted.addAll(seenContexts(profile));
            accepted.add(k.contextDigest);
        }
        for (String d : accepted) {
            if (verifies.test(d)) {
                return;
            }
        }
        List<String> tried = new ArrayList<>(accepted);
        if (pinned != null) {
            String d = unpinned(profile, tried, verifies);
            if (d != null) {
                throw refusedContext(profile, op, d, pinned);
            }
        }
        try {
            loadUnless(call, profile, x -> {
                for (String d : seenContexts(profile)) {
                    if (!tried.contains(d) && verifies.test(d)) {
                        return true;
                    }
                }
                return false;
            });
        } catch (ServerKeyChangedException e) {
            throw e;
        } catch (RpcFailure | RuntimeException e) {
            // The fetch failed: the answer is judged on what is known.
        }
        String d = unpinned(profile, tried, verifies);
        if (d != null) {
            if (pinned != null) {
                throw refusedContext(profile, op, d, pinned);
            }
            return;
        }
        throw identityFailure("the " + op + " answer for profile \"" + profile + "\" is not signed by the profile's "
                + "response key under a key context this client accepts");
    }

    private String unpinned(String profile, List<String> tried, Predicate<String> verifies) {
        for (String d : seenContexts(profile)) {
            if (!tried.contains(d)) {
                tried.add(d);
                if (verifies.test(d)) {
                    return d;
                }
            }
        }
        return null;
    }

    private ContextDigestException refusedContext(String profile, String op, String d, List<String> pinned) {
        refuseContext(profile);
        return new ContextDigestException("cipheron: the " + op + " answer for profile \"" + profile + "\" was made by "
                + "a replica on key context " + d + "; this client pins " + String.join(", ", pinned));
    }

    private ServerIdentityException suspectIdentity(Call call, String profile, ServerIdentityException orig) {
        try {
            load(call, profile);
        } catch (ServerKeyChangedException e) {
            throw e;
        } catch (RpcFailure | RuntimeException e) {
            // Not a key change.
        }
        return orig;
    }

    /** Checks the writer pin: a profile pinned to writer versions accepts data made under them only. */
    void checkWriter(String profile, String version, String what) {
        List<String> vs = pinsNow().writerVersions(profile);
        if (vs == null || vs.contains(version)) {
            return;
        }
        throw new ContextDigestException("cipheron: profile \"" + profile + "\" answered " + what + " made under "
                + "master key version \"" + version + "\"; this client pins the writer to " + String.join(", ", vs));
    }

    /**
     * Checks an answered ciphertext: of the profile's format (master version, or the blob's tenant key), of the
     * plaintext's length plus the format's overhead, with associated data exactly when asked.
     */
    void checkCiphertext(Scope s, byte[] ct, int n, byte[] keyId, boolean withAad) {
        boolean tenantKey = s.k().wrapped();
        Ciphertexts.KeyId kid;
        try {
            kid = Ciphertexts.parse(ct);
        } catch (Ciphertexts.Refused e) {
            if (e.unknownFormat()) {
                throw badResponse("the ciphertext answered for " + s.who() + " is in a format this protocol does not "
                        + "have (" + e.getMessage() + ")");
            }
            throw badResponse("the ciphertext for " + s.who() + " is not in the " + s.k().tenancy()
                    + " profile's format under the expected key for a " + n + "-byte plaintext");
        }
        boolean ok = ct.length == n + kid.overhead() && kid.associatedData() == withAad
                && kid.tenantKey() == tenantKey;
        if (tenantKey) {
            ok = ok && keyId != null && Bytes.constantTimeEquals(kid.tenantKeyId(), keyId);
        }
        if (!ok) {
            throw badResponse("the ciphertext for " + s.who() + " is not in the " + s.k().tenancy()
                    + " profile's format under the expected key for a " + n + "-byte plaintext");
        }
        if (!tenantKey) {
            checkWriter(s.profile(), kid.masterVersion(), "a ciphertext");
        }
    }

    /** Seals a payload to the profile's HPKE key under the request's info, bound to the request key. */
    Hpke.Sealed seal(Scope s, String op, byte[] payload) {
        String why = s.k().identity.usable();
        if (why != null) {
            throw badResponse("(" + s.who() + "): " + why);
        }
        try {
            return Hpke.seal(s.k().identity.hpke(), Transcripts.requestSealInfo(s.profile(), op, s.tenant(),
                    plan.requestPublicKey()), payload);
        } catch (GeneralSecurityException e) {
            throw new CipheronException("cipheron: sealing the request: " + e.getMessage(), e);
        }
    }

    static ByteString bs(byte[] b) {
        return b == null ? ByteString.EMPTY : ByteString.copyFrom(b);
    }

    // ── shared keys, and the single operations ─────────────────────────────────────────────────────────────

    /** The profile's keys, refused unless it is shared (a tenant call names a tenant). */
    Fetched sharedKeys(Call call, String profile) throws RpcFailure {
        Fetched f = cachedOrFetched(call, profile);
        if (!"shared".equals(f.keys.tenancy())) {
            throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                    + "tenancy: profile \"" + profile + "\" is " + f.keys.tenancy() + ": its calls name a tenant");
        }
        return f;
    }

    byte[] encrypt(Call call, Scope s, byte[] plaintext, byte[] aad) throws RpcFailure {
        return retryCall(call, s.profile(), () -> encryptOnce(call, s, plaintext, aad));
    }

    private byte[] encryptOnce(Call call, Scope s, byte[] plaintext, byte[] aad) throws RpcFailure {
        Hpke.Sealed sealed = seal(s, "encrypt", plaintext);
        byte[] nonce = newNonce();
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.encrypt(sealed.enc(), sealed.ciphertext(),
                s.tenant(), s.blob(), aad);
        Cipheron.RequestAuth auth = auth(s.profile(), "encrypt", nonce, reqDigest);
        Cipheron.EncryptRequest.Builder b = Cipheron.EncryptRequest.newBuilder().setProfile(s.profile())
                .setEnc(bs(sealed.enc())).setSealedPlaintext(bs(sealed.ciphertext())).setRequestNonce(bs(nonce))
                .setTenant(s.tenant()).setTenantKey(bs(s.blob())).setAssociatedData(bs(aad));
        if (auth != null) {
            b.setAuth(auth);
        }
        Cipheron.EncryptResponse resp;
        try {
            resp = pick().call(Op.ENCRYPT, b.build(), call.requestId(), call.deadline());
        } catch (RpcFailure f) {
            if (f.code() == Refusals.INVALID_ARGUMENT) {
                throw suspect(call, s.profile(), f);
            }
            throw f;
        }
        byte[] ct = resp.getCiphertext().toByteArray();
        verifyResponse(call, s.profile(), s.k(), "encrypt", nonce, auth, reqDigest,
                io.github.nnicora.cipheron.internal.wire.Digests.ciphertextResponse(ct),
                resp.getResponseSignature().toByteArray());
        checkCiphertext(s, ct, plaintext.length, s.h() == null ? null : s.h().keyId(), aad != null && aad.length > 0);
        return ct;
    }

    /** Checks a ciphertext the caller gives: a format this release reads, and the associated data it takes. */
    static Ciphertexts.KeyId parseCiphertext(Scope s, byte[] ct, byte[] aad) {
        Ciphertexts.KeyId kid;
        try {
            kid = Ciphertexts.parse(ct);
        } catch (Ciphertexts.Refused e) {
            throw new io.github.nnicora.cipheron.InvalidInputException("cipheron: invalid input: the ciphertext given "
                    + "for " + s.who() + ": " + e.getMessage(), e);
        }
        String why = Ciphertexts.checkAssociatedData(kid, aad);
        if (why != null) {
            throw new io.github.nnicora.cipheron.AssociatedDataException("cipheron: the associated data does not "
                    + "match the ciphertext's format: the ciphertext given for " + s.who() + ": " + why);
        }
        return kid;
    }

    byte[] decrypt(Call call, Scope s, byte[] ciphertext, byte[] aad) throws RpcFailure {
        return retryCall(call, s.profile(), () -> decryptOnce(call, s, ciphertext, aad));
    }

    private byte[] decryptOnce(Call call, Scope s, byte[] ciphertext, byte[] aad) throws RpcFailure {
        parseCiphertext(s, ciphertext, aad);
        java.security.KeyPair one;
        try {
            one = io.github.nnicora.cipheron.internal.crypto.P256.generate();
        } catch (GeneralSecurityException e) {
            throw new CipheronException("cipheron: a one-time key: " + e.getMessage(), e);
        }
        byte[] recipient = io.github.nnicora.cipheron.internal.crypto.P256.encode(one.getPublic());
        byte[] nonce = newNonce();
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.decrypt(recipient, ciphertext, s.tenant(),
                s.blob(), aad);
        Cipheron.RequestAuth auth = auth(s.profile(), "decrypt", nonce, reqDigest);
        Cipheron.DecryptRequest.Builder b = Cipheron.DecryptRequest.newBuilder().setProfile(s.profile())
                .setRecipientPublicKey(bs(recipient)).setCiphertext(bs(ciphertext)).setRequestNonce(bs(nonce))
                .setTenant(s.tenant()).setTenantKey(bs(s.blob())).setAssociatedData(bs(aad));
        if (auth != null) {
            b.setAuth(auth);
        }
        Cipheron.DecryptResponse resp = pick().call(Op.DECRYPT, b.build(), call.requestId(), call.deadline());
        byte[] enc = resp.getEnc().toByteArray();
        byte[] sealed = resp.getSealedPlaintext().toByteArray();
        verifyResponse(call, s.profile(), s.k(), "decrypt", nonce, auth, reqDigest,
                io.github.nnicora.cipheron.internal.wire.Digests.decryptResponse(recipient, enc, sealed),
                resp.getResponseSignature().toByteArray());
        try {
            return Hpke.open(one.getPrivate(), recipient, Transcripts.responseSealInfo(s.profile(), "decrypt",
                    s.tenant()), enc, sealed);
        } catch (GeneralSecurityException e) {
            throw badResponse("the plaintext for " + s.who() + ": cipheron: the sealed payload could not be opened");
        }
    }

    byte[] reEncrypt(Call call, Scope s, byte[] ciphertext, byte[] to, TenantKeys.Header toHeader, byte[] aad,
            byte[] toAad) throws RpcFailure {
        return retryCall(call, s.profile(), () -> reEncryptOnce(call, s, ciphertext, to, toHeader, aad, toAad));
    }

    private byte[] reEncryptOnce(Call call, Scope s, byte[] ciphertext, byte[] to, TenantKeys.Header toHeader,
            byte[] aad, byte[] toAad) throws RpcFailure {
        Ciphertexts.KeyId kid = parseCiphertext(s, ciphertext, aad);
        int n = ciphertext.length - kid.overhead();
        byte[] nonce = newNonce();
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.reEncrypt(ciphertext, s.tenant(), s.blob(),
                to, aad, toAad, "", "");
        Cipheron.RequestAuth auth = auth(s.profile(), "reencrypt", nonce, reqDigest);
        Cipheron.ReEncryptRequest.Builder b = Cipheron.ReEncryptRequest.newBuilder().setProfile(s.profile())
                .setCiphertext(bs(ciphertext)).setTenant(s.tenant()).setTenantKey(bs(s.blob())).setToTenantKey(bs(to))
                .setRequestNonce(bs(nonce)).setAssociatedData(bs(aad)).setToAssociatedData(bs(toAad));
        if (auth != null) {
            b.setAuth(auth);
        }
        Cipheron.ReEncryptResponse resp = pick().call(Op.RE_ENCRYPT, b.build(), call.requestId(), call.deadline());
        byte[] ct = resp.getCiphertext().toByteArray();
        verifyResponse(call, s.profile(), s.k(), "reencrypt", nonce, auth, reqDigest,
                io.github.nnicora.cipheron.internal.wire.Digests.ciphertextResponse(ct),
                resp.getResponseSignature().toByteArray());
        checkCiphertext(s, ct, n, toHeader == null ? null : toHeader.keyId(), toAad != null && toAad.length > 0);
        return ct;
    }

    /** A signature and the id of the key that made it. */
    public record Signed(byte[] signature, byte[] keyId) {}

    Signed sign(Call call, Scope s, byte[] data) throws RpcFailure {
        return retryCall(call, s.profile(), () -> signOnce(call, s, data));
    }

    private Signed signOnce(Call call, Scope s, byte[] data) throws RpcFailure {
        Hpke.Sealed sealed = seal(s, "sign", data);
        byte[] nonce = newNonce();
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.sign(sealed.enc(), sealed.ciphertext(),
                s.tenant(), s.blob());
        Cipheron.RequestAuth auth = auth(s.profile(), "sign", nonce, reqDigest);
        Cipheron.SignRequest.Builder b = Cipheron.SignRequest.newBuilder().setProfile(s.profile())
                .setEnc(bs(sealed.enc())).setSealedData(bs(sealed.ciphertext())).setRequestNonce(bs(nonce))
                .setTenant(s.tenant()).setTenantKey(bs(s.blob()));
        if (auth != null) {
            b.setAuth(auth);
        }
        Cipheron.SignResponse resp;
        try {
            resp = pick().call(Op.SIGN, b.build(), call.requestId(), call.deadline());
        } catch (RpcFailure f) {
            if (f.code() == Refusals.INVALID_ARGUMENT) {
                throw suspect(call, s.profile(), f);
            }
            throw f;
        }
        byte[] sig = resp.getSignature().toByteArray();
        byte[] keyId = resp.getKeyId().toByteArray();
        verifyResponse(call, s.profile(), s.k(), "sign", nonce, auth, reqDigest,
                io.github.nnicora.cipheron.internal.wire.Digests.signResponse(sig, keyId),
                resp.getResponseSignature().toByteArray());
        if (sig.length != Ed25519.SIGNATURE_LEN || keyId.length != SigningKeys.KEY_ID_LEN) {
            throw identityFailure("the signature answered for " + s.who() + " is not a 64-byte signature under a "
                    + "16-byte key id");
        }
        if (s.k().wrapped()) {
            if (!Bytes.constantTimeEquals(keyId, s.h().keyId()) || !Ed25519.verify(s.h().signingPublicKey(), data, sig)) {
                throw identityFailure("the signature answered for " + s.who() + " is not by the tenant key of the blob");
            }
            return new Signed(sig, keyId);
        }
        Scope cur = current(call, s);
        SigningKeys.Key key = answeredSigningKey(call, cur, keyId);
        if (key == null) {
            throw identityFailure("the signature answered for " + cur.who() + " names signing key " + Bytes.hex(keyId)
                    + ", which is not in the profile's authenticated list");
        }
        keyUsable(key, cur.who());
        if (!verifyUnder(cur, key.publicKey(), data, sig)) {
            throw identityFailure("the signature answered for " + cur.who() + " does not verify under the profile's "
                    + "signing key " + Bytes.hex(keyId));
        }
        return new Signed(sig, keyId);
    }

    static boolean verifyUnder(Scope s, byte[] pub, byte[] data, byte[] sig) {
        if ("perTenantDerived".equals(s.k().tenancy())) {
            return Ed25519.verify(pub, TenantKeys.signedMessage(s.profile(), s.tenant(), data), sig);
        }
        return Ed25519.verify(pub, data, sig);
    }

    /** Refuses a key that does not verify: revoked, or of an algorithm this client does not implement. */
    static void keyUsable(SigningKeys.Key key, String who) {
        if (SigningKeys.REVOKED.equals(key.state())) {
            throw new SigningKeyRevokedException("cipheron: the signing key is revoked (" + who + ", key id "
                    + Bytes.hex(key.keyId()) + "): the profile revoked it: no signature under it is accepted");
        }
        if (!key.usable()) {
            throw badResponse("(" + who + ", key id " + Bytes.hex(key.keyId()) + "): the key's algorithm (number "
                    + key.effectiveAlgorithm() + ") is not one this client implements");
        }
    }

    private SigningKeys.Key knownSigningKey(Scope s, byte[] keyId) {
        ProfileKeys k = keys.get(s.profile());
        if (k != null) {
            SigningKeys.Key key = k.signingKey(keyId);
            if (key != null) {
                return key;
            }
        }
        return s.k().signingKey(keyId);
    }

    private SigningKeys.Key answeredSigningKey(Call call, Scope s, byte[] keyId) throws RpcFailure {
        SigningKeys.Key key = knownSigningKey(s, keyId);
        if (key != null || keyId.length != SigningKeys.KEY_ID_LEN) {
            return key;
        }
        ProfileKeys k = loadUnless(call, s.profile(), x -> x.signingKey(keyId) != null);
        return k.signingKey(keyId);
    }

    private UnknownSigningKeyException unknownKey(Scope s, byte[] keyId, String why, Throwable cause) {
        String msg = "cipheron: the signature names a signing key this client does not know (" + s.who() + ", key id "
                + Bytes.hex(keyId) + "): " + why;
        return cause == null ? new UnknownSigningKeyException(msg)
                : new UnknownSigningKeyException(msg + ": " + cause.getMessage(), cause);
    }

    /** Verifies a signature under the profile's listed key {@code keyId} names, honouring its state. */
    boolean verify(Call call, Scope s, byte[] data, byte[] sig, byte[] keyId) throws RpcFailure {
        Scope cur = current(call, s);
        SigningKeys.Key key = knownSigningKey(cur, keyId);
        if (key == null) {
            if (keyId.length != SigningKeys.KEY_ID_LEN) {
                throw unknownKey(cur, keyId, "a signing key id is 16 bytes, not " + keyId.length, null);
            }
            if (cur.fresh()) {
                throw unknownKey(cur, keyId, "the profile's key list, fetched now, does not name it", null);
            }
            if (!claimVerifyFetch(cur.profile())) {
                throw unknownKey(cur, keyId, "it is not in the profile's key list as last fetched, and the list is "
                        + "fetched again for an unknown key id at most every 5s: try again then", null);
            }
            ProfileKeys k;
            try {
                k = load(call, cur.profile());
            } catch (RpcFailure | RuntimeException e) {
                throw unknownKey(cur, keyId, "the profile's keys could not be fetched again", e);
            }
            key = k.signingKey(keyId);
            if (key == null) {
                throw unknownKey(cur, keyId, "the profile's key list, fetched again now, does not name it", null);
            }
        }
        keyUsable(key, cur.who());
        return verifyUnder(cur, key.publicKey(), data, sig);
    }

    // ── tenancy ────────────────────────────────────────────────────────────────────────────────────────────

    /** Checks a blob given for a tenant: a tenant id, this tenant's key in this profile, the pinned one. */
    TenantKeys.Header checkBlob(String profile, String tenant, byte[] blob) {
        if (!Grammar.validTenant(tenant)) {
            throw notATenant(tenant);
        }
        TenantKeys.Header h;
        try {
            h = TenantKeys.check(blob, profile, tenant);
        } catch (TenantKeys.Refused e) {
            throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: the blob given "
                    + "for tenant \"" + tenant + "\" of profile \"" + profile + "\": " + e.getMessage(), e);
        }
        String pin = plan.tenantPins().get(Plan.tenantRef(profile, tenant));
        if (pin != null && !Bytes.constantTimeEquals(h.fingerprint(), pin)) {
            throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: the blob given "
                    + "for tenant \"" + tenant + "\" of profile \"" + profile + "\" is the key " + h.fingerprint()
                    + ", not the pinned " + pin);
        }
        return h;
    }

    static io.github.nnicora.cipheron.TenantKeyException notATenant(String tenant) {
        String shown = tenant.length() <= 32 ? "\"" + tenant + "\""
                : "\"" + tenant.substring(0, 32) + "\"… (" + Bytes.utf8(tenant).length + " bytes)";
        return new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: " + shown
                + " is not a tenant id (1 to 2048 bytes of printable ASCII, 0x21 to 0x7E)");
    }

    /** A wrapped profile's keys, refused for any other tenancy. */
    ProfileKeys wrappedKeys(Call call, String profile) throws RpcFailure {
        ProfileKeys k = keys(call, profile);
        if (!k.wrapped()) {
            throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                    + "tenancy: profile \"" + profile + "\" is " + k.tenancy() + ": it has no tenant key blobs");
        }
        return k;
    }

    /** A tenant key, as a call answers it. */
    public record TenantKeyOut(byte[] blob, byte[] keyId, byte[] signingPublicKey, String fingerprint) {}

    private static TenantKeys.Header tenantKeyAnswer(String profile, String tenant, byte[] blob, byte[] pub,
            String fp) {
        try {
            TenantKeys.Header h = TenantKeys.check(blob, profile, tenant);
            if (Arrays.equals(h.signingPublicKey(), pub) && h.fingerprint().equals(fp)) {
                return h;
            }
        } catch (TenantKeys.Refused e) {
            // Refused below.
        }
        throw badResponse("the tenant key answered for tenant \"" + tenant + "\" of profile \"" + profile
                + "\" is not the one its answer names");
    }

    TenantKeyOut createTenantKey(Call call, String profile, String tenant) throws RpcFailure {
        if (!Grammar.validTenant(tenant)) {
            throw notATenant(tenant);
        }
        ProfileKeys k = wrappedKeys(call, profile);
        return afterStart(call, profile, () -> {
            byte[] nonce = newNonce();
            byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.provision(tenant);
            Cipheron.RequestAuth auth = auth(profile, "provision", nonce, reqDigest);
            Cipheron.CreateTenantKeyRequest.Builder b = Cipheron.CreateTenantKeyRequest.newBuilder()
                    .setProfile(profile).setTenant(tenant).setRequestNonce(bs(nonce));
            if (auth != null) {
                b.setAuth(auth);
            }
            Cipheron.CreateTenantKeyResponse resp = pick().call(Op.CREATE_TENANT_KEY, b.build(), call.requestId(),
                    call.deadline());
            byte[] blob = resp.getTenantKey().toByteArray();
            byte[] pub = resp.getSigningPublicKey().toByteArray();
            String fp = resp.getFingerprint();
            verifyResponse(call, profile, k, "provision", nonce, auth, reqDigest,
                    io.github.nnicora.cipheron.internal.wire.Digests.tenantKeyResponse(blob, pub, fp),
                    resp.getResponseSignature().toByteArray());
            TenantKeys.Header h = tenantKeyAnswer(profile, tenant, blob, pub, fp);
            checkWriter(profile, h.wrappingVersion(), "a tenant key blob");
            return new TenantKeyOut(blob, h.keyId(), h.signingPublicKey(), h.fingerprint());
        });
    }

    TenantKeyOut rewrapTenantKey(Call call, String profile, String tenant, byte[] blob) throws RpcFailure {
        TenantKeys.Header old = checkBlob(profile, tenant, blob);
        fits(profile, 2L * blob.length + Bytes.utf8(tenant).length);
        ProfileKeys k = wrappedKeys(call, profile);
        return afterStart(call, profile, () -> {
            byte[] nonce = newNonce();
            byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.rewrapTenantKey(tenant, blob);
            Cipheron.RequestAuth auth = auth(profile, "rewrap-tenant-key", nonce, reqDigest);
            Cipheron.RewrapTenantKeyRequest.Builder b = Cipheron.RewrapTenantKeyRequest.newBuilder()
                    .setProfile(profile).setTenant(tenant).setTenantKey(bs(blob)).setRequestNonce(bs(nonce));
            if (auth != null) {
                b.setAuth(auth);
            }
            Cipheron.RewrapTenantKeyResponse resp = pick().call(Op.REWRAP_TENANT_KEY, b.build(), call.requestId(),
                    call.deadline());
            byte[] nb = resp.getTenantKey().toByteArray();
            byte[] pub = resp.getSigningPublicKey().toByteArray();
            String fp = resp.getFingerprint();
            verifyResponse(call, profile, k, "rewrap-tenant-key", nonce, auth, reqDigest,
                    io.github.nnicora.cipheron.internal.wire.Digests.tenantKeyResponse(nb, pub, fp),
                    resp.getResponseSignature().toByteArray());
            TenantKeys.Header h = rewrapAnswer(profile, tenant, old, nb, pub, fp);
            checkWriter(profile, h.wrappingVersion(), "a tenant key blob");
            return new TenantKeyOut(nb, h.keyId(), h.signingPublicKey(), h.fingerprint());
        });
    }

    static TenantKeys.Header rewrapAnswer(String profile, String tenant, TenantKeys.Header old, byte[] nb, byte[] pub,
            String fp) {
        TenantKeys.Header h = tenantKeyAnswer(profile, tenant, nb, pub, fp);
        if (!Bytes.constantTimeEquals(h.keyId(), old.keyId()) || !Arrays.equals(h.signingPublicKey(),
                old.signingPublicKey()) || !fp.equals(old.fingerprint()) || h.created() != old.created()) {
            throw badResponse("the rewrapped key answered for tenant \"" + tenant + "\" of profile \"" + profile
                    + "\" is not the key sent (a rewrap keeps the key id, the signing key, the fingerprint and the "
                    + "creation time)");
        }
        return h;
    }

    /** The scope of a tenant call: the profile's keys, and the tenant and blob its tenancy needs. */
    Scope tenantScope(Call call, String profile, String tenant, byte[] blob, TenantKeys.Header h, long payload)
            throws RpcFailure {
        open();
        fits(profile, payload + (blob == null ? 0 : blob.length) + Bytes.utf8(tenant).length);
        Fetched f = cachedOrFetched(call, profile);
        switch (f.keys.tenancy()) {
            case "perTenantWrapped":
                if (blob == null) {
                    throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: tenant \""
                            + tenant + "\" of profile \"" + profile + "\": a wrapped profile's calls carry the "
                            + "tenant's key blob");
                }
                break;
            case "perTenantDerived":
                if (blob != null) {
                    throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the "
                            + "profile's tenancy: profile \"" + profile + "\" is perTenantDerived: its tenants have "
                            + "no key blob");
                }
                break;
            default:
                throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                        + "tenancy: profile \"" + profile + "\" is " + f.keys.tenancy() + ": it has no tenants");
        }
        return new Scope(profile, f.keys, tenant, blob, h, f.fresh);
    }

    /** The shared scope of a profile. */
    Scope sharedScope(Call call, String profile) throws RpcFailure {
        Fetched f = sharedKeys(call, profile);
        return new Scope(profile, f.keys, "", null, null, f.fresh);
    }

    /** The keys of a profile, for {@code Keys}: the identity, the list, the context digest. */
    public ProfileView keysOf(Call call, String profile) throws RpcFailure {
        open();
        ProfileKeys k = load(call, profile);
        return new ProfileView(k.profile, k.identity, k.fingerprint, k.signingKeys, k.contextDigest, k.statement,
                k.statementSignature);
    }

    /**
     * The newest key statement this client verified that agrees with the signing-key list it holds, no older than
     * the keys' maximum age: none is handed out when a replica lags a revocation, or when no statement agrees.
     */
    public KeyStatements.Statement keyStatement(Call call, String profile, byte[][] rawAndSig) throws RpcFailure {
        open();
        ProfileKeys k = load(call, profile);
        long age = System.nanoTime() - k.statementAtNanos;
        if (k.statement == null && k.statementRevoked) {
            throw new SigningKeyRevokedException("cipheron: the signing key is revoked (profile \"" + profile + "\"): "
                    + "the key statements cipheron answered list as usable a signing key this client holds revoked (a "
                    + "replica that lags the revocation): none is handed out");
        }
        if (k.statement == null) {
            throw new KeysStaleException("cipheron: the profile's signing-key list is too old (profile \"" + profile
                    + "\"): no key statement this client verified agrees with the signing-key list it holds");
        }
        if (age > plan.keysMaxAge().toNanos() || age < 0) {
            throw new KeysStaleException("cipheron: the profile's signing-key list is too old (profile \"" + profile
                    + "\"): the newest key statement that agrees with it was verified "
                    + Duration.ofNanos(age).toSeconds() + "s ago, and the maximum is " + plan.keysMaxAge());
        }
        try {
            KeyStatements.Statement st = KeyStatements.verify(k.statement, k.statementSignature, profile, k.fingerprint);
            rawAndSig[0] = k.statement.clone();
            rawAndSig[1] = k.statementSignature.clone();
            return st;
        } catch (KeyStatements.Refused e) {
            throw new io.github.nnicora.cipheron.KeyStatementException(e.getMessage(), e);
        }
    }

    /** A profile's verified keys, as the public API shows them. */
    public record ProfileView(String profile, Identity identity, String fingerprint, List<SigningKeys.Key> signingKeys,
            String contextDigest, byte[] statement, byte[] statementSignature) {}

    // ── the public facade's entry points ───────────────────────────────────────────────────────────────────

    public byte[] encrypt(Call call, String profile, byte[] plaintext, byte[] aad) throws RpcFailure {
        open();
        fits(profile, (long) plaintext.length + len(aad) + 98);
        return encrypt(call, sharedScope(call, profile), plaintext, aad);
    }

    public byte[] decrypt(Call call, String profile, byte[] ciphertext, byte[] aad) throws RpcFailure {
        open();
        fits(profile, (long) ciphertext.length + len(aad));
        return decrypt(call, sharedScope(call, profile), ciphertext, aad);
    }

    public byte[] reEncrypt(Call call, String profile, byte[] ciphertext, byte[] aad, byte[] toAad) throws RpcFailure {
        open();
        reEncryptOptions(aad, toAad);
        fits(profile, (long) ciphertext.length + len(aad) + len(toAad) + 98);
        return reEncrypt(call, sharedScope(call, profile), ciphertext, null, null, aad, toAad);
    }

    public Signed sign(Call call, String profile, byte[] data) throws RpcFailure {
        open();
        fits(profile, data.length);
        return sign(call, sharedScope(call, profile), data);
    }

    public boolean verify(Call call, String profile, byte[] data, byte[] sig, byte[] keyId) throws RpcFailure {
        open();
        Fetched f = sharedKeys(call, profile);
        return verify(call, new Scope(profile, f.keys, "", null, null, f.fresh), data, sig, keyId);
    }

    public TenantKeyOut createTenantKeyCall(Call call, String profile, String tenant) throws RpcFailure {
        open();
        return createTenantKey(call, profile, tenant);
    }

    public TenantKeyOut rewrapTenantKeyCall(Call call, String profile, String tenant, byte[] blob) throws RpcFailure {
        open();
        return rewrapTenantKey(call, profile, tenant, blob);
    }

    /** A tenant handle's state: its profile, tenant, blob and the blob's header (or the handle's refusal). */
    public TenantRef tenant(String profile, String tenant, byte[] blob) {
        if (!Grammar.validTenant(tenant)) {
            return new TenantRef(profile, tenant, null, null, notATenant(tenant));
        }
        if (blob == null) {
            return new TenantRef(profile, tenant, null, null, null);
        }
        byte[] b = blob.clone();
        try {
            return new TenantRef(profile, tenant, b, checkBlob(profile, tenant, b), null);
        } catch (CipheronException e) {
            return new TenantRef(profile, tenant, b, null, e);
        }
    }

    /** A tenant handle. */
    public record TenantRef(String profile, String tenant, byte[] blob, TenantKeys.Header header,
            CipheronException refusal) {}

    private Scope scopeOf(Call call, TenantRef t, long payload) throws RpcFailure {
        if (t.refusal() != null) {
            throw t.refusal();
        }
        return tenantScope(call, t.profile(), t.tenant(), t.blob(), t.header(), payload);
    }

    public byte[] tenantEncrypt(Call call, TenantRef t, byte[] plaintext, byte[] aad) throws RpcFailure {
        return encrypt(call, scopeOf(call, t, (long) plaintext.length + len(aad) + 98), plaintext, aad);
    }

    public byte[] tenantDecrypt(Call call, TenantRef t, byte[] ciphertext, byte[] aad) throws RpcFailure {
        return decrypt(call, scopeOf(call, t, (long) ciphertext.length + len(aad)), ciphertext, aad);
    }

    public byte[] tenantReEncrypt(Call call, TenantRef t, byte[] ciphertext, byte[] to, byte[] aad, byte[] toAad)
            throws RpcFailure {
        reEncryptOptions(aad, toAad);
        Scope s = scopeOf(call, t, (long) ciphertext.length + len(to) + len(aad) + len(toAad) + 98);
        TenantKeys.Header toHeader = null;
        if (s.k().wrapped()) {
            if (to == null) {
                throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: ReEncrypt for "
                        + s.who() + ": a wrapped profile re-encrypts under a tenant key blob (to)");
            }
            try {
                toHeader = TenantKeys.check(to, t.profile(), t.tenant());
            } catch (TenantKeys.Refused e) {
                throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: the target "
                        + "blob given for " + s.who() + ": " + e.getMessage(), e);
            }
        } else if (to != null) {
            throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                    + "tenancy: profile \"" + t.profile() + "\" is " + s.k().tenancy() + ": ReEncrypt has no target "
                    + "blob");
        }
        return reEncrypt(call, s, ciphertext, to == null ? null : to.clone(), toHeader, aad, toAad);
    }

    public Signed tenantSign(Call call, TenantRef t, byte[] data) throws RpcFailure {
        return sign(call, scopeOf(call, t, data.length), data);
    }

    public boolean tenantVerify(Call call, TenantRef t, byte[] data, byte[] sig, byte[] keyId) throws RpcFailure {
        Scope s = scopeOf(call, t, 0);
        if (s.k().wrapped()) {
            return Bytes.constantTimeEquals(keyId, s.h().keyId()) && Ed25519.verify(s.h().signingPublicKey(), data, sig);
        }
        return verify(call, s, data, sig, keyId);
    }

    // ── batches ────────────────────────────────────────────────────────────────────────────────────────────

    /** The most items one batch holds. */
    public static final int MAX_BATCH_ITEMS = 4096;

    /** One item of a batch: its data, and its associated data and target associated data. */
    public record Item(byte[] data, byte[] aad, byte[] toAad) {}

    /** One item's outcome: its value, or the refusal cipheron answered for it alone. */
    public record ItemResult(byte[] value, RpcFailure error) {}

    static RpcFailure itemFailure(Cipheron.ItemError e, String requestId) {
        String reason = e.getReason().isEmpty() ? null : e.getReason();
        return new RpcFailure(e.getCode(), e.getMessage(), reason == null ? null : Refusals.DOMAIN, reason, null, false,
                false, requestId, null);
    }

    /** An item error the client refuses to believe: one that says nothing about the item, or one with a result. */
    private static void itemErrorAlone(Scope s, int i, Cipheron.ItemError e, byte[]... result) {
        for (byte[] f : result) {
            if (f.length > 0) {
                throw identityFailure("batch item " + i + " answered for " + s.who() + " is an error that also "
                        + "carries a result, which the response signature does not cover");
            }
        }
        switch (e.getCode()) {
            case 0, 14, 8, 13, 2, 9 -> throw badResponse("batch item " + i + ": a batch item error for " + s.who()
                    + " with code " + e.getCode());
            default -> {
                // A refusal of the item alone.
            }
        }
    }

    private void verifyBatch(Call call, Scope s, String op, byte[] nonce, Cipheron.RequestAuth auth, byte[] reqDigest,
            byte[] sig, int n, int sent, java.util.function.IntFunction<byte[]> itemDigest) throws RpcFailure {
        if (n > MAX_BATCH_ITEMS) {
            throw identityFailure("the " + op + " answer for " + s.who() + " holds " + n + " results; no batch holds "
                    + "more than " + MAX_BATCH_ITEMS);
        }
        byte[][] rd = new byte[n][];
        for (int i = 0; i < n; i++) {
            rd[i] = itemDigest.apply(i);
        }
        verifyResponse(call, s.profile(), s.k(), op, nonce, auth, reqDigest,
                io.github.nnicora.cipheron.internal.wire.Digests.batch(rd), sig);
        if (n != sent) {
            throw badResponse(n + " results for a batch of " + sent + " items for " + s.who());
        }
    }

    static void checkBatchItems(List<Item> items) {
        if (items.isEmpty() || items.size() > MAX_BATCH_ITEMS) {
            throw new io.github.nnicora.cipheron.InvalidInputException("cipheron: a batch holds 1 to "
                    + MAX_BATCH_ITEMS + " items, not " + items.size());
        }
        for (Item it : items) {
            if (len(it.aad()) > Ciphertexts.MAX_ASSOCIATED_DATA_LEN || len(it.toAad()) > Ciphertexts.MAX_ASSOCIATED_DATA_LEN) {
                throw new io.github.nnicora.cipheron.AssociatedDataException("cipheron: the associated data does not "
                        + "match the ciphertext's format: associated data is at most 65536 bytes");
            }
        }
    }

    private void batchFits(String profile, List<Item> items, long extra) {
        long n = extra;
        for (Item it : items) {
            n += len(it.data()) + len(it.aad()) + len(it.toAad()) + 98 + 16;
        }
        fits(profile, n);
    }

    private static void checkReEncryptItems(List<Item> items) {
        for (int i = 0; i < items.size(); i++) {
            String why = Ciphertexts.checkReEncryptAssociatedData(items.get(i).aad(), items.get(i).toAad());
            if (why != null) {
                throw new io.github.nnicora.cipheron.AssociatedDataException("cipheron: the associated data does not "
                        + "match the ciphertext's format: " + why + ": batch item " + i + ": give it targetAssociatedData "
                        + "equal to its associatedData (a re-encryption keeps the binding)");
            }
        }
    }

    private List<ItemResult> encryptBatchOnce(Call call, Scope s, List<Item> items) throws RpcFailure {
        byte[] nonce = newNonce();
        Cipheron.EncryptBatchRequest.Builder req = Cipheron.EncryptBatchRequest.newBuilder().setProfile(s.profile())
                .setTenant(s.tenant()).setTenantKey(bs(s.blob())).setRequestNonce(bs(nonce));
        byte[][] digests = new byte[items.size()][];
        for (int i = 0; i < items.size(); i++) {
            Item it = items.get(i);
            Hpke.Sealed sealed = seal(s, "encrypt", it.data());
            req.addItems(Cipheron.EncryptBatchItem.newBuilder().setEnc(bs(sealed.enc()))
                    .setSealedPlaintext(bs(sealed.ciphertext())).setAssociatedData(bs(it.aad())));
            digests[i] = io.github.nnicora.cipheron.internal.wire.Digests.encrypt(sealed.enc(), sealed.ciphertext(),
                    s.tenant(), s.blob(), it.aad());
        }
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.batch(digests);
        Cipheron.RequestAuth auth = auth(s.profile(), "encrypt-batch", nonce, reqDigest);
        if (auth != null) {
            req.setAuth(auth);
        }
        Cipheron.EncryptBatchResponse resp = pick().call(Op.ENCRYPT_BATCH, req.build(), call.requestId(),
                call.deadline());
        List<Cipheron.EncryptBatchResult> res = resp.getResultsList();
        verifyBatch(call, s, "encrypt-batch", nonce, auth, reqDigest, resp.getResponseSignature().toByteArray(),
                res.size(), items.size(), i -> res.get(i).hasError()
                        ? io.github.nnicora.cipheron.internal.wire.Digests.batchError(res.get(i).getError().getCode(),
                                res.get(i).getError().getReason(), res.get(i).getError().getMessage())
                        : io.github.nnicora.cipheron.internal.wire.Digests.batchResult(
                                res.get(i).getCiphertext().toByteArray()));
        List<ItemResult> out = new ArrayList<>();
        for (int i = 0; i < res.size(); i++) {
            Cipheron.EncryptBatchResult r = res.get(i);
            if (r.hasError()) {
                itemErrorAlone(s, i, r.getError(), r.getCiphertext().toByteArray());
                out.add(new ItemResult(null, itemFailure(r.getError(), call.requestId())));
                continue;
            }
            byte[] ct = r.getCiphertext().toByteArray();
            checkCiphertext(s, ct, items.get(i).data().length, s.h() == null ? null : s.h().keyId(),
                    len(items.get(i).aad()) > 0);
            out.add(new ItemResult(ct, null));
        }
        return out;
    }

    private List<ItemResult> decryptBatchOnce(Call call, Scope s, List<Item> items) throws RpcFailure {
        for (Item it : items) {
            parseCiphertext(s, it.data(), it.aad());
        }
        java.security.KeyPair one;
        try {
            one = io.github.nnicora.cipheron.internal.crypto.P256.generate();
        } catch (GeneralSecurityException e) {
            throw new CipheronException("cipheron: a one-time key: " + e.getMessage(), e);
        }
        byte[] recipient = io.github.nnicora.cipheron.internal.crypto.P256.encode(one.getPublic());
        byte[] nonce = newNonce();
        Cipheron.DecryptBatchRequest.Builder req = Cipheron.DecryptBatchRequest.newBuilder().setProfile(s.profile())
                .setRecipientPublicKey(bs(recipient)).setTenant(s.tenant()).setTenantKey(bs(s.blob()))
                .setRequestNonce(bs(nonce));
        byte[][] digests = new byte[items.size()][];
        for (int i = 0; i < items.size(); i++) {
            Item it = items.get(i);
            req.addItems(Cipheron.DecryptBatchItem.newBuilder().setCiphertext(bs(it.data()))
                    .setAssociatedData(bs(it.aad())));
            digests[i] = io.github.nnicora.cipheron.internal.wire.Digests.decrypt(recipient, it.data(), s.tenant(),
                    s.blob(), it.aad());
        }
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.batch(digests);
        Cipheron.RequestAuth auth = auth(s.profile(), "decrypt-batch", nonce, reqDigest);
        if (auth != null) {
            req.setAuth(auth);
        }
        Cipheron.DecryptBatchResponse resp = pick().call(Op.DECRYPT_BATCH, req.build(), call.requestId(),
                call.deadline());
        List<Cipheron.DecryptBatchResult> res = resp.getResultsList();
        verifyBatch(call, s, "decrypt-batch", nonce, auth, reqDigest, resp.getResponseSignature().toByteArray(),
                res.size(), items.size(), i -> res.get(i).hasError()
                        ? io.github.nnicora.cipheron.internal.wire.Digests.batchError(res.get(i).getError().getCode(),
                                res.get(i).getError().getReason(), res.get(i).getError().getMessage())
                        : io.github.nnicora.cipheron.internal.wire.Digests.batchResult(recipient,
                                res.get(i).getEnc().toByteArray(), res.get(i).getSealedPlaintext().toByteArray()));
        List<ItemResult> out = new ArrayList<>();
        byte[] info = Transcripts.responseSealInfo(s.profile(), "decrypt", s.tenant());
        for (int i = 0; i < res.size(); i++) {
            Cipheron.DecryptBatchResult r = res.get(i);
            if (r.hasError()) {
                itemErrorAlone(s, i, r.getError(), r.getEnc().toByteArray(), r.getSealedPlaintext().toByteArray());
                out.add(new ItemResult(null, itemFailure(r.getError(), call.requestId())));
                continue;
            }
            try {
                out.add(new ItemResult(Hpke.open(one.getPrivate(), recipient, info, r.getEnc().toByteArray(),
                        r.getSealedPlaintext().toByteArray()), null));
            } catch (GeneralSecurityException e) {
                for (ItemResult o : out) {
                    Bytes.wipe(o.value());
                }
                throw badResponse("the plaintext of batch item " + i + " for " + s.who() + ": cipheron: the sealed "
                        + "payload could not be opened");
            }
        }
        return out;
    }

    private List<ItemResult> reEncryptBatchOnce(Call call, Scope s, List<Item> items, byte[] to,
            TenantKeys.Header toHeader) throws RpcFailure {
        int[] sizes = new int[items.size()];
        for (int i = 0; i < items.size(); i++) {
            Item it = items.get(i);
            sizes[i] = it.data().length - parseCiphertext(s, it.data(), it.aad()).overhead();
        }
        byte[] nonce = newNonce();
        Cipheron.ReEncryptBatchRequest.Builder req = Cipheron.ReEncryptBatchRequest.newBuilder().setProfile(s.profile())
                .setTenant(s.tenant()).setTenantKey(bs(s.blob())).setToTenantKey(bs(to)).setRequestNonce(bs(nonce));
        byte[][] digests = new byte[items.size()][];
        for (int i = 0; i < items.size(); i++) {
            Item it = items.get(i);
            req.addItems(Cipheron.ReEncryptBatchItem.newBuilder().setCiphertext(bs(it.data()))
                    .setAssociatedData(bs(it.aad())).setToAssociatedData(bs(it.toAad())));
            digests[i] = io.github.nnicora.cipheron.internal.wire.Digests.reEncrypt(it.data(), s.tenant(), s.blob(),
                    to, it.aad(), it.toAad(), "", "");
        }
        byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.batch(digests);
        Cipheron.RequestAuth auth = auth(s.profile(), "reencrypt-batch", nonce, reqDigest);
        if (auth != null) {
            req.setAuth(auth);
        }
        Cipheron.ReEncryptBatchResponse resp = pick().call(Op.RE_ENCRYPT_BATCH, req.build(), call.requestId(),
                call.deadline());
        List<Cipheron.ReEncryptBatchResult> res = resp.getResultsList();
        verifyBatch(call, s, "reencrypt-batch", nonce, auth, reqDigest, resp.getResponseSignature().toByteArray(),
                res.size(), items.size(), i -> res.get(i).hasError()
                        ? io.github.nnicora.cipheron.internal.wire.Digests.batchError(res.get(i).getError().getCode(),
                                res.get(i).getError().getReason(), res.get(i).getError().getMessage())
                        : io.github.nnicora.cipheron.internal.wire.Digests.batchResult(
                                res.get(i).getCiphertext().toByteArray()));
        List<ItemResult> out = new ArrayList<>();
        for (int i = 0; i < res.size(); i++) {
            Cipheron.ReEncryptBatchResult r = res.get(i);
            if (r.hasError()) {
                itemErrorAlone(s, i, r.getError(), r.getCiphertext().toByteArray());
                out.add(new ItemResult(null, itemFailure(r.getError(), call.requestId())));
                continue;
            }
            byte[] ct = r.getCiphertext().toByteArray();
            checkCiphertext(s, ct, sizes[i], toHeader == null ? null : toHeader.keyId(), len(items.get(i).toAad()) > 0);
            out.add(new ItemResult(ct, null));
        }
        return out;
    }

    private Scope batchScope(Call call, String profile, List<Item> items) throws RpcFailure {
        open();
        checkBatchItems(items);
        batchFits(profile, items, 0);
        return sharedScope(call, profile);
    }

    public List<ItemResult> encryptBatch(Call call, String profile, List<Item> items) throws RpcFailure {
        Scope s = batchScope(call, profile, items);
        return retryCall(call, profile, () -> encryptBatchOnce(call, s, items));
    }

    public List<ItemResult> decryptBatch(Call call, String profile, List<Item> items) throws RpcFailure {
        Scope s = batchScope(call, profile, items);
        return retryCall(call, profile, () -> decryptBatchOnce(call, s, items));
    }

    public List<ItemResult> reEncryptBatch(Call call, String profile, List<Item> items) throws RpcFailure {
        checkReEncryptItems(items);
        Scope s = batchScope(call, profile, items);
        return retryCall(call, profile, () -> reEncryptBatchOnce(call, s, items, null, null));
    }

    private Scope tenantBatchScope(Call call, TenantRef t, List<Item> items, long extra) throws RpcFailure {
        checkBatchItems(items);
        batchFits(t.profile(), items, extra);
        return scopeOf(call, t, 0);
    }

    public List<ItemResult> tenantEncryptBatch(Call call, TenantRef t, List<Item> items) throws RpcFailure {
        Scope s = tenantBatchScope(call, t, items, 0);
        return retryCall(call, t.profile(), () -> encryptBatchOnce(call, s, items));
    }

    public List<ItemResult> tenantDecryptBatch(Call call, TenantRef t, List<Item> items) throws RpcFailure {
        Scope s = tenantBatchScope(call, t, items, 0);
        return retryCall(call, t.profile(), () -> decryptBatchOnce(call, s, items));
    }

    public List<ItemResult> tenantReEncryptBatch(Call call, TenantRef t, List<Item> items, byte[] to)
            throws RpcFailure {
        checkReEncryptItems(items);
        Scope s = tenantBatchScope(call, t, items, len(to));
        TenantKeys.Header toHeader = target(s, t, to);
        byte[] target = to == null ? null : to.clone();
        return retryCall(call, t.profile(), () -> reEncryptBatchOnce(call, s, items, target, toHeader));
    }

    /** A re-encryption's target blob: the same tenant's, in a wrapped profile; none in a derived one. */
    private static TenantKeys.Header target(Scope s, TenantRef t, byte[] to) {
        if (s.k().wrapped()) {
            if (to == null) {
                throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: ReEncrypt for "
                        + s.who() + ": a wrapped profile re-encrypts under a tenant key blob (to)");
            }
            try {
                return TenantKeys.check(to, t.profile(), t.tenant());
            } catch (TenantKeys.Refused e) {
                throw new io.github.nnicora.cipheron.TenantKeyException("cipheron: not the tenant's key: the target "
                        + "blob given for " + s.who() + ": " + e.getMessage(), e);
            }
        }
        if (to != null) {
            throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                    + "tenancy: profile \"" + t.profile() + "\" is " + s.k().tenancy() + ": ReEncrypt has no target "
                    + "blob");
        }
        return null;
    }

    /** One tenant key to rewrap: the tenant and its blob. */
    public record KeyRef(String tenant, byte[] blob) {}

    /** One rewrap's outcome: the rewrapped key, or the refusal cipheron answered for it alone. */
    public record KeyResult(TenantKeyOut key, RpcFailure error) {}

    /** Rewraps many tenant keys of a wrapped profile in one request: never retried (a second execution rewraps again). */
    public List<KeyResult> rewrapTenantKeyBatch(Call call, String profile, List<KeyRef> keys) throws RpcFailure {
        open();
        if (keys.isEmpty() || keys.size() > MAX_BATCH_ITEMS) {
            throw new io.github.nnicora.cipheron.InvalidInputException("cipheron: a batch holds 1 to "
                    + MAX_BATCH_ITEMS + " items, not " + keys.size());
        }
        List<TenantKeys.Header> olds = new ArrayList<>();
        long n = 0;
        for (KeyRef r : keys) {
            olds.add(checkBlob(profile, r.tenant(), r.blob()));
            n += 2L * r.blob().length + Bytes.utf8(r.tenant()).length + 64;
        }
        fits(profile, n);
        ProfileKeys k = wrappedKeys(call, profile);
        Scope s = new Scope(profile, k, "", null, null, false);
        return afterStart(call, profile, () -> {
            byte[] nonce = newNonce();
            Cipheron.RewrapTenantKeyBatchRequest.Builder req = Cipheron.RewrapTenantKeyBatchRequest.newBuilder()
                    .setProfile(profile).setRequestNonce(bs(nonce));
            byte[][] digests = new byte[keys.size()][];
            for (int i = 0; i < keys.size(); i++) {
                KeyRef r = keys.get(i);
                req.addItems(Cipheron.RewrapTenantKeyBatchItem.newBuilder().setTenant(r.tenant())
                        .setTenantKey(bs(r.blob())));
                digests[i] = io.github.nnicora.cipheron.internal.wire.Digests.rewrapTenantKey(r.tenant(), r.blob());
            }
            byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.batch(digests);
            Cipheron.RequestAuth auth = auth(profile, "rewrap-tenant-key-batch", nonce, reqDigest);
            if (auth != null) {
                req.setAuth(auth);
            }
            Cipheron.RewrapTenantKeyBatchResponse resp = pick().call(Op.REWRAP_TENANT_KEY_BATCH, req.build(),
                    call.requestId(), call.deadline());
            List<Cipheron.RewrapTenantKeyBatchResult> res = resp.getResultsList();
            verifyBatch(call, s, "rewrap-tenant-key-batch", nonce, auth, reqDigest,
                    resp.getResponseSignature().toByteArray(), res.size(), keys.size(), i -> res.get(i).hasError()
                            ? io.github.nnicora.cipheron.internal.wire.Digests.batchError(
                                    res.get(i).getError().getCode(), res.get(i).getError().getReason(),
                                    res.get(i).getError().getMessage())
                            : io.github.nnicora.cipheron.internal.wire.Digests.batchResult(
                                    res.get(i).getTenantKey().toByteArray(),
                                    res.get(i).getSigningPublicKey().toByteArray(),
                                    Bytes.utf8(res.get(i).getFingerprint())));
            List<KeyResult> out = new ArrayList<>();
            for (int i = 0; i < res.size(); i++) {
                Cipheron.RewrapTenantKeyBatchResult r = res.get(i);
                if (r.hasError()) {
                    itemErrorAlone(s, i, r.getError(), r.getTenantKey().toByteArray(),
                            r.getSigningPublicKey().toByteArray(), Bytes.utf8(r.getFingerprint()));
                    out.add(new KeyResult(null, itemFailure(r.getError(), call.requestId())));
                    continue;
                }
                byte[] nb = r.getTenantKey().toByteArray();
                TenantKeys.Header h = rewrapAnswer(profile, keys.get(i).tenant(), olds.get(i), nb,
                        r.getSigningPublicKey().toByteArray(), r.getFingerprint());
                checkWriter(profile, h.wrappingVersion(), "a tenant key blob");
                out.add(new KeyResult(new TenantKeyOut(nb, h.keyId(), h.signingPublicKey(), h.fingerprint()), null));
            }
            return out;
        });
    }

    // ── re-encryption across profiles ──────────────────────────────────────────────────────────────────────

    /** One side of a cross-profile re-encryption: a profile, and its tenant and blob if it is perTenant. */
    public record Side(String profile, String tenant, byte[] blob) {}

    private Scope sideScope(Call call, Side sd) throws RpcFailure {
        if ((sd.tenant() == null || sd.tenant().isEmpty()) && sd.blob() == null) {
            return sharedScope(call, sd.profile());
        }
        return scopeOf(call, tenant(sd.profile(), sd.tenant(), sd.blob()), 0);
    }

    /**
     * Re-encrypts a ciphertext of one profile under another, without the plaintext leaving cipheron: the request is
     * signed under both profiles (auth, to_auth), and the answer is verified under both profiles' response keys.
     */
    public byte[] reEncryptAcross(Call call, Side from, Side to, byte[] ciphertext, byte[] aad, byte[] toAad)
            throws RpcFailure {
        open();
        reEncryptOptions(aad, toAad);
        if (from.profile().equals(to.profile())) {
            throw new io.github.nnicora.cipheron.TenancyException("cipheron: the call is not one of the profile's "
                    + "tenancy: reEncryptAcross moves a ciphertext to ANOTHER profile; within profile \""
                    + from.profile() + "\" it is reEncrypt, and never to another tenant");
        }
        fits(from.profile(), (long) ciphertext.length + len(from.blob()) + len(to.blob())
                + Bytes.utf8(to.profile()).length + (to.tenant() == null ? 0 : Bytes.utf8(to.tenant()).length)
                + len(aad) + len(toAad) + 98);
        Scope fs = sideScope(call, from);
        Scope ts = sideScope(call, to);
        return retryCall(call, fs.profile(), () -> {
            Ciphertexts.KeyId kid = parseCiphertext(fs, ciphertext, aad);
            int n = ciphertext.length - kid.overhead();
            byte[] nonce = newNonce();
            byte[] reqDigest = io.github.nnicora.cipheron.internal.wire.Digests.reEncrypt(ciphertext, fs.tenant(),
                    fs.blob(), ts.blob(), aad, toAad, ts.profile(), ts.tenant());
            Cipheron.RequestAuth auth = auth(fs.profile(), "reencrypt", nonce, reqDigest);
            Cipheron.RequestAuth toAuth = auth(ts.profile(), "reencrypt", nonce, reqDigest);
            Cipheron.ReEncryptRequest.Builder b = Cipheron.ReEncryptRequest.newBuilder().setProfile(fs.profile())
                    .setCiphertext(bs(ciphertext)).setTenant(fs.tenant()).setTenantKey(bs(fs.blob()))
                    .setToTenantKey(bs(ts.blob())).setRequestNonce(bs(nonce)).setAssociatedData(bs(aad))
                    .setToAssociatedData(bs(toAad)).setToProfile(ts.profile()).setToTenant(ts.tenant());
            if (auth != null) {
                b.setAuth(auth);
            }
            if (toAuth != null) {
                b.setToAuth(toAuth);
            }
            Cipheron.ReEncryptResponse resp = pick().call(Op.RE_ENCRYPT, b.build(), call.requestId(), call.deadline());
            byte[] ct = resp.getCiphertext().toByteArray();
            byte[] respDigest = io.github.nnicora.cipheron.internal.wire.Digests.ciphertextResponse(ct);
            verifyResponse(call, fs.profile(), fs.k(), "reencrypt", nonce, auth, reqDigest, respDigest,
                    resp.getResponseSignature().toByteArray());
            verifyResponse(call, ts.profile(), ts.k(), "reencrypt", nonce, auth, reqDigest, respDigest,
                    resp.getToResponseSignature().toByteArray());
            checkCiphertext(ts, ct, n, ts.h() == null ? null : ts.h().keyId(), len(toAad) > 0);
            return ct;
        });
    }

    /** A re-encryption's associated data check, for the containers: the target is the same bytes. */
    public static void reEncryptCheck(byte[] aad, byte[] toAad) {
        reEncryptOptions(aad, toAad);
    }

    /** A re-encryption keeps the binding: the target associated data equals the source's. */
    static void reEncryptOptions(byte[] aad, byte[] toAad) {
        String why = Ciphertexts.checkReEncryptAssociatedData(aad, toAad);
        if (why != null) {
            throw new io.github.nnicora.cipheron.AssociatedDataException("cipheron: the associated data does not match "
                    + "the ciphertext's format: " + why + ": pass targetAssociatedData equal to associatedData (a "
                    + "re-encryption keeps the binding; a re-binding is a decrypt and an encrypt)");
        }
    }

    static int len(byte[] b) {
        return b == null ? 0 : b.length;
    }
}
