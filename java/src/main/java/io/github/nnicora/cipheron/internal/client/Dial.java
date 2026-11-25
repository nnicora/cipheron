package io.github.nnicora.cipheron.internal.client;

import io.github.nnicora.cipheron.AssociatedDataException;
import io.github.nnicora.cipheron.BadResponseException;
import io.github.nnicora.cipheron.BusyException;
import io.github.nnicora.cipheron.CertificateRefusedException;
import io.github.nnicora.cipheron.CipheronException;
import io.github.nnicora.cipheron.ClosedException;
import io.github.nnicora.cipheron.DeadlineExceededException;
import io.github.nnicora.cipheron.InternalException;
import io.github.nnicora.cipheron.InvalidInputException;
import io.github.nnicora.cipheron.KeyVersionUnavailableException;
import io.github.nnicora.cipheron.NoWriterException;
import io.github.nnicora.cipheron.PermissionDeniedException;
import io.github.nnicora.cipheron.ProfileSealedException;
import io.github.nnicora.cipheron.ServerIdentityException;
import io.github.nnicora.cipheron.TooLargeException;
import io.github.nnicora.cipheron.UnavailableException;
import io.github.nnicora.cipheron.UnsupportedException;
import io.github.nnicora.cipheron.internal.wire.Refusals;

import java.nio.file.Files;
import java.security.GeneralSecurityException;

/** Builds a client from its plan, and maps what a call failed with to the public exceptions. */
public final class Dial {
    private Dial() {}

    /** A client of {@code plan}: its connections are made on the first call, not here. */
    public static Core dial(Plan plan) {
        IdentityState id = new IdentityState();
        int n = plan.connections() > 0 ? plan.connections()
                : plan.http() ? Plan.DEFAULT_HTTP_CONNECTIONS : Plan.DEFAULT_CONNECTIONS;
        Rpc[] rpcs = new Rpc[plan.http() ? 1 : n];
        Tls.FileKeyManager keys = null;
        Tls.ServerTrust trust = null;
        if (!plan.endpoint().isSocket()) {
            try {
                keys = new Tls.FileKeyManager(plan.certFile(), plan.keyFile());
                trust = new Tls.ServerTrust(Pem.certificates(Files.readAllBytes(plan.caFile())),
                        plan.serverSpiffeId(), id);
            } catch (GeneralSecurityException | java.io.IOException e) {
                throw new IllegalArgumentException("cipheron: TLS files: " + e.getMessage(), e);
            }
        }
        try {
            for (int i = 0; i < rpcs.length; i++) {
                if (plan.http()) {
                    rpcs[i] = HttpRpc.create(plan, keys, trust, id, n);
                } else if (plan.endpoint().isSocket()) {
                    rpcs[i] = GrpcRpc.socket(plan.endpoint().socket(), plan.serverUid(), id, plan.maxMessage());
                } else {
                    rpcs[i] = GrpcRpc.network(plan.endpoint().authority(), keys, trust, id, plan.maxMessage());
                }
            }
        } catch (RuntimeException e) {
            for (Rpc r : rpcs) {
                if (r != null) {
                    r.close();
                }
            }
            throw e;
        }
        return new Core(plan, rpcs, id);
    }

    /**
     * The public exception a call answers for {@code e}: the client's own decisions as they are; a refusal by its
     * status code and its reason in cipheron's domain; an end of the call's own deadline as such.
     */
    /** The public exception of one batch item's refusal (no transport behind it: its code and reason alone). */
    public static CipheronException mapItem(Core core, Core.Call call, RpcFailure f) {
        return map(core, call, f);
    }

    public static CipheronException map(Core core, Core.Call call, Throwable e) {
        CipheronException out;
        if (e instanceof CipheronException ce) {
            out = ce;
        } else if (e instanceof RpcFailure f) {
            out = mapFailure(core, call, f);
            if (f.retryDelay() != null) {
                out.withRetryAfter(f.retryDelay());
            }
            if (f.code() == Refusals.INVALID_ARGUMENT && f.hasReason(Refusals.BATCH_LIMIT)) {
                try {
                    int items = Integer.parseInt(f.metadata().getOrDefault("maxItems", ""));
                    long bytes = Long.parseLong(f.metadata().getOrDefault("maxBytes", ""));
                    if (items >= 1 && bytes >= 1) {
                        out.withBatchLimits(new CipheronException.BatchLimits(items, bytes));
                    }
                } catch (NumberFormatException nfe) {
                    // Limits that do not parse name none.
                }
            }
        } else {
            out = new CipheronException("cipheron: " + e.getMessage(), e);
        }
        out.withRequestId(call.requestId());
        core.observe("", out);
        return out;
    }

    private static CipheronException mapFailure(Core core, Core.Call call, RpcFailure f) {
        if (f.getCause() instanceof GrpcRpc.ServerIdentityCause) {
            return new ServerIdentityException("cipheron: not the profile's cipheron: " + f.statusMessage(), f);
        }
        if (f.getCause() instanceof CertificateRefusals.Refusal) {
            return new CertificateRefusedException("cipheron: permission denied: " + f.statusMessage(), f);
        }
        int code = f.code();
        boolean cut = code == RpcFailure.CANCELLED || code == RpcFailure.DEADLINE_EXCEEDED
                || code == Refusals.UNAVAILABLE;
        if (core.closed() && !call.ended() && (code == RpcFailure.CANCELLED || code == Refusals.UNAVAILABLE)) {
            return new ClosedException("cipheron: the client is closed: " + f.statusMessage(), f);
        }
        Throwable last = core.lastIdentityFailure();
        if (last != null && cut) {
            return new ServerIdentityException("cipheron: not the profile's cipheron: " + last.getMessage(), f);
        }
        String msg = f.statusMessage();
        switch (code) {
            case Refusals.PERMISSION_DENIED:
                return new PermissionDeniedException("cipheron: permission denied: " + msg, f);
            case Refusals.INVALID_ARGUMENT:
                if (f.hasReason(Refusals.KEY_VERSION_UNAVAILABLE)) {
                    return new KeyVersionUnavailableException("cipheron: the key version is not available: " + msg, f);
                }
                if (f.hasReason(Refusals.ASSOCIATED_DATA)) {
                    return new AssociatedDataException("cipheron: invalid input: " + msg, f);
                }
                return new InvalidInputException("cipheron: invalid input: " + msg, f);
            case Refusals.RESOURCE_EXHAUSTED:
                if (f.hasReason(Refusals.BUSY) || f.hasRetryInfo()) {
                    return new BusyException("cipheron: unavailable: " + msg, f);
                }
                if (f.sizeRefusal()) {
                    return new TooLargeException("cipheron: too large: " + msg, f);
                }
                return new UnavailableException("cipheron: unavailable: " + msg, f);
            case Refusals.UNAVAILABLE:
                if (f.hasReason(Refusals.NO_WRITER)) {
                    return new NoWriterException("cipheron: unavailable: " + msg, f);
                }
                if (f.hasReason(Refusals.PROFILE_SEALED)) {
                    return new ProfileSealedException("cipheron: unavailable: " + msg, f);
                }
                return new UnavailableException("cipheron: unavailable: " + msg, f);
            case Refusals.UNIMPLEMENTED:
                return new UnsupportedException("cipheron: not supported by this cipheron: " + msg, f);
            case Refusals.INTERNAL:
                return new InternalException("cipheron: internal error: " + msg, f);
            case RpcFailure.DEADLINE_EXCEEDED:
            case RpcFailure.CANCELLED:
                return new DeadlineExceededException("cipheron: " + msg + ": the call's deadline passed", f);
            default:
                return new CipheronException("cipheron: " + msg + " (code " + code + ")", f);
        }
    }

    /** A malformed answer, for the transports. */
    static BadResponseException badResponse(String why) {
        return new BadResponseException("cipheron: malformed answer: " + why);
    }
}
