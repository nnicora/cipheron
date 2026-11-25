package io.github.nnicora.cipheron.internal.client;

import io.grpc.Context;

import java.util.HashMap;
import java.util.Map;

/**
 * Whether the last connection attempt was refused because the party at the other end is not the profile's cipheron
 * (a socket served by another uid, a server certificate that does not check), and the calls waiting on a connection
 * meanwhile. A refusal cancels every waiting call at once with the identity failure, so a call fails fast rather than
 * waiting for its deadline; a later attempt that is not refused clears it ({@code internal/client/identity.go}).
 */
final class IdentityState {
    private final Object mu = new Object();
    private Throwable failure;
    private long seq;
    private final Map<Long, Context.CancellableContext> waiting = new HashMap<>();

    /** An identity refusal of the last attempt: every waiting call is cancelled with it. */
    void failed(Throwable cause) {
        synchronized (mu) {
            failure = cause;
            for (Context.CancellableContext c : waiting.values()) {
                c.cancel(new IdentityFailure(cause));
            }
            waiting.clear();
        }
    }

    /** The last attempt was not refused for identity. */
    void clear() {
        synchronized (mu) {
            failure = null;
        }
    }

    /** The last attempt's identity refusal, or null. */
    Throwable last() {
        synchronized (mu) {
            return failure;
        }
    }

    /** A call's registration: its cancellable context, and whether the last attempt was already refused. */
    record Call(Context.CancellableContext context, boolean refused, Runnable done) {}

    /** Registers a call: an identity refusal arriving while it waits cancels its context. */
    Call begin() {
        Context.CancellableContext ctx = Context.current().withCancellation();
        long id;
        boolean refused;
        synchronized (mu) {
            refused = failure != null;
            id = ++seq;
            waiting.put(id, ctx);
        }
        return new Call(ctx, refused, () -> {
            synchronized (mu) {
                waiting.remove(id);
            }
            ctx.cancel(null);
        });
    }

    /** The cause a call is cancelled with when the server's identity is refused. */
    static final class IdentityFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        IdentityFailure(Throwable cause) {
            super(cause.getMessage(), cause);
        }
    }
}
