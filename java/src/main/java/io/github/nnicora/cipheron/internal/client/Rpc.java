package io.github.nnicora.cipheron.internal.client;

import com.google.protobuf.Message;

import java.time.Instant;

/**
 * One connection to cipheron, over either API: a call sends one request and answers its result, or an
 * {@link RpcFailure}: a refusal, or a failure of the path.
 */
interface Rpc extends AutoCloseable {
    /** Calls {@code op} with {@code request}, under the call's {@code requestId}, before {@code deadline}. */
    <Q extends Message, R extends Message> R call(Op<Q, R> op, Q request, String requestId, Instant deadline)
            throws RpcFailure;

    /** Whether the connection is usable now (connected or idle), for the pool's choice. */
    boolean usable();

    @Override
    void close();
}
