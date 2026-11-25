package io.github.nnicora.cipheron.internal.client;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.rpc.ErrorInfo;
import com.google.rpc.RetryInfo;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ConnectivityState;
import io.grpc.ForwardingClientCall;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.protobuf.StatusProto;
import io.grpc.stub.ClientCalls;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioDomainSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLException;

/**
 * One gRPC connection (a channel) to cipheron, over the unix socket (NIO on the JDK socket, with the server's uid checked
 * on the connection itself) or mutual TLS. Every request declares its size ({@code cipheron-request-bytes}) and carries
 * its request id ({@code x-request-id}); nothing is compressed; calls wait for a connection until their deadline,
 * unless the last attempt was an identity refusal ({@code internal/client/dial.go}).
 */
final class GrpcRpc implements Rpc {
    static final Metadata.Key<String> REQUEST_BYTES =
            Metadata.Key.of("cipheron-request-bytes", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> REQUEST_ID = Metadata.Key.of("x-request-id", Metadata.ASCII_STRING_MARSHALLER);
    private static final CallOptions.Key<String> REQUEST_ID_OPTION = CallOptions.Key.create("cipheron-request-id");
    private static final CallOptions.Key<Integer> REQUEST_SIZE_OPTION =
            CallOptions.Key.create("cipheron-request-size");

    private static final int STREAM_WINDOW = 1 << 20;
    private static final Duration KEEPALIVE_TIME = Duration.ofSeconds(30);
    private static final Duration KEEPALIVE_TIMEOUT = Duration.ofSeconds(15);

    private final ManagedChannel channel;
    private final EventLoopGroup group;
    private final IdentityState id;
    private final int maxMessage;

    private GrpcRpc(ManagedChannel channel, EventLoopGroup group, IdentityState id, int maxMessage) {
        this.channel = channel;
        this.group = group;
        this.id = id;
        this.maxMessage = maxMessage;
    }

    /**
     * A connection over the unix socket {@code path} (Netty's NIO channel on the JDK's socket: the same on Linux and
     * macOS); {@code serverUid} null checks no server (anyServer).
     */
    static GrpcRpc socket(String path, Long serverUid, IdentityState id, int maxMessage) {
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        NettyChannelBuilder b = NettyChannelBuilder.forAddress(UnixDomainSocketAddress.of(path)).eventLoopGroup(group)
                .usePlaintext().maxInboundMessageSize(maxMessage).flowControlWindow(STREAM_WINDOW)
                .intercept(new Declare());
        b.channelFactory(() -> {
            SocketChannel socket;
            try {
                socket = SocketChannel.open(StandardProtocolFamily.UNIX);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            NioDomainSocketChannel ch = new NioDomainSocketChannel(socket);
            if (serverUid != null) {
                ch.pipeline().addFirst(new PeerCheck(path, serverUid, socket, id));
            }
            return ch;
        });
        return new GrpcRpc(b.build(), group, id, maxMessage);
    }

    /** A connection over mutual TLS to {@code authority}. */
    static GrpcRpc network(String authority, Tls.FileKeyManager keys, Tls.ServerTrust trust, IdentityState id,
            int maxMessage) {
        SslContext ssl;
        try {
            ssl = GrpcSslContexts.configure(SslContextBuilder.forClient(), SslProvider.JDK).keyManager(keys)
                    .trustManager(trust).protocols("TLSv1.3").build();
        } catch (SSLException e) {
            throw new IllegalStateException("cipheron: TLS: " + e.getMessage(), e);
        }
        ManagedChannel ch = NettyChannelBuilder.forTarget(authority).sslContext(ssl).maxInboundMessageSize(maxMessage)
                .flowControlWindow(STREAM_WINDOW).keepAliveTime(KEEPALIVE_TIME.toSeconds(), TimeUnit.SECONDS)
                .keepAliveTimeout(KEEPALIVE_TIMEOUT.toSeconds(), TimeUnit.SECONDS).keepAliveWithoutCalls(false)
                .intercept(new Declare()).build();
        return new GrpcRpc(ch, null, id, maxMessage);
    }

    @Override
    public <Q extends Message, R extends Message> R call(Op<Q, R> op, Q request, String requestId, Instant deadline)
            throws RpcFailure {
        IdentityState.Call c = id.begin();
        try {
            CallOptions opts = CallOptions.DEFAULT.withOption(REQUEST_ID_OPTION, requestId)
                    .withOption(REQUEST_SIZE_OPTION, request.getSerializedSize())
                    .withMaxOutboundMessageSize(maxMessage).withMaxInboundMessageSize(maxMessage);
            if (!c.refused()) {
                opts = opts.withWaitForReady();
            }
            long nanos = Duration.between(Instant.now(), deadline).toNanos();
            opts = opts.withDeadlineAfter(Math.max(nanos, 1), TimeUnit.NANOSECONDS);
            CallOptions o = opts;
            return c.context().call(() -> ClientCalls.blockingUnaryCall(channel, op.method(), o, request));
        } catch (StatusRuntimeException e) {
            Throwable cause = c.context().cancellationCause();
            if (cause instanceof IdentityState.IdentityFailure f) {
                throw identity(f.getCause(), requestId);
            }
            throw failure(e, requestId);
        } catch (Exception e) {
            if (e instanceof RuntimeException r) {
                throw r;
            }
            throw new IllegalStateException(e);
        } finally {
            c.done().run();
        }
    }

    /** The failure a call answers when the server's identity was refused. */
    static RpcFailure identity(Throwable cause, String requestId) {
        return new RpcFailure(RpcFailure.UNKNOWN, cause.getMessage(), null, null, null, false, false, requestId,
                new ServerIdentityCause(cause));
    }

    /** Marks a failure as the server's identity's. */
    static final class ServerIdentityCause extends Exception {
        private static final long serialVersionUID = 1L;

        ServerIdentityCause(Throwable cause) {
            super(cause.getMessage(), cause);
        }
    }

    /** Reads a gRPC status as a failure: its code, its last ErrorInfo of any domain, its RetryInfo. */
    static RpcFailure failure(StatusRuntimeException e, String requestId) {
        Status s = e.getStatus();
        String domain = null;
        String reason = null;
        java.util.Map<String, String> metadata = java.util.Map.of();
        Duration delay = null;
        boolean retryInfo = false;
        int details = 0;
        com.google.rpc.Status sp = StatusProto.fromThrowable(e);
        if (sp != null) {
            details = sp.getDetailsCount();
            for (Any a : sp.getDetailsList()) {
                try {
                    if (a.is(ErrorInfo.class)) {
                        ErrorInfo ei = a.unpack(ErrorInfo.class);
                        domain = ei.getDomain();
                        reason = ei.getReason();
                        metadata = ei.getMetadataMap();
                    } else if (a.is(RetryInfo.class)) {
                        retryInfo = true;
                        RetryInfo ri = a.unpack(RetryInfo.class);
                        if (ri.hasRetryDelay() && ri.getRetryDelay().getSeconds() >= 0 && ri.getRetryDelay().getNanos() >= 0) {
                            delay = Duration.ofSeconds(ri.getRetryDelay().getSeconds(), ri.getRetryDelay().getNanos());
                        }
                    }
                } catch (InvalidProtocolBufferException ex) {
                    // A detail that does not parse names nothing.
                }
            }
        }
        String msg = s.getDescription() == null ? s.getCode().name() : s.getDescription();
        boolean size = s.getCode() == Status.Code.RESOURCE_EXHAUSTED && details == 0
                && (msg.contains("larger than max") || msg.contains("message too large")
                        || msg.contains("exceeds maximum size"));
        return new RpcFailure(s.getCode().value(), msg, domain, reason, delay, retryInfo, size, requestId, e)
                .withMetadata(metadata);
    }

    @Override
    public boolean usable() {
        ConnectivityState st = channel.getState(false);
        return st == ConnectivityState.READY || st == ConnectivityState.IDLE;
    }

    @Override
    public void close() {
        channel.shutdownNow();
        try {
            channel.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (group != null) {
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
        }
    }

    /** Declares each request's size and carries its request id: metadata the server reads before the body. */
    private static final class Declare implements ClientInterceptor {
        @Override
        public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
            return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, options)) {
                @Override
                public void start(Listener<R> listener, Metadata h) {
                    String rid = options.getOption(REQUEST_ID_OPTION);
                    if (rid != null) {
                        h.put(REQUEST_ID, rid);
                    }
                    Integer n = options.getOption(REQUEST_SIZE_OPTION);
                    if (n != null) {
                        h.put(REQUEST_BYTES, Integer.toString(Math.max(1, n)));
                    }
                    super.start(listener, h);
                }
            };
        }
    }
}
