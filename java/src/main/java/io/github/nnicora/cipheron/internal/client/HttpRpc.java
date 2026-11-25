package io.github.nnicora.cipheron.internal.client;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import com.google.rpc.ErrorInfo;
import com.google.rpc.RetryInfo;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioDomainSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.TooLongHttpContentException;
import io.netty.handler.ssl.SslHandler;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.net.URLEncoder;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;

/**
 * The JSON API over HTTP/1.1 ({@code internal/client/dial.go}, {@code DialHTTP}): {@code POST
 * /v1/cipher/{profile}/{op}} with a proto3 JSON body, {@code Content-Type: application/json} and the request id as
 * {@code Grpc-Metadata-X-Request-Id}, on keep-alive connections: over the network, mutual TLS 1.3 offering ALPN
 * {@code http/1.1} alone, no proxy, no redirect, and cipheron's refusal of this client's certificate read as such
 * ({@link CertificateRefusals}: Netty's TLS handler decodes the alert before the connection's end, so the call that
 * wrote on the connection reads the refusal); over the unix socket, each connection's server uid checked before its
 * first request. An idle connection is closed after {@link #IDLE_TIMEOUT}. At most {@code connections} calls run at
 * once, so at most that many connections are open, idle ones included; the others wait for one until their deadlines.
 * A request is never sent a second time. An answer that is not 200 is read as the status cipheron wrote
 * ({@code google.rpc.Status}), or by its HTTP code.
 */
final class HttpRpc implements Rpc {
    private static final JsonFormat.Printer PRINTER = JsonFormat.printer().omittingInsignificantWhitespace();
    private static final JsonFormat.Parser PARSER = JsonFormat.parser().ignoringUnknownFields();
    private static final JsonFormat.Parser STATUS = JsonFormat.parser().ignoringUnknownFields().usingTypeRegistry(
            JsonFormat.TypeRegistry.newBuilder().add(ErrorInfo.getDescriptor()).add(RetryInfo.getDescriptor()).build());

    /**
     * How long an idle connection is kept: under cipheron's own two minutes (its listener closes a connection
     * idle that long), so the client drops a connection before cipheron does and a request is not written into one
     * cipheron is closing ({@code internal/client/dial.go}, {@code httpIdleTimeout}).
     */
    static final Duration IDLE_TIMEOUT = Duration.ofSeconds(90);

    private final Endpoint endpoint;
    private final Long serverUid;
    private final SSLContext ssl;
    private final String hostHeader;
    private final EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private final IdentityState id;
    private final int limit;
    private final Semaphore permits;
    private final Deque<Conn> idle = new ArrayDeque<>();
    private volatile boolean closed;

    private HttpRpc(Endpoint endpoint, Long serverUid, SSLContext ssl, IdentityState id, int limit,
            int connections) {
        this.endpoint = endpoint;
        this.serverUid = serverUid;
        this.ssl = ssl;
        // The socket's host is not dialled: it only has to be a valid one.
        this.hostHeader = endpoint.isSocket() ? "cipheron" : endpoint.authority();
        this.id = id;
        this.limit = limit;
        this.permits = new Semaphore(connections, true);
    }

    static HttpRpc create(Plan plan, Tls.FileKeyManager keys, Tls.ServerTrust trust, IdentityState id,
            int connections) {
        int limit = (int) Math.min(Integer.MAX_VALUE, (long) plan.maxMessage() / 3 * 4 + (64 << 10));
        if (plan.endpoint().isSocket()) {
            return new HttpRpc(plan.endpoint(), plan.serverUid(), null, id, limit, connections);
        }
        SSLContext ssl;
        try {
            ssl = SSLContext.getInstance("TLSv1.3");
            ssl.init(new KeyManager[] {keys}, new TrustManager[] {trust}, null);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cipheron: TLS: " + e.getMessage(), e);
        }
        return new HttpRpc(plan.endpoint(), null, CertificateRefusals.watching(ssl, null), id, limit, connections);
    }

    @Override
    public <Q extends Message, R extends Message> R call(Op<Q, R> op, Q request, String requestId, Instant deadline)
            throws RpcFailure {
        if (closed) {
            throw new RpcFailure(RpcFailure.CANCELLED, "the client is closed", null, null, null, false, false,
                    requestId, null);
        }
        String profile = profileOf(request);
        String path = "/v1/cipher/" + URLEncoder.encode(profile, StandardCharsets.UTF_8).replace("+", "%20") + "/"
                + op.route();
        byte[] body;
        try {
            body = PRINTER.print(request).getBytes(StandardCharsets.UTF_8);
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalStateException(e);
        }
        Duration left = Duration.between(Instant.now(), deadline);
        if (left.isNegative() || left.isZero()) {
            throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed", requestId);
        }
        try {
            if (!permits.tryAcquire(left.toNanos(), TimeUnit.NANOSECONDS)) {
                throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed waiting for one of the "
                        + "client's connections (connections)", requestId);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw failure(RpcFailure.CANCELLED, "interrupted", requestId);
        }
        try {
            return exchange(op, path, body, requestId, deadline);
        } finally {
            permits.release();
        }
    }

    private <Q extends Message, R extends Message> R exchange(Op<Q, R> op, String path, byte[] body,
            String requestId, Instant deadline) throws RpcFailure {
        if (closed) {
            throw new RpcFailure(RpcFailure.CANCELLED, "the client is closed", null, null, null, false, false,
                    requestId, null);
        }
        Duration left = Duration.between(Instant.now(), deadline);
        if (left.isNegative() || left.isZero()) {
            throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed", requestId);
        }
        Answer a = roundTrip(path, body, requestId, deadline);
        int code = a.code();
        byte[] raw = a.body();
        if (raw.length > limit) {
            throw new RpcFailure(8, "the answer is larger than " + limit + " bytes (maxMessageBytes)", null, null, null,
                    false, true, requestId, null);
        }
        if (code >= 300 && code < 400) {
            throw failure(RpcFailure.FAILED_PRECONDITION, "cipheron answered HTTP " + code + ", a redirect: cipheron "
                    + "never redirects, so what answered at this address is not cipheron's API; the redirect was not "
                    + "followed", requestId);
        }
        if (code == 404) {
            throw failure(12, "cipheron answered HTTP 404 for the " + op.route() + " operation's route: the server "
                    + "does not serve it", requestId);
        }
        if (code != 200) {
            throw status(code, raw, requestId);
        }
        try {
            Message.Builder b = op.response().newBuilderForType();
            PARSER.merge(new String(raw, StandardCharsets.UTF_8), b);
            @SuppressWarnings("unchecked")
            R out = (R) b.build();
            return out;
        } catch (InvalidProtocolBufferException e) {
            throw failure(RpcFailure.UNKNOWN, "an answer that is not the operation's JSON: " + e.getMessage(),
                    requestId);
        }
    }

    private static String profileOf(Message request) {
        Object p = request.getField(request.getDescriptorForType().findFieldByName("profile"));
        return p == null ? "" : p.toString();
    }

    private static RpcFailure failure(int code, String msg, String requestId) {
        return new RpcFailure(code, msg, null, null, null, false, false, requestId, null);
    }

    /** An error answer: the {@code google.rpc.Status} cipheron wrote, or a status by its HTTP code. */
    static RpcFailure status(int http, byte[] raw, String requestId) {
        String text = new String(raw, StandardCharsets.UTF_8);
        com.google.rpc.Status.Builder st = com.google.rpc.Status.newBuilder();
        boolean full;
        try {
            STATUS.merge(text, st);
            full = st.getCode() != 0;
        } catch (InvalidProtocolBufferException | RuntimeException e) {
            full = false;
        }
        String msg = full && !st.getMessage().isEmpty() ? st.getMessage() : "cipheron answered HTTP " + http;
        if (http == 413) {
            return new RpcFailure(8, "too large: " + msg, null, null, null, false, true, requestId, null);
        }
        if (http == 429 && !full) {
            return new RpcFailure(8, msg, null, null, Duration.ofSeconds(1), true, false, requestId, null);
        }
        if (full) {
            String domain = null;
            String reason = null;
            Duration delay = null;
            boolean retryInfo = false;
            java.util.Map<String, String> metadata = java.util.Map.of();
            for (com.google.protobuf.Any a : st.getDetailsList()) {
                try {
                    if (a.is(ErrorInfo.class)) {
                        ErrorInfo ei = a.unpack(ErrorInfo.class);
                        domain = ei.getDomain();
                        reason = ei.getReason();
                        metadata = ei.getMetadataMap();
                    } else if (a.is(RetryInfo.class)) {
                        retryInfo = true;
                        RetryInfo ri = a.unpack(RetryInfo.class);
                        if (ri.hasRetryDelay() && ri.getRetryDelay().getSeconds() >= 0) {
                            delay = Duration.ofSeconds(ri.getRetryDelay().getSeconds(), ri.getRetryDelay().getNanos());
                        }
                    }
                } catch (InvalidProtocolBufferException e) {
                    // A detail that does not parse names nothing.
                }
            }
            boolean size = st.getCode() == 8 && st.getDetailsCount() == 0
                    && (msg.contains("larger than max") || msg.contains("message too large"));
            return new RpcFailure(st.getCode(), msg, domain, reason, delay, retryInfo, size, requestId, null)
                    .withMetadata(metadata);
        }
        int code = switch (http) {
            case 400 -> 3;
            case 403 -> 7;
            case 503 -> 14;
            case 501, 405 -> 12;
            default -> RpcFailure.UNKNOWN;
        };
        return failure(code, msg, requestId);
    }

    /** An answer: its HTTP status and its body. */
    private record Answer(int code, byte[] body) {}

    /**
     * One call, on an idle connection of the pool or a new one (on the socket, its server's uid checked before a byte
     * is written; on the network, its server checked in the TLS handshake): one request, one answer. A connection whose
     * answer keeps it alive goes back to the pool; one that failed, timed out or was told to close is closed. The
     * request is never sent a second time.
     */
    private Answer roundTrip(String path, byte[] body, String requestId, Instant deadline) throws RpcFailure {
        Conn c = takeIdle();
        try {
            if (c == null) {
                c = connect(deadline, requestId);
            }
            CompletableFuture<FullHttpResponse> answer = new CompletableFuture<>();
            c.pending = answer;
            DefaultFullHttpRequest req = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, path,
                    Unpooled.wrappedBuffer(body));
            req.headers().set(HttpHeaderNames.HOST, hostHeader).set(HttpHeaderNames.CONTENT_TYPE, "application/json")
                    .set(HttpHeaderNames.CONTENT_LENGTH, body.length).set("Grpc-Metadata-X-Request-Id", requestId);
            c.ch.writeAndFlush(req).addListener(w -> {
                if (!w.isSuccess()) {
                    answer.completeExceptionally(w.cause());
                }
            });
            long left = Duration.between(Instant.now(), deadline).toNanos();
            FullHttpResponse r = answer.get(Math.max(left, 1), TimeUnit.NANOSECONDS);
            Answer out;
            boolean keep;
            try {
                out = new Answer(r.status().code(), ByteBufUtil.getBytes(r.content()));
                keep = HttpUtil.isKeepAlive(r);
            } finally {
                r.release();
            }
            if (keep) {
                putIdle(c);
            } else {
                c.ch.close();
            }
            c = null;
            return out;
        } catch (TimeoutException e) {
            throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed", requestId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw failure(RpcFailure.CANCELLED, "interrupted", requestId);
        } catch (ExecutionException | RuntimeException e) {
            Throwable last = id.last();
            if (last != null) {
                throw GrpcRpc.identity(last, requestId);
            }
            Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
            if (cause instanceof TooLongHttpContentException) {
                // The aggregator's bound (limit + 1): an answer this client does not read.
                throw new RpcFailure(8, "the answer is larger than " + limit + " bytes (maxMessageBytes)", null, null,
                        null, false, true, requestId, null);
            }
            CertificateRefusals.Refusal refused = CertificateRefusals.find(cause);
            if (refused != null) {
                throw GrpcRpc.certificateRefused(refused, requestId);
            }
            throw failure(14, "cipheron: " + cause.getMessage(), requestId);
        } finally {
            if (c != null) {
                c.ch.close();
            }
        }
    }

    /** A new connection, made before {@code deadline} (on the network, its TLS handshake runs on the first write). */
    private Conn connect(Instant deadline, String requestId) throws RpcFailure, InterruptedException,
            ExecutionException {
        Conn c = new Conn();
        Bootstrap b = new Bootstrap().group(group);
        SocketAddress to;
        if (endpoint.isSocket()) {
            String socket = endpoint.socket();
            to = UnixDomainSocketAddress.of(socket);
            b.channelFactory(() -> {
                SocketChannel sc;
                try {
                    sc = SocketChannel.open(StandardProtocolFamily.UNIX);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                NioDomainSocketChannel ch = new NioDomainSocketChannel(sc);
                if (serverUid != null) {
                    ch.pipeline().addFirst(new PeerCheck(socket, serverUid, sc, id));
                }
                return ch;
            });
        } else {
            to = new InetSocketAddress(endpoint.host(), endpoint.port());
            b.channelFactory(NioSocketChannel::new);
        }
        b.handler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) {
                if (ssl != null) {
                    ch.pipeline().addLast(tls());
                }
                ch.pipeline().addLast(new HttpClientCodec(), new HttpObjectAggregator(limit + 1), c);
            }
        });
        ChannelFuture f = b.connect(to);
        long left = Duration.between(Instant.now(), deadline).toNanos();
        if (!f.await(Math.max(left, 1), TimeUnit.NANOSECONDS)) {
            f.cancel(false);
            f.channel().close();
            throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed", requestId);
        }
        if (!f.isSuccess()) {
            throw new ExecutionException(f.cause());
        }
        c.ch = f.channel();
        return c;
    }

    /**
     * The client side of the network's TLS: 1.3 only, ALPN {@code http/1.1} alone (on cipheron's network listener h2 is
     * its gRPC server, which a JSON request does not reach), the server's host name checked unless the trust manager
     * checks its SPIFFE id instead, and no handshake timeout of its own: the call's deadline bounds it.
     */
    private SslHandler tls() {
        SSLEngine e = ssl.createSSLEngine(endpoint.host(), endpoint.port());
        e.setUseClientMode(true);
        SSLParameters p = e.getSSLParameters();
        p.setProtocols(new String[] {"TLSv1.3"});
        p.setApplicationProtocols(new String[] {"http/1.1"});
        p.setEndpointIdentificationAlgorithm("HTTPS");
        e.setSSLParameters(p);
        SslHandler h = new SslHandler(e);
        h.setHandshakeTimeoutMillis(0);
        return h;
    }

    /** An idle connection that is still open, or null. */
    private Conn takeIdle() {
        synchronized (idle) {
            for (Conn c; (c = idle.pollFirst()) != null;) {
                c.idleClose.cancel(false);
                if (c.ch.isActive()) {
                    return c;
                }
                c.ch.close();
            }
            return null;
        }
    }

    /** Keeps {@code c} for a later call, for at most {@link #IDLE_TIMEOUT}. */
    private void putIdle(Conn c) {
        synchronized (idle) {
            if (closed || !c.ch.isActive()) {
                c.ch.close();
                return;
            }
            c.idleClose = c.ch.eventLoop().schedule(() -> {
                boolean mine;
                synchronized (idle) {
                    mine = idle.remove(c);
                }
                if (mine) {
                    c.ch.close();
                }
            }, IDLE_TIMEOUT.toNanos(), TimeUnit.NANOSECONDS);
            idle.addFirst(c);
        }
    }

    /** One pooled connection: its channel, and the answer its current call waits for. */
    private final class Conn extends SimpleChannelInboundHandler<FullHttpResponse> {
        private Channel ch;
        private volatile CompletableFuture<FullHttpResponse> pending;
        private ScheduledFuture<?> idleClose;

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
            CompletableFuture<FullHttpResponse> p = pending;
            pending = null;
            if (p == null || !p.complete(msg.retain())) {
                if (p != null) {
                    msg.release();
                }
                // An answer no call waits for: the connection is out of step, and not used again.
                ctx.close();
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            CompletableFuture<FullHttpResponse> p = pending;
            if (p != null) {
                p.completeExceptionally(new IOException("the connection closed"));
            }
            synchronized (idle) {
                idle.remove(this);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            CompletableFuture<FullHttpResponse> p = pending;
            if (p != null) {
                p.completeExceptionally(cause);
            }
            ctx.close();
        }
    }

    @Override
    public boolean usable() {
        return !closed;
    }

    @Override
    public void close() {
        closed = true;
        synchronized (idle) {
            for (Conn c : idle) {
                c.idleClose.cancel(false);
                c.ch.close();
            }
            idle.clear();
        }
        group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
    }
}
