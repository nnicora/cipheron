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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioDomainSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpVersion;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ProxySelector;
import java.net.StandardProtocolFamily;
import java.net.URI;
import java.net.URLEncoder;
import java.net.UnixDomainSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * The JSON API over HTTP/1.1 ({@code internal/client/dial.go}, {@code DialHTTP}): {@code POST
 * /v1/cipher/{profile}/{op}} with a proto3 JSON body, {@code Content-Type: application/json} and the request id as
 * {@code Grpc-Metadata-X-Request-Id}. Over the network: mutual TLS with ALPN {@code http/1.1}, no proxy, no redirect.
 * Over the unix socket: a new connection per call, its server's uid checked first. An answer that is not 200 is read
 * as the status cipheron wrote ({@code google.rpc.Status}), or by its HTTP code.
 */
final class HttpRpc implements Rpc {
    private static final JsonFormat.Printer PRINTER = JsonFormat.printer().omittingInsignificantWhitespace();
    private static final JsonFormat.Parser PARSER = JsonFormat.parser().ignoringUnknownFields();
    private static final JsonFormat.Parser STATUS = JsonFormat.parser().ignoringUnknownFields().usingTypeRegistry(
            JsonFormat.TypeRegistry.newBuilder().add(ErrorInfo.getDescriptor()).add(RetryInfo.getDescriptor()).build());

    private final HttpClient http;
    private final String base;
    private final String socket;
    private final Long serverUid;
    private final EventLoopGroup group;
    private final IdentityState id;
    private final int limit;
    private volatile boolean closed;

    private HttpRpc(HttpClient http, String base, String socket, Long serverUid, EventLoopGroup group,
            IdentityState id, int limit) {
        this.http = http;
        this.base = base;
        this.socket = socket;
        this.serverUid = serverUid;
        this.group = group;
        this.id = id;
        this.limit = limit;
    }

    static HttpRpc create(Plan plan, Tls.FileKeyManager keys, Tls.ServerTrust trust, IdentityState id,
            int connections) {
        int limit = (int) Math.min(Integer.MAX_VALUE, (long) plan.maxMessage() / 3 * 4 + (64 << 10));
        if (plan.endpoint().isSocket()) {
            return new HttpRpc(null, "http://cipheron", plan.endpoint().socket(), plan.serverUid(),
                    new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory()), id, limit);
        }
        SSLContext ssl;
        try {
            ssl = SSLContext.getInstance("TLSv1.3");
            ssl.init(new javax.net.ssl.KeyManager[] {keys}, new javax.net.ssl.TrustManager[] {trust}, null);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cipheron: TLS: " + e.getMessage(), e);
        }
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[] {"TLSv1.3"});
        params.setApplicationProtocols(new String[] {"http/1.1"});
        HttpClient c = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(ssl)
                .sslParameters(params).followRedirects(HttpClient.Redirect.NEVER).proxy(ProxySelector.of(null))
                .build();
        return new HttpRpc(c, "https://" + plan.endpoint().authority(), null, null, null, id, limit);
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
        int code;
        byte[] raw;
        if (socket != null) {
            FullHttpResponse r = socketCall(path, body, requestId, left);
            try {
                code = r.status().code();
                raw = ByteBufUtil.getBytes(r.content());
            } finally {
                r.release();
            }
        } else {
            HttpRequest req = HttpRequest.newBuilder(URI.create(base + path)).timeout(left)
                    .header("Content-Type", "application/json").header("Grpc-Metadata-X-Request-Id", requestId)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            try {
                HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
                code = r.statusCode();
                raw = r.body();
            } catch (HttpTimeoutException e) {
                throw failure(RpcFailure.DEADLINE_EXCEEDED, "the call's deadline passed", requestId);
            } catch (IOException e) {
                Throwable last = id.last();
                if (last != null) {
                    throw GrpcRpc.identity(last, requestId);
                }
                throw failure(14, "cipheron: " + e.getMessage(), requestId);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw failure(RpcFailure.CANCELLED, "interrupted", requestId);
            }
        }
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

    /** One call over the unix socket: a new connection, its server checked, one request, one answer. */
    private FullHttpResponse socketCall(String path, byte[] body, String requestId, Duration left) throws RpcFailure {
        CompletableFuture<FullHttpResponse> answer = new CompletableFuture<>();
        Bootstrap b = new Bootstrap().group(group).channelFactory(() -> {
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
        }).handler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) {
                ch.pipeline().addLast(new HttpClientCodec(), new HttpObjectAggregator(limit + 1),
                        new SimpleChannelInboundHandler<FullHttpResponse>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) {
                                answer.complete(msg.retain());
                                ctx.close();
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) {
                                answer.completeExceptionally(new IOException("the connection closed"));
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                answer.completeExceptionally(cause);
                                ctx.close();
                            }
                        });
            }
        });
        Channel ch = null;
        try {
            ch = b.connect(UnixDomainSocketAddress.of(socket)).sync().channel();
            DefaultFullHttpRequest req = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, path,
                    Unpooled.wrappedBuffer(body));
            req.headers().set(HttpHeaderNames.HOST, "cipheron").set(HttpHeaderNames.CONTENT_TYPE, "application/json")
                    .set(HttpHeaderNames.CONTENT_LENGTH, body.length).set("Grpc-Metadata-X-Request-Id", requestId);
            ch.writeAndFlush(req);
            return answer.get(Math.max(left.toNanos(), 1), TimeUnit.NANOSECONDS);
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
            Throwable c = e instanceof ExecutionException ? e.getCause() : e;
            throw failure(14, "cipheron: " + c.getMessage(), requestId);
        } finally {
            if (ch != null) {
                ch.close();
            }
        }
    }

    @Override
    public boolean usable() {
        return !closed;
    }

    @Override
    public void close() {
        closed = true;
        if (group != null) {
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
        }
    }
}
