package io.github.nnicora.cipheron.internal.client;

import io.grpc.Context;

import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * cipheron refusing this client's CERTIFICATE in the TLS handshake ({@code internal/client/refusal.go}): an identity no
 * profile lists, one outside the scope of the trust bundle that verified it, or a chain that does not verify. cipheron
 * tells it by a TLS alert; without this class the client would read the closed connection as a server not up yet, and
 * a call would wait for a connection until its deadline. With it, the call fails at once with
 * {@code CertificateRefusedException} (a {@code PermissionDeniedException}).
 *
 * <p><b>Only an authenticated alert counts.</b> An alert is a record anyone on the path can write while it is not
 * protected: a TLS 1.2 alert is plaintext, and a TLS 1.3 alert during the client's handshake is encrypted under keys an
 * active attacker who answered the ClientHello shares. In TLS 1.3 the server checks the client's certificate after it
 * sent its Finished, so its refusal reaches the client after the client verified the server's CertificateVerify and
 * Finished, under the server's application traffic key: only the server this client verified can produce it. So the
 * client treats as a refusal only a certificate-refusal alert read on a TLS 1.3 connection whose handshake had
 * completed ({@link #watching}); every other failure stays what it was (a gRPC call keeps waiting for a connection, an
 * HTTP call fails UNAVAILABLE).
 *
 * <p><b>It ends calls, not the client.</b> Over gRPC a refusal ends every call registered on that connection (one
 * channel of the pool) at that moment, and a later call asks for a fresh connection attempt at once instead of waiting
 * out the backoff the refusals grew; it fails only if that attempt is refused in turn. Over HTTP the call that read the
 * refusal fails with it. Listing the identity, or fixing the certificate, is picked up by the next call.
 *
 * <p>One race remains, harmless: cipheron closes a refused connection as soon as it sent the alert, and when the
 * client's first bytes are still unread there the close is a reset, which may reach the client before the alert. That
 * attempt is then a transient failure like any other, and the next one tells.
 */
final class CertificateRefusals {
    /**
     * The alerts by which a server refuses the client's certificate (RFC 8446 §6.2), by the names the JDK reports
     * them under: bad_certificate (Go's crypto/tls's answer to a failed VerifyConnection — cipheron's every refusal),
     * unsupported_certificate, certificate_revoked, certificate_expired, certificate_unknown, unknown_ca,
     * access_denied, certificate_required.
     */
    private static final Set<String> ALERTS = Set.of("bad_certificate", "unsupported_certificate",
            "certificate_revoked", "certificate_expired", "certificate_unknown", "unknown_ca", "access_denied",
            "certificate_required");

    /**
     * How the JDK words an alert it received ({@code sun.security.ssl.Alert}): "(bad_certificate) Received fatal
     * alert: bad_certificate" in JDK 21. The JDK exposes no alert code, so the name is read after this.
     */
    private static final String RECEIVED = "Received fatal alert: ";

    private final Object mu = new Object();
    private boolean last;
    private long seq;
    private final Map<Long, Context.CancellableContext> waiting = new HashMap<>();

    /** cipheron's refusal, read on an authenticated connection: thrown by a watched engine in place of the alert's. */
    static final class Refusal extends SSLException {
        private static final long serialVersionUID = 1L;

        Refusal(SSLException alert) {
            super("cipheron refused this client's certificate in the TLS handshake (" + alert.getMessage() + "): no "
                    + "profile lists its identity, its identity is not in the scope of the trust bundle that verified "
                    + "it, or its chain does not verify against cipheron's trust bundles (cipheron's log has the "
                    + "reason)", alert);
        }
    }

    /** The name of the alert {@code x} says was received, or "". */
    static String alertOf(SSLException x) {
        String m = x.getMessage();
        int i = m == null ? -1 : m.lastIndexOf(RECEIVED);
        return i < 0 ? "" : m.substring(i + RECEIVED.length()).strip();
    }

    /** The refusal in {@code t}'s causes, or null. */
    static Refusal find(Throwable t) {
        for (int depth = 0; t != null && depth < 32; depth++, t = t.getCause()) {
            if (t instanceof Refusal r) {
                return r;
            }
        }
        return null;
    }

    /** A refusal read on this connection: every call registered now is cancelled with it. */
    void refused(Refusal r) {
        synchronized (mu) {
            last = true;
            for (Context.CancellableContext c : waiting.values()) {
                c.cancel(r);
            }
            waiting.clear();
        }
    }

    /** A handshake completed: the last attempt was not refused (unless its refusal follows). */
    void clear() {
        synchronized (mu) {
            last = false;
        }
    }

    /** A call's registration: its context (cancelled by a refusal), and whether the last attempt was refused. */
    record Call(Context.CancellableContext context, boolean refused, Runnable done) {}

    /** Registers a call running in {@code parent}: a refusal while it runs cancels its context. */
    Call begin(Context.CancellableContext parent) {
        Context.CancellableContext ctx = parent.withCancellation();
        long id;
        boolean refused;
        synchronized (mu) {
            refused = last;
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

    /**
     * {@code real} (initialized), whose engines throw a {@link Refusal} for an authenticated certificate refusal and
     * tell {@code sink} of it, and of every handshake that completed ({@code sink} null: tell nobody).
     */
    static SSLContext watching(SSLContext real, CertificateRefusals sink) {
        return new Watched(new Spi(real, sink), real);
    }

    /** {@code e}, watched as {@link #watching}'s engines are. */
    static SSLEngine watch(SSLEngine e, CertificateRefusals sink) {
        return new Engine(e, sink);
    }

    private static final class Watched extends SSLContext {
        Watched(SSLContextSpi spi, SSLContext real) {
            super(spi, real.getProvider(), real.getProtocol());
        }
    }

    private static final class Spi extends SSLContextSpi {
        private final SSLContext real;
        private final CertificateRefusals sink;

        Spi(SSLContext real, CertificateRefusals sink) {
            this.real = real;
            this.sink = sink;
        }

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random)
                throws KeyManagementException {
            real.init(km, tm, random);
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            throw new UnsupportedOperationException("cipheron: TLS runs on engines only");
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            throw new UnsupportedOperationException("cipheron: a client serves no TLS");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            return watch(real.createSSLEngine(), sink);
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return watch(real.createSSLEngine(host, port), sink);
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return real.getServerSessionContext();
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return real.getClientSessionContext();
        }

        @Override
        protected SSLParameters engineGetDefaultSSLParameters() {
            return real.getDefaultSSLParameters();
        }

        @Override
        protected SSLParameters engineGetSupportedSSLParameters() {
            return real.getSupportedSSLParameters();
        }
    }

    /** The JDK's engine, watched: whether its handshake completed on TLS 1.3, and what alert ended it. */
    private static final class Engine extends SSLEngine {
        private final SSLEngine e;
        private final CertificateRefusals sink;
        private volatile boolean authenticated;
        private boolean reported;

        Engine(SSLEngine e, CertificateRefusals sink) {
            super(e.getPeerHost(), e.getPeerPort());
            this.e = e;
            this.sink = sink;
        }

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
            return seen(e.wrap(srcs, offset, length, dst));
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
                throws SSLException {
            try {
                return seen(e.unwrap(src, dsts, offset, length));
            } catch (SSLException x) {
                throw refusal(x);
            }
        }

        /** The result that completes the handshake (FINISHED is only ever a result's) marks the connection. */
        private SSLEngineResult seen(SSLEngineResult r) {
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                authenticated = "TLSv1.3".equals(e.getSession().getProtocol());
                if (sink != null) {
                    sink.clear();
                }
            }
            return r;
        }

        /** {@code x} as a {@link Refusal} when it is a refusal alert read after a TLS 1.3 handshake completed. */
        private SSLException refusal(SSLException x) {
            if (x instanceof Refusal || !authenticated || !ALERTS.contains(alertOf(x))) {
                return x;
            }
            Refusal r = new Refusal(x);
            synchronized (this) {
                if (sink != null && !reported) {
                    reported = true;
                    sink.refused(r);
                }
            }
            return r;
        }

        @Override
        public Runnable getDelegatedTask() {
            return e.getDelegatedTask();
        }

        @Override
        public void closeInbound() throws SSLException {
            e.closeInbound();
        }

        @Override
        public boolean isInboundDone() {
            return e.isInboundDone();
        }

        @Override
        public void closeOutbound() {
            e.closeOutbound();
        }

        @Override
        public boolean isOutboundDone() {
            return e.isOutboundDone();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return e.getSupportedCipherSuites();
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return e.getEnabledCipherSuites();
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
            e.setEnabledCipherSuites(suites);
        }

        @Override
        public String[] getSupportedProtocols() {
            return e.getSupportedProtocols();
        }

        @Override
        public String[] getEnabledProtocols() {
            return e.getEnabledProtocols();
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {
            e.setEnabledProtocols(protocols);
        }

        @Override
        public SSLSession getSession() {
            return e.getSession();
        }

        @Override
        public SSLSession getHandshakeSession() {
            return e.getHandshakeSession();
        }

        @Override
        public void beginHandshake() throws SSLException {
            e.beginHandshake();
        }

        @Override
        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return e.getHandshakeStatus();
        }

        @Override
        public void setUseClientMode(boolean mode) {
            e.setUseClientMode(mode);
        }

        @Override
        public boolean getUseClientMode() {
            return e.getUseClientMode();
        }

        @Override
        public void setNeedClientAuth(boolean need) {
            e.setNeedClientAuth(need);
        }

        @Override
        public boolean getNeedClientAuth() {
            return e.getNeedClientAuth();
        }

        @Override
        public void setWantClientAuth(boolean want) {
            e.setWantClientAuth(want);
        }

        @Override
        public boolean getWantClientAuth() {
            return e.getWantClientAuth();
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {
            e.setEnableSessionCreation(flag);
        }

        @Override
        public boolean getEnableSessionCreation() {
            return e.getEnableSessionCreation();
        }

        @Override
        public SSLParameters getSSLParameters() {
            return e.getSSLParameters();
        }

        @Override
        public void setSSLParameters(SSLParameters params) {
            e.setSSLParameters(params);
        }

        @Override
        public String getApplicationProtocol() {
            return e.getApplicationProtocol();
        }

        @Override
        public String getHandshakeApplicationProtocol() {
            return e.getHandshakeApplicationProtocol();
        }

        @Override
        public void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
            e.setHandshakeApplicationProtocolSelector(selector);
        }

        @Override
        public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
            return e.getHandshakeApplicationProtocolSelector();
        }
    }
}
