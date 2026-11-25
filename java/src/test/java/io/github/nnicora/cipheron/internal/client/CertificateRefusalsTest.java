package io.github.nnicora.cipheron.internal.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.Context;

import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import org.junit.jupiter.api.Test;

/**
 * Only an authenticated certificate refusal counts: a refusal alert read after a TLS 1.3 handshake completed. The
 * same alert during the handshake, or on TLS 1.2, is what it was — an on-path party could have written it.
 */
class CertificateRefusalsTest {
    private static final SSLEngineResult FINISHED = new SSLEngineResult(SSLEngineResult.Status.OK,
            SSLEngineResult.HandshakeStatus.FINISHED, 0, 0);
    private static final SSLEngineResult HANDSHAKING = new SSLEngineResult(SSLEngineResult.Status.OK,
            SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);

    private static SSLException alert(String name) {
        return new SSLHandshakeException("(" + name + ") Received fatal alert: " + name);
    }

    @Test
    void aRefusalAlertDuringTheHandshakeIsNotARefusal() {
        Stub stub = new Stub("TLSv1.3");
        CertificateRefusals sink = new CertificateRefusals();
        CertificateRefusals.Call call = sink.begin(Context.current().withCancellation());
        SSLEngine e = CertificateRefusals.watch(stub, sink);
        stub.wrap = HANDSHAKING;
        wrap(e);
        stub.alert = alert("bad_certificate");
        SSLException x = assertThrows(SSLException.class, () -> unwrap(e));
        assertSame(stub.alert, x);
        assertFalse(call.context().isCancelled());
    }

    @Test
    void aRefusalAlertAfterATls13HandshakeEndsTheCallsOnce() {
        Stub stub = new Stub("TLSv1.3");
        CertificateRefusals sink = new CertificateRefusals();
        CertificateRefusals.Call call = sink.begin(Context.current().withCancellation());
        SSLEngine e = CertificateRefusals.watch(stub, sink);
        stub.wrap = FINISHED;
        wrap(e);
        stub.alert = alert("bad_certificate");
        SSLException x = assertThrows(SSLException.class, () -> unwrap(e));
        CertificateRefusals.Refusal r = assertInstanceOf(CertificateRefusals.Refusal.class, x);
        assertSame(stub.alert, r.getCause());
        assertTrue(call.context().isCancelled());
        assertSame(r, call.context().cancellationCause());
        assertNotNull(CertificateRefusals.find(new RuntimeException(new java.io.IOException(r))));

        // A call made now knows the last attempt was refused; a completed handshake clears it.
        CertificateRefusals.Call next = sink.begin(Context.current().withCancellation());
        assertTrue(next.refused());
        assertFalse(next.context().isCancelled(), "a refusal is reported once, to the calls of that moment");
        Stub again = new Stub("TLSv1.3");
        again.wrap = FINISHED;
        wrap(CertificateRefusals.watch(again, sink));
        assertFalse(sink.begin(Context.current().withCancellation()).refused());
    }

    @Test
    void aRefusalAlertOnTls12IsNotARefusal() {
        Stub stub = new Stub("TLSv1.2");
        SSLEngine e = CertificateRefusals.watch(stub, null);
        stub.wrap = FINISHED;
        wrap(e);
        stub.alert = alert("bad_certificate");
        assertSame(stub.alert, assertThrows(SSLException.class, () -> unwrap(e)));
    }

    @Test
    void onlyTheCertificateRefusalAlertsCount() {
        for (String name : new String[] {"bad_certificate", "unsupported_certificate", "certificate_revoked",
                "certificate_expired", "certificate_unknown", "unknown_ca", "access_denied",
                "certificate_required"}) {
            Stub stub = new Stub("TLSv1.3");
            SSLEngine e = CertificateRefusals.watch(stub, null);
            stub.wrap = FINISHED;
            wrap(e);
            stub.alert = alert(name);
            assertInstanceOf(CertificateRefusals.Refusal.class, assertThrows(SSLException.class, () -> unwrap(e)),
                    name);
        }
        for (String name : new String[] {"handshake_failure", "internal_error", "decrypt_error", "close_notify"}) {
            Stub stub = new Stub("TLSv1.3");
            SSLEngine e = CertificateRefusals.watch(stub, null);
            stub.wrap = FINISHED;
            wrap(e);
            stub.alert = alert(name);
            assertSame(stub.alert, assertThrows(SSLException.class, () -> unwrap(e)), name);
        }
        Stub stub = new Stub("TLSv1.3");
        SSLEngine e = CertificateRefusals.watch(stub, null);
        stub.wrap = FINISHED;
        wrap(e);
        stub.alert = new SSLException("Connection reset");
        assertSame(stub.alert, assertThrows(SSLException.class, () -> unwrap(e)));
    }

    private static void wrap(SSLEngine e) {
        try {
            e.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(0));
        } catch (SSLException x) {
            throw new AssertionError(x);
        }
    }

    private static void unwrap(SSLEngine e) throws SSLException {
        e.unwrap(ByteBuffer.allocate(0), ByteBuffer.allocate(0));
    }

    /** An engine whose wrap answers {@code wrap}, whose unwrap throws {@code alert}, on a session of {@code protocol}. */
    private static final class Stub extends SSLEngine {
        private final SSLSession session;
        SSLEngineResult wrap = HANDSHAKING;
        SSLException alert;

        Stub(String protocol) {
            session = (SSLSession) Proxy.newProxyInstance(SSLSession.class.getClassLoader(),
                    new Class<?>[] {SSLSession.class},
                    (p, m, a) -> m.getName().equals("getProtocol") ? protocol : null);
        }

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
            return wrap;
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
            if (alert != null) {
                throw alert;
            }
            return HANDSHAKING;
        }

        @Override
        public SSLSession getSession() {
            return session;
        }

        @Override
        public Runnable getDelegatedTask() {
            return null;
        }

        @Override
        public void closeInbound() {}

        @Override
        public boolean isInboundDone() {
            return false;
        }

        @Override
        public void closeOutbound() {}

        @Override
        public boolean isOutboundDone() {
            return false;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {}

        @Override
        public String[] getSupportedProtocols() {
            return new String[0];
        }

        @Override
        public String[] getEnabledProtocols() {
            return new String[0];
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {}

        @Override
        public void beginHandshake() {}

        @Override
        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        @Override
        public void setUseClientMode(boolean mode) {}

        @Override
        public boolean getUseClientMode() {
            return true;
        }

        @Override
        public void setNeedClientAuth(boolean need) {}

        @Override
        public boolean getNeedClientAuth() {
            return false;
        }

        @Override
        public void setWantClientAuth(boolean want) {}

        @Override
        public boolean getWantClientAuth() {
            return false;
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {}

        @Override
        public boolean getEnableSessionCreation() {
            return true;
        }
    }
}
