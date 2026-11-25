package io.github.nnicora.cipheron.internal.client;

import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * The network path's mutual TLS: TLS 1.3, this client's certificate, and the server checked against the configured
 * CAs only — never the system's roots — by its host name, or by its SPIFFE id (exactly one URI SAN, equal to it).
 * A server that does not check is an identity failure: the waiting calls fail at once
 * ({@code internal/client/options.go}, {@code tlsfiles.go}).
 */
final class Tls {
    private Tls() {}

    /** The client's certificate and key, from PEM files re-read on every handshake (a rotated pair is picked up). */
    static final class FileKeyManager extends X509ExtendedKeyManager {
        private static final String ALIAS = "cipheron";
        private final Path certFile;
        private final Path keyFile;
        private final Object mu = new Object();
        private X509Certificate[] chain;
        private PrivateKey key;

        FileKeyManager(Path certFile, Path keyFile) throws GeneralSecurityException {
            this.certFile = certFile;
            this.keyFile = keyFile;
            load();
        }

        private void load() throws GeneralSecurityException {
            try {
                List<X509Certificate> c = Pem.certificates(Files.readAllBytes(certFile));
                PrivateKey k = Pem.privateKey(Files.readAllBytes(keyFile));
                synchronized (mu) {
                    chain = c.toArray(new X509Certificate[0]);
                    key = k;
                }
            } catch (java.io.IOException e) {
                throw new GeneralSecurityException("cipheron: reading the client certificate: " + e.getMessage(), e);
            }
        }

        private void reload() {
            try {
                load();
            } catch (GeneralSecurityException e) {
                // A pair caught mid-rotation: the last good pair stays in use.
            }
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            reload();
            return ALIAS;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            reload();
            return ALIAS;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            synchronized (mu) {
                return chain.clone();
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            synchronized (mu) {
                return key;
            }
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] {ALIAS};
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[0];
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }

    /**
     * The server check: PKIX against the configured CAs only, then the host name (gRPC asks the engine for HTTPS
     * endpoint identification) or the SPIFFE id; a failure is recorded as the identity refusal.
     */
    static final class ServerTrust extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager pkix;
        private final String spiffeId;
        private final IdentityState id;

        ServerTrust(Collection<X509Certificate> cas, String spiffeId, IdentityState id) throws GeneralSecurityException {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try {
                ks.load(null, null);
            } catch (java.io.IOException e) {
                throw new GeneralSecurityException(e);
            }
            int i = 0;
            for (X509Certificate ca : cas) {
                ks.setCertificateEntry("ca" + i++, ca);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(ks);
            X509ExtendedTrustManager found = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509ExtendedTrustManager x) {
                    found = x;
                }
            }
            if (found == null) {
                throw new GeneralSecurityException("no X.509 trust manager");
            }
            this.pkix = found;
            this.spiffeId = spiffeId;
            this.id = id;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            try {
                if (spiffeId == null) {
                    pkix.checkServerTrusted(chain, authType, engine);
                } else {
                    pkix.checkServerTrusted(chain, authType);
                    checkSpiffe(chain[0]);
                }
                id.clear();
            } catch (CertificateException e) {
                id.failed(e);
                throw e;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            checkServerTrusted(chain, authType, (SSLEngine) null);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            checkServerTrusted(chain, authType, (SSLEngine) null);
        }

        private void checkSpiffe(X509Certificate leaf) throws CertificateException {
            List<String> uris = new ArrayList<>();
            try {
                Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (Integer.valueOf(6).equals(san.get(0))) {
                            uris.add(String.valueOf(san.get(1)));
                        }
                    }
                }
            } catch (CertificateParsingException e) {
                throw new CertificateException("cipheron: the server certificate's names cannot be read", e);
            }
            if (uris.size() != 1 || !uris.get(0).equals(spiffeId)) {
                throw new CertificateException("cipheron: the server certificate names " + uris
                        + ", not exactly the SPIFFE id " + spiffeId);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("cipheron: a client checks no client");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("cipheron: a client checks no client");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("cipheron: a client checks no client");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return pkix.getAcceptedIssuers();
        }
    }
}
