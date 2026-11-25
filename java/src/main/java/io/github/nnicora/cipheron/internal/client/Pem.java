package io.github.nnicora.cipheron.internal.client;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Strict PEM: every byte of a file belongs to a complete block of the expected type, whitespace aside. A file caught
 * mid-write is refused rather than partly adopted ({@code internal/certificate}, {@code transport.onePEM}).
 */
final class Pem {
    private Pem() {}

    /** The DER of every block of {@code type} in {@code pem}, which holds nothing else. */
    static List<byte[]> blocks(byte[] pem, String type) throws GeneralSecurityException {
        String s = new String(pem, StandardCharsets.US_ASCII);
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        List<byte[]> out = new ArrayList<>();
        int i = 0;
        while (true) {
            int b = s.indexOf("-----BEGIN ", i);
            if (b < 0) {
                if (!s.substring(i).isBlank()) {
                    throw new GeneralSecurityException("PEM: bytes outside a " + type + " block");
                }
                break;
            }
            if (!s.substring(i, b).isBlank() || !s.startsWith(begin, b)) {
                throw new GeneralSecurityException("PEM: expected only " + type + " blocks");
            }
            int e = s.indexOf(end, b);
            if (e < 0) {
                throw new GeneralSecurityException("PEM: a " + type + " block is not complete");
            }
            String body = s.substring(b + begin.length(), e);
            if (body.contains(":")) {
                throw new GeneralSecurityException("PEM: a block with headers");
            }
            try {
                out.add(Base64.getMimeDecoder().decode(body.replaceAll("\\s", "")));
            } catch (IllegalArgumentException ex) {
                throw new GeneralSecurityException("PEM: a block that is not base64", ex);
            }
            i = e + end.length();
        }
        if (out.isEmpty()) {
            throw new GeneralSecurityException("PEM: no " + type + " block");
        }
        return out;
    }

    /** The certificates of a bundle: one or more CERTIFICATE blocks and nothing else. */
    static List<X509Certificate> certificates(byte[] pem) throws GeneralSecurityException {
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        List<X509Certificate> out = new ArrayList<>();
        for (byte[] der : blocks(pem, "CERTIFICATE")) {
            out.add((X509Certificate) f.generateCertificate(new ByteArrayInputStream(der)));
        }
        return out;
    }

    /** The DER of the one block of {@code type} in {@code pem}. */
    static byte[] one(byte[] pem, String type) throws GeneralSecurityException {
        List<byte[]> b = blocks(pem, type);
        if (b.size() != 1) {
            throw new GeneralSecurityException("PEM: expected one " + type + " block, not " + b.size());
        }
        return b.get(0);
    }

    /** A PKCS #8 private key (one PRIVATE KEY block) of any algorithm the JDK reads: EC, RSA, Ed25519. */
    static PrivateKey privateKey(byte[] pem) throws GeneralSecurityException {
        byte[] der = one(pem, "PRIVATE KEY");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        GeneralSecurityException last = null;
        for (String alg : new String[] {"EC", "RSA", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw new GeneralSecurityException("PEM: not a PKCS #8 private key", last);
    }
}
