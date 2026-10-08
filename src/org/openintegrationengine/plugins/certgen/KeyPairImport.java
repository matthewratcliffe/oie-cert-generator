/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * A key pair given as PEM -- a private key and its certificate chain -- turned into
 * what TLS Manager stores: the key, and the chain leaf first with each issuer after
 * the certificate it signed.
 *
 * <p>PEM bundles arrive in whatever order whoever assembled them chose, sometimes
 * with a certificate twice or one that belongs to another chain, so the order is
 * rebuilt from the signatures rather than trusted: the leaf is the certificate the
 * key belongs to, and each next link is the given certificate that signed the last.
 * Anything left over is reported, not stored. The intermediates matter: a listener
 * presents exactly this chain, and a client that has only the root cannot get from
 * a leaf to it without them.
 */
final class KeyPairImport {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** The parsed key pair, plus what was in the PEM but not in the chain. */
    static final class Parsed {
        final PrivateKey key;
        final X509Certificate[] chain;
        final List<X509Certificate> unused;
        final int duplicates;

        Parsed(PrivateKey key, X509Certificate[] chain, List<X509Certificate> unused, int duplicates) {
            this.key = key;
            this.chain = chain;
            this.unused = unused;
            this.duplicates = duplicates;
        }
    }

    private KeyPairImport() {
    }

    /**
     * Parses and orders a key pair. {@code keyPem} may be empty when the key is in
     * {@code certificatePem} with the certificates. Refuses an encrypted key, no
     * certificate for the key, and an expired leaf.
     */
    static Parsed parse(String certificatePem, String keyPem, Instant now) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        List<PrivateKey> keys = new ArrayList<>();
        int duplicates = read(certificatePem, certs, keys);
        if (keyPem != null && !keyPem.isBlank()) {
            duplicates += read(keyPem, certs, keys);
        }
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No certificate found in the PEM.");
        }
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("No private key found in the PEM.");
        }
        if (keys.size() > 1) {
            throw new IllegalArgumentException("The PEM holds " + keys.size()
                + " private keys; give exactly one.");
        }
        PrivateKey key = keys.get(0);

        X509Certificate leaf = null;
        for (X509Certificate c : certs) {
            if (belongsTo(key, c.getPublicKey())) {
                leaf = c;
                break;
            }
        }
        if (leaf == null) {
            throw new IllegalArgumentException("The private key is not the key of any of the "
                + certs.size() + " certificate(s) given.");
        }
        if (!leaf.getNotAfter().toInstant().isAfter(now)) {
            throw new IllegalArgumentException("The certificate " + leaf.getSubjectX500Principal().getName()
                + " expired on " + leaf.getNotAfter().toInstant() + ".");
        }

        List<X509Certificate> chain = new ArrayList<>();
        List<X509Certificate> rest = new ArrayList<>(certs);
        rest.remove(leaf);
        chain.add(leaf);
        X509Certificate last = leaf;
        while (!selfSigned(last)) {
            X509Certificate issuer = null;
            for (X509Certificate c : rest) {
                if (c.getSubjectX500Principal().equals(last.getIssuerX500Principal())
                        && signedBy(last, c.getPublicKey())) {
                    issuer = c;
                    break;
                }
            }
            if (issuer == null) {
                break;
            }
            chain.add(issuer);
            rest.remove(issuer);
            last = issuer;
        }
        return new Parsed(key, chain.toArray(new X509Certificate[0]), rest, duplicates);
    }

    /** Adds the certificates and keys in one PEM text; returns how many repeats it skipped. */
    private static int read(String pem, List<X509Certificate> certs, List<PrivateKey> keys) throws Exception {
        JcaX509CertificateConverter certs509 = new JcaX509CertificateConverter();
        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
        int duplicates = 0;
        try (PEMParser parser = new PEMParser(new StringReader(pem == null ? "" : pem))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                if (o instanceof X509CertificateHolder) {
                    X509Certificate c = certs509.getCertificate((X509CertificateHolder) o);
                    boolean seen = false;
                    for (X509Certificate have : certs) {
                        if (Arrays.equals(have.getEncoded(), c.getEncoded())) {
                            seen = true;
                            break;
                        }
                    }
                    if (seen) {
                        duplicates++;
                    } else {
                        certs.add(c);
                    }
                } else if (o instanceof PrivateKeyInfo) {
                    keys.add(keyConverter.getPrivateKey((PrivateKeyInfo) o));
                } else if (o instanceof PEMKeyPair) {
                    // "RSA PRIVATE KEY" / "EC PRIVATE KEY": the traditional OpenSSL forms.
                    // Only the private half: an EC key may omit its public point.
                    keys.add(keyConverter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo()));
                } else if (o instanceof PEMEncryptedKeyPair || o instanceof PKCS8EncryptedPrivateKeyInfo) {
                    throw new IllegalArgumentException("The private key is encrypted; give it "
                        + "unencrypted (openssl pkey -in key.pem -out plain.pem).");
                }
                // Anything else -- parameters, a CRL -- is not part of a key pair.
            }
        }
        return duplicates;
    }

    /** True when {@code key} is the private half of {@code pub}: it signs, pub verifies. */
    static boolean belongsTo(PrivateKey key, PublicKey pub) {
        String alg;
        switch (key.getAlgorithm().toUpperCase(Locale.ROOT)) {
            case "RSA":
                alg = "SHA256withRSA";
                break;
            case "EC":
            case "ECDSA":
                alg = "SHA256withECDSA";
                break;
            case "ED25519":
            case "ED448":
            case "EDDSA":
                alg = key.getAlgorithm();
                break;
            default:
                return false;
        }
        try {
            byte[] probe = new byte[32];
            RANDOM.nextBytes(probe);
            Signature signer = Signature.getInstance(alg);
            signer.initSign(key);
            signer.update(probe);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance(alg);
            verifier.initVerify(pub);
            verifier.update(probe);
            return verifier.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean selfSigned(X509Certificate c) {
        return c.getSubjectX500Principal().equals(c.getIssuerX500Principal())
            && signedBy(c, c.getPublicKey());
    }

    private static boolean signedBy(X509Certificate c, PublicKey issuerKey) {
        try {
            c.verify(issuerKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
