/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Checks KeyPairImport with throwaway chains: run by build.sh, no engine needed.
 * Exits non-zero on the first failure.
 */
public final class ImportSelfTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Instant now = Instant.now();
        Instant from = now.minusSeconds(3600);
        Instant to = now.plusSeconds(86400L * 365);

        KeyPair rootKeys = CertificateIssuer.generate(CertificateIssuer.KeyType.RSA_2048);
        KeyPair intKeys = CertificateIssuer.generate(CertificateIssuer.KeyType.RSA_2048);
        X509Certificate root = cert(rootKeys.getPrivate(), "CN=Test Root", rootKeys.getPublic(), "CN=Test Root", true, from, to);
        X509Certificate inter = cert(rootKeys.getPrivate(), "CN=Test Root", intKeys.getPublic(), "CN=Test Intermediate", true, from, to);
        CertificateIssuer.Issued leaf = CertificateIssuer.issue(intKeys.getPrivate(),
            new X509Certificate[] {inter, root}, "CN=*.example.org", List.of(),
            CertificateIssuer.KeyType.RSA_2048, null, now);

        // The GitLab bundle's shape: leaf, intermediate, the leaf again -- and
        // out of order for good measure, with the key in PKCS#8.
        String bundle = Pem.certificate(inter) + Pem.certificate(leaf.certificate)
            + Pem.certificate(leaf.certificate);
        KeyPairImport.Parsed p = KeyPairImport.parse(bundle, Pem.privateKey(leaf.privateKey), now);
        check("leaf first", p.chain[0].equals(leaf.certificate));
        check("intermediate kept", p.chain.length == 2 && p.chain[1].equals(inter));
        check("duplicate leaf counted", p.duplicates == 1);
        check("nothing unused", p.unused.isEmpty());

        // Root included, all reversed: a full chain, root last.
        p = KeyPairImport.parse(Pem.certificate(root) + Pem.certificate(inter)
            + Pem.certificate(leaf.certificate), Pem.privateKey(leaf.privateKey), now);
        check("full chain ordered", p.chain.length == 3 && p.chain[0].equals(leaf.certificate)
            && p.chain[1].equals(inter) && p.chain[2].equals(root));

        // The traditional "RSA PRIVATE KEY" form, and the key inside the bundle.
        String pkcs1 = traditional(leaf.privateKey);
        check("PKCS#1 key is traditional", pkcs1.contains("BEGIN RSA PRIVATE KEY"));
        p = KeyPairImport.parse(pkcs1 + Pem.certificate(leaf.certificate) + Pem.certificate(inter), "", now);
        check("PKCS#1 key in the bundle", p.chain.length == 2);

        // An EC key pair, PKCS#8 as openssl 3 writes it. (BouncyCastle's traditional
        // writer leaves a JDK EC key's curve out, which openssl never does.)
        CertificateIssuer.Issued ec = CertificateIssuer.issue(intKeys.getPrivate(),
            new X509Certificate[] {inter, root}, "CN=ec.example.org", List.of(),
            CertificateIssuer.KeyType.EC_P256, null, now);
        p = KeyPairImport.parse(Pem.certificate(ec.certificate) + Pem.certificate(inter),
            Pem.privateKey(ec.privateKey), now);
        check("EC key pair", p.chain.length == 2 && p.chain[0].equals(ec.certificate));

        // A certificate from another chain is left out, and said so.
        p = KeyPairImport.parse(bundle + Pem.certificate(ec.certificate), Pem.privateKey(leaf.privateKey), now);
        check("unrelated certificate unused", p.unused.size() == 1 && p.chain.length == 2);

        refuses("wrong key", () -> KeyPairImport.parse(bundle, Pem.privateKey(ec.privateKey), now));
        refuses("no key", () -> KeyPairImport.parse(bundle, "", now));
        refuses("no certificate", () -> KeyPairImport.parse("", Pem.privateKey(leaf.privateKey), now));
        refuses("expired", () -> KeyPairImport.parse(bundle, Pem.privateKey(leaf.privateKey),
            now.plusSeconds(86400L * 365 * 30)));
        refuses("encrypted key", () -> KeyPairImport.parse(bundle, encrypted(leaf.privateKey), now));

        if (failures > 0) {
            System.err.println("import self-test: " + failures + " failure(s)");
            System.exit(1);
        }
        System.out.println("    import self-test passed");
    }

    private interface Body {
        void run() throws Exception;
    }

    private static void refuses(String name, Body body) {
        try {
            body.run();
            failures++;
            System.err.println("    FAIL " + name + ": accepted");
        } catch (IllegalArgumentException expected) {
            // refused, as it should be
        } catch (Exception e) {
            failures++;
            System.err.println("    FAIL " + name + ": " + e);
        }
    }

    private static String traditional(PrivateKey key) throws Exception {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(key);
        }
        return out.toString();
    }

    /** The traditional OpenSSL encrypted form, "Proc-Type: 4,ENCRYPTED". */
    private static String encrypted(PrivateKey key) throws Exception {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(key, new JcePEMEncryptorBuilder("AES-128-CBC")
                .setProvider(new BouncyCastleProvider()).build("secret".toCharArray()));
        }
        return out.toString();
    }

    private static X509Certificate cert(PrivateKey signer, String issuer, PublicKey subjectKey, String subject,
                                        boolean isCa, Instant from, Instant to) throws Exception {
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
            BigInteger.valueOf(System.nanoTime()), Date.from(from), Date.from(to), new X500Name(subject), subjectKey);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(isCa
            ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        return new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder(CertificateIssuer.signatureAlgorithm(signer)).build(signer)));
    }

    private static void check(String name, boolean ok) {
        if (!ok) {
            failures++;
            System.err.println("    FAIL " + name);
        }
    }
}
