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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Checks CertificateIssuer against the rules it promises, with throwaway CAs:
 * run by build.sh, no engine needed. Exits non-zero on the first failure.
 */
public final class IssuerSelfTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Instant now = Instant.now();

        // A 30-year CA: a default certificate gets the full 25 years.
        KeyPair caKeys = CertificateIssuer.generate(CertificateIssuer.KeyType.RSA_2048);
        X509Certificate ca30 = ca(caKeys, "CN=Test Root CA, O=hTrak", now.minusSeconds(3600), years(now, 30), true);
        CertificateIssuer.Issued a = CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca30}, "CN=client1.htrak.com, O=hTrak, C=AU", List.of(),
            CertificateIssuer.KeyType.RSA_2048, null, now);
        check("25-year default", !a.cappedToCa
            && approx(a.certificate.getNotAfter().toInstant(), years(now, 25)));
        check("subject kept", a.certificate.getSubjectX500Principal().getName()
            .equals("CN=client1.htrak.com,O=hTrak,C=AU"));
        check("issuer is the CA", a.certificate.getIssuerX500Principal().equals(ca30.getSubjectX500Principal()));
        List<String> eku = a.certificate.getExtendedKeyUsage();
        check("serverAuth and clientAuth", eku.contains("1.3.6.1.5.5.7.3.1") && eku.contains("1.3.6.1.5.5.7.3.2"));
        check("not a CA", a.certificate.getBasicConstraints() == -1);
        check("RSA key usage: digitalSignature, keyEncipherment",
            a.certificate.getKeyUsage()[0] && a.certificate.getKeyUsage()[2]);
        check("host name CN becomes a DNS SAN", hasSan(a.certificate, 2, "client1.htrak.com"));
        check("chain is cert then CA", a.chain.length == 2 && a.chain[1].equals(ca30));
        check("path validates to the CA", validates(a.chain, ca30));
        check("backdated, but not before the CA", !a.certificate.getNotBefore().before(ca30.getNotBefore())
            && a.certificate.getNotBefore().toInstant().isBefore(now));

        // A CA expiring in 10 years: the certificate is cut to the CA's end.
        X509Certificate ca10 = ca(caKeys, "CN=Short CA", now.minusSeconds(3600), years(now, 10), true);
        CertificateIssuer.Issued b = CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca10}, "CN=client2", List.of(), CertificateIssuer.KeyType.EC_P256, null, now);
        check("cut to the CA's expiry", b.cappedToCa && b.certificate.getNotAfter().equals(ca10.getNotAfter()));
        check("EC key", "EC".equals(b.privateKey.getAlgorithm()));
        check("EC key usage: keyAgreement", b.certificate.getKeyUsage()[4]);
        check("non-host CN gets no SAN", b.certificate.getSubjectAlternativeNames() == null);
        check("EC cert validates", validates(b.chain, ca10));

        // Explicit days; explicit SANs of each kind.
        CertificateIssuer.Issued c = CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca30}, "CN=svc, OU=Ops, O=hTrak",
            List.of("DNS:svc.internal", "IP:10.1.2.3", "email:ops@htrak.com", "partner.example.org"),
            CertificateIssuer.KeyType.RSA_2048, 365, now);
        check("365 days", approx(c.certificate.getNotAfter().toInstant(), now.plusSeconds(365L * 86400)));
        check("DNS SAN", hasSan(c.certificate, 2, "svc.internal") && hasSan(c.certificate, 2, "partner.example.org"));
        check("IP SAN", hasSan(c.certificate, 7, "10.1.2.3"));
        check("email SAN", hasSan(c.certificate, 1, "ops@htrak.com"));

        // An EC CA signs with ECDSA.
        KeyPair ecCaKeys = CertificateIssuer.generate(CertificateIssuer.KeyType.EC_P384);
        X509Certificate ecCa = ca(ecCaKeys, "CN=EC CA", now.minusSeconds(60), years(now, 40), true);
        CertificateIssuer.Issued d = CertificateIssuer.issue(ecCaKeys.getPrivate(),
            new X509Certificate[] {ecCa}, "bare name", List.of(), CertificateIssuer.KeyType.RSA_2048, null, now);
        check("EC CA signs SHA384withECDSA", "SHA384withECDSA".equals(d.certificate.getSigAlgName()));
        check("bare name becomes CN", d.certificate.getSubjectX500Principal().getName().equals("CN=bare name"));
        check("signed by EC CA validates", validates(d.chain, ecCa));

        // Refusals.
        X509Certificate leaf = ca(caKeys, "CN=Not a CA", now.minusSeconds(60), years(now, 5), false);
        refused("non-CA signer", () -> CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {leaf}, "CN=x", List.of(), CertificateIssuer.KeyType.RSA_2048, null, now));
        X509Certificate expired = ca(caKeys, "CN=Old CA", now.minusSeconds(86400L * 20), now.minusSeconds(86400), true);
        refused("expired CA", () -> CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {expired}, "CN=x", List.of(), CertificateIssuer.KeyType.RSA_2048, null, now));
        refused("empty subject", () -> CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca30}, " ", List.of(), CertificateIssuer.KeyType.RSA_2048, null, now));
        refused("bad SAN kind", () -> CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca30}, "CN=x", List.of("foo:bar"), CertificateIssuer.KeyType.RSA_2048, null, now));
        refused("zero days", () -> CertificateIssuer.issue(caKeys.getPrivate(),
            new X509Certificate[] {ca30}, "CN=x", List.of(), CertificateIssuer.KeyType.RSA_2048, 0, now));
        refused("unknown key type", () -> CertificateIssuer.KeyType.parse("DSA_1024"));
        check("key type spellings", CertificateIssuer.KeyType.parse("ec-p256") == CertificateIssuer.KeyType.EC_P256
            && CertificateIssuer.KeyType.parse("rsa 4096") == CertificateIssuer.KeyType.RSA_4096
            && CertificateIssuer.KeyType.parse("") == CertificateIssuer.KeyType.RSA_2048);

        // PKCS#12 and PEM round trips.
        byte[] p12 = CertGenService.pkcs12("client1", a, "s3cret".toCharArray());
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), "s3cret".toCharArray());
        check("PKCS#12 holds key and chain", ks.isKeyEntry("client1")
            && ks.getCertificateChain("client1").length == 2
            && ks.getKey("client1", "s3cret".toCharArray()) != null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> pem =
            cf.generateCertificates(new ByteArrayInputStream(Pem.certificates(a.chain).getBytes()));
        check("PEM chain parses back", pem.size() == 2);
        check("PEM key is PKCS#8", Pem.privateKey(a.privateKey).startsWith("-----BEGIN PRIVATE KEY-----\n"));
        check("generated password", CertGenService.generatePassword().length() == 20);

        if (failures > 0) {
            System.err.println("    " + failures + " check(s) failed");
            System.exit(1);
        }
        System.out.println("    issuer: all checks passed");
    }

    private static X509Certificate ca(KeyPair keys, String dn, Instant from, Instant to, boolean isCa) throws Exception {
        X500Name name = new X500Name(dn);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(System.nanoTime()),
            Date.from(from), Date.from(to), name, keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(isCa
            ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        String alg = CertificateIssuer.signatureAlgorithm(keys.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder(alg).build(keys.getPrivate())));
    }

    private static boolean validates(X509Certificate[] chain, X509Certificate root) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(
                cf.generateCertPath(List.of(chain).subList(0, chain.length - 1)), params);
            return true;
        } catch (Exception e) {
            System.err.println("      path validation: " + e);
            return false;
        }
    }

    private static boolean hasSan(X509Certificate cert, int type, String value) throws Exception {
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null) {
            return false;
        }
        for (List<?> san : sans) {
            if (((Integer) san.get(0)) == type && value.equals(san.get(1))) {
                return true;
            }
        }
        return false;
    }

    private static Instant years(Instant from, int n) {
        return from.atOffset(ZoneOffset.UTC).plusYears(n).toInstant();
    }

    /** Certificates carry whole seconds. */
    private static boolean approx(Instant a, Instant b) {
        return Math.abs(a.getEpochSecond() - b.getEpochSecond()) <= 1;
    }

    private static void check(String name, boolean ok) {
        if (!ok) {
            failures++;
            System.err.println("    FAIL " + name);
        }
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void refused(String name, Action action) {
        try {
            action.run();
            check(name + " refused", false);
        } catch (IllegalArgumentException expected) {
            // refused, as it should be
        } catch (Exception e) {
            check(name + " refused with IllegalArgumentException (got " + e + ")", false);
        }
    }
}
