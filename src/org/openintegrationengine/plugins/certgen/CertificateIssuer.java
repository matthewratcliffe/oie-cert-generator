/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;

/**
 * Issues a certificate for a new key pair, signed by a CA's key, for mutual TLS.
 *
 * <p>Pure JDK and BouncyCastle -- nothing here touches the engine -- so the build
 * exercises it directly. BouncyCastle comes from the engine's own server-lib and is
 * used only to build and sign the certificate; no provider is registered, so the
 * engine's JCA setup is left exactly as it was.
 *
 * <p>Every certificate is an end-entity certificate for both ends of an mTLS
 * connection: basicConstraints CA:false, extendedKeyUsage serverAuth and clientAuth.
 * It is valid for {@value #DEFAULT_YEARS} years unless asked otherwise, and never
 * past its CA: a certificate outliving its issuer would fail path validation the
 * day the CA expires anyway, so the end date is cut to the CA's and the result says
 * so.
 */
public final class CertificateIssuer {

    public static final int DEFAULT_YEARS = 25;

    /** Backdated so a peer whose clock runs a little behind still accepts it. */
    private static final Duration BACKDATE = Duration.ofMinutes(5);

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A host name a server certificate can carry as a DNS SAN: dotted, or localhost. */
    private static final Pattern HOSTNAME = Pattern.compile(
        "(?i)^(\\*\\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$|^localhost$");
    private static final Pattern IP_LITERAL = Pattern.compile(
        "^(\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)$");

    /** The key the new certificate is issued for. */
    public enum KeyType {
        RSA_2048("RSA", 2048, null),
        RSA_3072("RSA", 3072, null),
        RSA_4096("RSA", 4096, null),
        EC_P256("EC", 256, "secp256r1"),
        EC_P384("EC", 384, "secp384r1");

        final String algorithm;
        final int size;
        final String curve;

        KeyType(String algorithm, int size, String curve) {
            this.algorithm = algorithm;
            this.size = size;
            this.curve = curve;
        }

        /** RSA_2048, rsa-2048, "RSA 2048", EC_P256, ec-p256 ... */
        public static KeyType parse(String value) {
            if (value == null || value.isBlank()) {
                return RSA_2048;
            }
            String norm = value.trim().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
            for (KeyType t : values()) {
                if (t.name().equals(norm) || t.name().replace("_P", "_").equals(norm)) {
                    return t;
                }
            }
            throw new IllegalArgumentException("Key type \"" + value + "\" is not one of "
                + "RSA_2048, RSA_3072, RSA_4096, EC_P256 or EC_P384.");
        }
    }

    /** What issue() produced. */
    public static final class Issued {
        public final X509Certificate certificate;
        public final PrivateKey privateKey;
        /** The new certificate first, then the CA's chain. */
        public final X509Certificate[] chain;
        /** True when the end date was cut short to the CA's. */
        public final boolean cappedToCa;

        Issued(X509Certificate certificate, PrivateKey privateKey, X509Certificate[] chain,
               boolean cappedToCa) {
            this.certificate = certificate;
            this.privateKey = privateKey;
            this.chain = chain;
            this.cappedToCa = cappedToCa;
        }
    }

    private CertificateIssuer() {
    }

    /**
     * True when this certificate may sign others: basicConstraints CA:true, or an
     * X.509 v1 self-signed root, which predates the extension. A keyUsage that is
     * present must also allow keyCertSign.
     */
    public static boolean isCa(X509Certificate cert) {
        boolean ca = cert.getBasicConstraints() >= 0
            || (cert.getVersion() == 1
                && cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
        boolean[] usage = cert.getKeyUsage();
        return ca && (usage == null || (usage.length > 5 && usage[5]));
    }

    /**
     * Parses a subject such as {@code CN=client1, O=hTrak, C=AU}. A bare name with no
     * attribute is taken as the CN.
     *
     * <p>Through the JDK's X500Principal, which reads the string in RFC 2253 order --
     * most specific first, as keytool and OpenSSL write it -- and encodes it the
     * conventional way round, C before O before CN. BouncyCastle's own string parser
     * keeps the typed order, which would put CN first in the certificate.
     */
    public static X500Name parseSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("A subject is required, e.g. CN=client1, O=hTrak.");
        }
        String s = subject.trim();
        if (!s.contains("=")) {
            s = "CN=" + escapeRdnValue(s);
        }
        try {
            X500Name name = X500Name.getInstance(new X500Principal(s).getEncoded());
            if (name.getRDNs().length == 0) {
                throw new IllegalArgumentException("empty");
            }
            return name;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The subject \"" + subject + "\" is not a "
                + "distinguished name; write it as CN=client1, O=hTrak, C=AU.", e);
        }
    }

    /** RFC 2253 escaping for an attribute value. */
    static String escapeRdnValue(String value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean edgeSpace = c == ' ' && (i == 0 || i == value.length() - 1);
            if (",+\"\\<>;=".indexOf(c) >= 0 || edgeSpace || (c == '#' && i == 0)) {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** The subject's first CN, or null. */
    public static String commonName(X500Name name) {
        RDN[] cns = name.getRDNs(BCStyle.CN);
        if (cns.length == 0) {
            return null;
        }
        ASN1Encodable value = cns[0].getFirst().getValue();
        return IETFUtils.valueToString(value);
    }

    /**
     * Issues a certificate.
     *
     * @param caKey        the CA's private key
     * @param caChain      the CA's certificate first, then whatever chain it carries
     * @param subject      the new certificate's subject
     * @param altNames     subjectAltName entries -- DNS:host, IP:addr, email:x, URI:x,
     *                     or bare values, typed by their shape. Empty with a CN that is a
     *                     host name puts that host name in as DNS, which TLS servers need.
     * @param keyType      the new key
     * @param validityDays null for {@value #DEFAULT_YEARS} years
     * @param now          the issuing time
     */
    public static Issued issue(PrivateKey caKey, X509Certificate[] caChain, String subject,
                               List<String> altNames, KeyType keyType, Integer validityDays,
                               Instant now) throws Exception {
        if (caChain == null || caChain.length == 0) {
            throw new IllegalArgumentException("The CA has no certificate.");
        }
        X509Certificate ca = caChain[0];
        String caName = ca.getSubjectX500Principal().getName();
        if (!isCa(ca)) {
            throw new IllegalArgumentException("\"" + caName + "\" is not a CA certificate "
                + "(no basicConstraints CA:true, or keyUsage without keyCertSign), so what it "
                + "signs would not validate. Choose a CA key pair.");
        }
        Instant caStart = ca.getNotBefore().toInstant();
        Instant caEnd = ca.getNotAfter().toInstant();
        if (!caEnd.isAfter(now)) {
            throw new IllegalArgumentException("The CA \"" + caName + "\" expired on "
                + caEnd + ".");
        }
        if (caStart.isAfter(now)) {
            throw new IllegalArgumentException("The CA \"" + caName + "\" is not valid until "
                + caStart + ".");
        }

        X500Name subjectName = parseSubject(subject);
        GeneralNames sans = altNames(altNames, commonName(subjectName));

        Instant notBefore = now.minus(BACKDATE);
        if (notBefore.isBefore(caStart)) {
            notBefore = caStart;
        }
        Instant wanted;
        if (validityDays == null) {
            wanted = now.atOffset(ZoneOffset.UTC).plusYears(DEFAULT_YEARS).toInstant();
        } else {
            if (validityDays < 1) {
                throw new IllegalArgumentException("The validity must be at least one day.");
            }
            wanted = now.plus(Duration.ofDays(validityDays));
        }
        boolean capped = wanted.isAfter(caEnd);
        Instant notAfter = capped ? caEnd : wanted;

        KeyPair keyPair = generate(keyType);
        PublicKey publicKey = keyPair.getPublic();

        // The issuer is the CA's subject exactly as encoded in its certificate, so the
        // two compare byte for byte in path building.
        X500Name issuer = new JcaX509CertificateHolder(ca).getSubject();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
            serial(), Date.from(notBefore), Date.from(notAfter), subjectName, publicKey);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        int usage = KeyUsage.digitalSignature
            | ("RSA".equals(keyType.algorithm) ? KeyUsage.keyEncipherment : KeyUsage.keyAgreement);
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
            new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
            ext.createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
            ext.createAuthorityKeyIdentifier(ca));
        if (sans != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(caKey)).build(caKey);
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

        // Proved before it is handed out: signed by this CA, and valid now.
        cert.verify(ca.getPublicKey());
        cert.checkValidity(Date.from(now));

        X509Certificate[] chain = new X509Certificate[caChain.length + 1];
        chain[0] = cert;
        System.arraycopy(caChain, 0, chain, 1, caChain.length);
        return new Issued(cert, keyPair.getPrivate(), chain, capped);
    }

    static KeyPair generate(KeyType type) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(type.algorithm);
        if (type.curve != null) {
            gen.initialize(new ECGenParameterSpec(type.curve), RANDOM);
        } else {
            gen.initialize(type.size, RANDOM);
        }
        return gen.generateKeyPair();
    }

    /** Positive, non-zero, 159 bits of randomness: within RFC 5280's 20-octet limit. */
    static BigInteger serial() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        bytes[0] &= 0x7f;
        bytes[0] |= 0x01;
        return new BigInteger(1, bytes);
    }

    /** The CA key decides the signature: SHA-256 with RSA, ECDSA matched to the curve. */
    static String signatureAlgorithm(PrivateKey caKey) {
        String alg = caKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(alg)) {
            return "SHA256withRSA";
        }
        if ("EC".equalsIgnoreCase(alg) || "ECDSA".equalsIgnoreCase(alg)) {
            int bits = caKey instanceof ECKey
                ? ((ECKey) caKey).getParams().getOrder().bitLength() : 256;
            return bits <= 256 ? "SHA256withECDSA" : bits <= 384 ? "SHA384withECDSA" : "SHA512withECDSA";
        }
        if ("Ed25519".equalsIgnoreCase(alg) || "EdDSA".equalsIgnoreCase(alg)) {
            return "Ed25519";
        }
        throw new IllegalArgumentException("The CA's key is " + alg + ", which this cannot sign "
            + "with; use an RSA or EC CA.");
    }

    static GeneralNames altNames(List<String> entries, String commonName) {
        List<GeneralName> names = new ArrayList<>();
        if (entries != null) {
            for (String raw : entries) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                names.add(altName(raw.trim()));
            }
        }
        if (names.isEmpty() && commonName != null && HOSTNAME.matcher(commonName).matches()) {
            names.add(new GeneralName(GeneralName.dNSName, commonName));
        }
        return names.isEmpty() ? null : new GeneralNames(names.toArray(new GeneralName[0]));
    }

    private static GeneralName altName(String entry) {
        int colon = entry.indexOf(':');
        String kind = colon > 0 ? entry.substring(0, colon).trim().toLowerCase(Locale.ROOT) : "";
        String value = colon > 0 ? entry.substring(colon + 1).trim() : entry;
        switch (kind) {
            case "dns":
                return new GeneralName(GeneralName.dNSName, value);
            case "ip":
                return ipName(value, entry);
            case "email":
            case "rfc822":
                return new GeneralName(GeneralName.rfc822Name, value);
            case "uri":
                return new GeneralName(GeneralName.uniformResourceIdentifier, value);
            default:
                // A bare value, typed by its shape -- or an IPv6 literal, whose colons
                // look like a prefix.
                if (IP_LITERAL.matcher(entry).matches()) {
                    return ipName(entry, entry);
                }
                if (entry.contains("@")) {
                    return new GeneralName(GeneralName.rfc822Name, entry);
                }
                if (kind.isEmpty() || !kind.matches("[a-z0-9]+")) {
                    return new GeneralName(GeneralName.dNSName, entry);
                }
                throw new IllegalArgumentException("Subject alternative name \"" + entry
                    + "\": use DNS:, IP:, email: or URI:.");
        }
    }

    private static GeneralName ipName(String value, String entry) {
        try {
            // Numeric literals only: getByName resolves names, which must not happen here.
            if (!IP_LITERAL.matcher(value).matches()) {
                throw new IllegalArgumentException("not an address");
            }
            InetAddress.getByName(value);
            return new GeneralName(GeneralName.iPAddress, value);
        } catch (Exception e) {
            throw new IllegalArgumentException("Subject alternative name \"" + entry
                + "\" is not an IP address.", e);
        }
    }
}
