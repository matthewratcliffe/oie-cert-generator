/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Lists the CA key pairs TLS Manager holds and issues certificates signed by them.
 */
final class CertGenService {

    private static final Logger LOG = LogManager.getLogger(CertGenService.class);

    /** "CA" as a word of the alias, in any case: root-ca, Internal CA, ca_2026. */
    private static final Pattern CA_WORD = Pattern.compile("(?i)(^|[^a-z])ca([^a-z]|$)");

    private static final String PASSWORD_ALPHABET =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The key pairs that can sign, the one to offer first, and the defaults the form
     * starts from. The default is the first CA whose name contains "CA" -- exactly, or
     * as a word -- else the first CA.
     */
    Map<String, Object> authorities() {
        Map<String, Object> out = new LinkedHashMap<>();
        List<TlsManagerKeyStore.Entry> pairs;
        try {
            pairs = TlsManagerKeyStore.keyPairs();
        } catch (Exception e) {
            out.put("ok", Boolean.FALSE);
            out.put("error", message(e));
            return out;
        }
        Instant now = Instant.now();
        List<Map<String, Object>> list = new ArrayList<>();
        // TLS Manager's keystore is PKCS#12, which lowercases aliases ("Test Root CA"
        // reads back as "test root ca"), so the case-sensitive match only helps a
        // file-backed store; the case-insensitive ones are what find it in the usual one.
        String byName = null;
        String byWord = null;
        String bySubstring = null;
        String anyCa = null;
        for (TlsManagerKeyStore.Entry pair : pairs) {
            X509Certificate cert = pair.chain[0];
            boolean ca = CertificateIssuer.isCa(cert);
            boolean expired = !cert.getNotAfter().toInstant().isAfter(now);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("alias", pair.alias);
            m.put("subject", cert.getSubjectX500Principal().getName());
            m.put("notAfter", cert.getNotAfter().toInstant().toString());
            m.put("keyAlgorithm", pair.key.getAlgorithm());
            m.put("ca", ca);
            m.put("expired", expired);
            list.add(m);
            if (ca && !expired) {
                if (byName == null && pair.alias.contains("CA")) {
                    byName = pair.alias;
                }
                if (byWord == null && CA_WORD.matcher(pair.alias).find()) {
                    byWord = pair.alias;
                }
                // Only CA certificates get here, so "ca" inside a word -- rootca -- is safe.
                if (bySubstring == null && pair.alias.toLowerCase(Locale.ROOT).contains("ca")) {
                    bySubstring = pair.alias;
                }
                if (anyCa == null) {
                    anyCa = pair.alias;
                }
            }
        }
        String preferred = byName != null ? byName : byWord != null ? byWord
            : bySubstring != null ? bySubstring : anyCa;
        out.put("ok", Boolean.TRUE);
        out.put("authorities", list);
        out.put("defaultAlias", preferred == null ? "" : preferred);
        out.put("defaultYears", CertificateIssuer.DEFAULT_YEARS);
        out.put("defaultKeyType", CertificateIssuer.KeyType.RSA_2048.name());
        out.put("keyTypes", Arrays.stream(CertificateIssuer.KeyType.values())
            .map(Enum::name).collect(java.util.stream.Collectors.toList()));
        return out;
    }

    /**
     * Issues and saves a certificate.
     *
     * <p>Fields: caAlias (default: as authorities() picks), subject (required),
     * alias (the name it is saved under; default from the CN), subjectAltNames
     * (comma- or newline-separated), keyType (default RSA_2048), validityDays (default
     * {@value CertificateIssuer#DEFAULT_YEARS} years), pkcs12Password (default: a
     * generated one, returned), save (default true), trust (add the certificate
     * to TLS Manager's trusted certificates; default true).
     */
    Map<String, Object> issue(Map<String, String> in, String user) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            String caAlias = text(in, "caAlias");
            if (caAlias.isEmpty()) {
                caAlias = String.valueOf(authorities().getOrDefault("defaultAlias", ""));
                if (caAlias.isEmpty()) {
                    throw new IllegalArgumentException("TLS Manager has no CA key pair to sign with.");
                }
            }
            TlsManagerKeyStore.Entry ca = TlsManagerKeyStore.keyPair(caAlias);

            String subject = text(in, "subject");
            CertificateIssuer.KeyType keyType = CertificateIssuer.KeyType.parse(text(in, "keyType"));
            Integer days = null;
            String rawDays = text(in, "validityDays");
            if (!rawDays.isEmpty()) {
                try {
                    days = Integer.valueOf(rawDays);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("The validity \"" + rawDays + "\" is not a number of days.");
                }
            }
            List<String> sans = new ArrayList<>();
            for (String s : text(in, "subjectAltNames").split("[,\\n]")) {
                if (!s.isBlank()) {
                    sans.add(s.trim());
                }
            }
            boolean save = !"false".equalsIgnoreCase(text(in, "save"));
            // Trusted too, by default: a TLS listener checks a client's certificate against
            // TLS Manager's trusted certificates, so this is what lets a channel accept it.
            boolean trust = !"false".equalsIgnoreCase(text(in, "trust"));

            // Checked before issuing, so a taken name costs nothing.
            String alias = text(in, "alias");
            if (alias.isEmpty()) {
                String cn = CertificateIssuer.commonName(CertificateIssuer.parseSubject(subject));
                alias = (cn == null || cn.isBlank() ? "certificate" : cn).trim();
            }
            if (save && TlsManagerKeyStore.contains(alias)) {
                throw new IllegalArgumentException("TLS Manager already has \"" + alias
                    + "\"; give this certificate another name.");
            }
            if (trust && TlsManagerKeyStore.trustedContains(alias)) {
                throw new IllegalArgumentException("TLS Manager already trusts a certificate named \""
                    + alias + "\"; give this certificate another name.");
            }

            CertificateIssuer.Issued issued = CertificateIssuer.issue(ca.key, ca.chain, subject,
                sans, keyType, days, Instant.now());

            String password = text(in, "pkcs12Password");
            boolean generated = password.isEmpty();
            if (generated) {
                password = generatePassword();
            }
            byte[] p12 = pkcs12(alias, issued, password.toCharArray());

            if (save) {
                TlsManagerKeyStore.add(alias, issued.privateKey, issued.chain);
            }
            if (trust) {
                TlsManagerKeyStore.addTrusted(alias, issued.certificate);
            }

            X509Certificate cert = issued.certificate;
            out.put("ok", Boolean.TRUE);
            out.put("alias", alias);
            out.put("saved", save);
            out.put("trusted", trust);
            out.put("subject", cert.getSubjectX500Principal().getName());
            out.put("issuer", cert.getIssuerX500Principal().getName());
            out.put("caAlias", caAlias);
            out.put("serial", cert.getSerialNumber().toString(16).toUpperCase(Locale.ROOT));
            out.put("notBefore", cert.getNotBefore().toInstant().toString());
            out.put("notAfter", cert.getNotAfter().toInstant().toString());
            out.put("cappedToCa", issued.cappedToCa);
            out.put("keyType", keyType.name());
            out.put("certificatePem", Pem.certificate(cert));
            out.put("chainPem", Pem.certificates(issued.chain));
            out.put("privateKeyPem", Pem.privateKey(issued.privateKey));
            out.put("pkcs12", Base64.getEncoder().encodeToString(p12));
            out.put("pkcs12Password", password);
            out.put("pkcs12PasswordGenerated", generated);
            LOG.info("certificate generator: {} issued {} (serial {}) signed by {}, valid to {}{}{}{}",
                user == null ? "someone" : user, out.get("subject"), out.get("serial"), caAlias,
                out.get("notAfter"), issued.cappedToCa ? " (cut to the CA's expiry)" : "",
                save ? ", saved as TLS Manager key pair \"" + alias + "\"" : "",
                trust ? " and trusted" : "");
        } catch (Exception e) {
            out.clear();
            out.put("ok", Boolean.FALSE);
            out.put("error", message(e));
        }
        return out;
    }

    /**
     * Imports a key pair from PEM -- a certificate issued elsewhere, a public CA's say --
     * so TLS connectors can present it by alias.
     *
     * <p>Fields: alias (required), certificatePem (the certificate and its chain, in
     * any order; may hold the key too), privateKeyPem (unencrypted; optional when it
     * is in certificatePem), replace (replace a key pair already under alias;
     * default false). The chain is stored leaf first with its intermediates, which
     * TLS Manager's own key pair API drops.
     */
    Map<String, Object> importKeyPair(Map<String, String> in, String user) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            String alias = text(in, "alias");
            if (alias.isEmpty()) {
                throw new IllegalArgumentException("Give the alias to save the key pair under.");
            }
            KeyPairImport.Parsed parsed = KeyPairImport.parse(text(in, "certificatePem"),
                text(in, "privateKeyPem"), Instant.now());
            boolean replace = "true".equalsIgnoreCase(text(in, "replace"));
            TlsManagerKeyStore.Put result = TlsManagerKeyStore.put(alias, parsed.key, parsed.chain, replace);

            X509Certificate leaf = parsed.chain[0];
            List<String> chain = new ArrayList<>();
            for (X509Certificate c : parsed.chain) {
                chain.add(c.getSubjectX500Principal().getName());
            }
            out.put("ok", Boolean.TRUE);
            out.put("alias", alias);
            out.put("result", result.name().toLowerCase(Locale.ROOT));
            out.put("subject", leaf.getSubjectX500Principal().getName());
            out.put("issuer", leaf.getIssuerX500Principal().getName());
            out.put("notAfter", leaf.getNotAfter().toInstant().toString());
            out.put("chainLength", parsed.chain.length);
            out.put("chain", String.join("\n", chain));
            out.put("ignored", parsed.unused.size());
            out.put("duplicates", parsed.duplicates);
            LOG.info("certificate generator: {} imported key pair \"{}\" ({}): {}, chain of {}, valid to {}{}",
                user == null ? "someone" : user, alias, out.get("result"), out.get("subject"),
                parsed.chain.length, out.get("notAfter"),
                parsed.unused.isEmpty() ? "" : "; " + parsed.unused.size()
                    + " certificate(s) not in its chain left out");
        } catch (Exception e) {
            out.clear();
            out.put("ok", Boolean.FALSE);
            out.put("error", message(e));
        }
        return out;
    }

    static byte[] pkcs12(String alias, CertificateIssuer.Issued issued, char[] password) throws Exception {
        KeyStore p12 = KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        p12.setKeyEntry(alias, issued.privateKey, password, issued.chain);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        p12.store(bytes, password);
        return bytes.toByteArray();
    }

    static String generatePassword() {
        StringBuilder sb = new StringBuilder(20);
        for (int i = 0; i < 20; i++) {
            sb.append(PASSWORD_ALPHABET.charAt(RANDOM.nextInt(PASSWORD_ALPHABET.length())));
        }
        return sb.toString();
    }

    private static String text(Map<String, String> in, String key) {
        String v = in == null ? null : in.get(key);
        return v == null ? "" : v.trim();
    }

    private static String message(Throwable t) {
        Throwable cause = t;
        // Reflection wraps what TLS Manager threw.
        while (cause instanceof java.lang.reflect.InvocationTargetException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        String m = cause.getMessage();
        if (!(cause instanceof IllegalArgumentException || cause instanceof IllegalStateException)) {
            LOG.warn("certificate generator: {}", m, cause);
        }
        return m == null || m.isBlank() ? cause.getClass().getSimpleName() : m;
    }
}
