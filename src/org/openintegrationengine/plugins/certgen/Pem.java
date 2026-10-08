/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/** PEM text: certificates, and private keys as unencrypted PKCS#8. */
final class Pem {

    private static final Base64.Encoder MIME = Base64.getMimeEncoder(64, new byte[] {'\n'});

    private Pem() {
    }

    static String certificate(X509Certificate cert) throws CertificateEncodingException {
        return block("CERTIFICATE", cert.getEncoded());
    }

    static String certificates(X509Certificate[] chain) throws CertificateEncodingException {
        StringBuilder sb = new StringBuilder();
        for (X509Certificate cert : chain) {
            sb.append(certificate(cert));
        }
        return sb.toString();
    }

    /** RSA and EC keys from the JDK encode as PKCS#8 already. */
    static String privateKey(PrivateKey key) {
        if (!"PKCS#8".equalsIgnoreCase(key.getFormat())) {
            throw new IllegalStateException("The key encodes as " + key.getFormat() + ", not PKCS#8.");
        }
        return block("PRIVATE KEY", key.getEncoded());
    }

    private static String block(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + MIME.encodeToString(der) + "\n-----END " + type + "-----\n";
    }
}
