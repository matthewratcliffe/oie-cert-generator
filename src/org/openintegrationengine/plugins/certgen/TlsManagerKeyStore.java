/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.certgen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * TLS Manager's local key pairs -- the "additional keystore" its console page and
 * TLS connectors use -- read and added to through TLS Manager itself.
 *
 * <p>TLS Manager holds that keystore in memory (CertificateService.externalKeyStore)
 * and persists it through a backend: base64 PKCS#12 in the configuration table by
 * default, or a file. Writing the table directly would leave the in-memory copy
 * stale until a restart, so an addition goes through its public
 * {@code storeExtraKeyStore(byte[], char[])}, which reloads the live keystore and
 * persists it in one call. Reflection rather than a compile-time dependency: TLS
 * Manager is a third-party extension, this plugin must still load without it, and
 * its classes are only on the classpath when it is installed.
 *
 * <p>The keystore password is the backend's: empty for the database backend, the
 * configured one for a file.
 */
final class TlsManagerKeyStore {

    static final String PLUGIN_CLASS =
        "org.openintegrationengine.tlsmanager.server.TLSServicePlugin";

    /** Serialises additions: each is read-modify-write of the whole keystore. */
    private static final Object LOCK = new Object();

    /** A key pair in the store. */
    static final class Entry {
        final String alias;
        final PrivateKey key;
        final X509Certificate[] chain;

        Entry(String alias, PrivateKey key, X509Certificate[] chain) {
            this.alias = alias;
            this.key = key;
            this.chain = chain;
        }
    }

    private TlsManagerKeyStore() {
    }

    /** TLS Manager's CertificateService, or an exception that says why there is none. */
    private static Object certificateService() throws Exception {
        Class<?> plugin;
        try {
            plugin = Class.forName(PLUGIN_CLASS, true, TlsManagerKeyStore.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            ClassLoader context = Thread.currentThread().getContextClassLoader();
            try {
                plugin = Class.forName(PLUGIN_CLASS, true, context);
            } catch (ClassNotFoundException again) {
                throw new IllegalStateException("TLS Manager is not installed on this engine; "
                    + "the certificate generator signs with its local key pairs.");
            }
        }
        Object instance = plugin.getMethod("getPluginInstance").invoke(null);
        if (instance == null) {
            throw new IllegalStateException("TLS Manager has not started yet.");
        }
        Object service = plugin.getMethod("getCertificateService").invoke(instance);
        if (service == null) {
            throw new IllegalStateException("TLS Manager's certificate service is not available.");
        }
        return service;
    }

    private static KeyStore liveKeyStore(Object service) throws Exception {
        KeyStore ks = (KeyStore) service.getClass().getMethod("getExternalKeyStore").invoke(service);
        if (ks == null) {
            throw new IllegalStateException("TLS Manager has no local key store.");
        }
        return ks;
    }

    private static KeyStore liveTrustStore(Object service) throws Exception {
        KeyStore ks = (KeyStore) service.getClass().getMethod("getExternalTrustStore").invoke(service);
        if (ks == null) {
            throw new IllegalStateException("TLS Manager has no trusted certificate store.");
        }
        return ks;
    }

    private static char[] password(Object service) throws Exception {
        return password(service, "extraKeyStoreBackend");
    }

    private static char[] password(Object service, String backendField) throws Exception {
        Field field = service.getClass().getDeclaredField(backendField);
        field.setAccessible(true);
        Object backend = field.get(service);
        if (backend == null) {
            throw new IllegalStateException("TLS Manager's key store backend is not set up.");
        }
        // loadPassword is declared on the backend's public interface; look it up there,
        // since the implementing classes need not be public.
        for (Class<?> iface : backend.getClass().getInterfaces()) {
            try {
                char[] pw = (char[]) iface.getMethod("loadPassword").invoke(backend);
                return pw == null ? new char[0] : pw;
            } catch (NoSuchMethodException ignored) {
                // try the next interface
            }
        }
        throw new IllegalStateException("TLS Manager's key store backend has no loadPassword.");
    }

    /** Every key pair, aliases in order. */
    static List<Entry> keyPairs() throws Exception {
        Object service = certificateService();
        KeyStore ks = liveKeyStore(service);
        char[] pw = password(service);
        List<Entry> out = new ArrayList<>();
        synchronized (LOCK) {
            List<String> aliases = Collections.list(ks.aliases());
            Collections.sort(aliases, String.CASE_INSENSITIVE_ORDER);
            for (String alias : aliases) {
                if (!ks.isKeyEntry(alias)) {
                    continue;
                }
                Entry entry = read(ks, alias, pw);
                if (entry != null) {
                    out.add(entry);
                }
            }
        }
        return out;
    }

    /** One key pair, or an exception naming what is wrong with it. */
    static Entry keyPair(String alias) throws Exception {
        Object service = certificateService();
        KeyStore ks = liveKeyStore(service);
        char[] pw = password(service);
        synchronized (LOCK) {
            if (!ks.containsAlias(alias)) {
                throw new IllegalArgumentException("TLS Manager has no key pair \"" + alias + "\".");
            }
            if (!ks.isKeyEntry(alias)) {
                throw new IllegalArgumentException("\"" + alias + "\" in TLS Manager is a "
                    + "certificate without a private key, so it cannot sign.");
            }
            Entry entry = read(ks, alias, pw);
            if (entry == null) {
                throw new IllegalArgumentException("The private key of \"" + alias
                    + "\" could not be read with TLS Manager's key store password.");
            }
            return entry;
        }
    }

    static boolean contains(String alias) throws Exception {
        Object service = certificateService();
        synchronized (LOCK) {
            return liveKeyStore(service).containsAlias(alias);
        }
    }

    static boolean trustedContains(String alias) throws Exception {
        Object service = certificateService();
        synchronized (LOCK) {
            return liveTrustStore(service).containsAlias(alias);
        }
    }

    /**
     * Adds a certificate to TLS Manager's trusted certificates -- what a TLS listener
     * checks a client's certificate against -- and saves that store through TLS
     * Manager. Refuses an alias already in use there.
     */
    static void addTrusted(String alias, X509Certificate cert) throws Exception {
        Object service = certificateService();
        char[] pw = password(service, "extraTrustStoreBackend");
        synchronized (LOCK) {
            KeyStore live = liveTrustStore(service);
            if (live.containsAlias(alias)) {
                throw new IllegalArgumentException("TLS Manager already trusts a certificate named \""
                    + alias + "\"; choose another name.");
            }
            ByteArrayOutputStream current = new ByteArrayOutputStream();
            live.store(current, pw);
            KeyStore copy = KeyStore.getInstance(live.getType());
            copy.load(new ByteArrayInputStream(current.toByteArray()), pw);
            copy.setCertificateEntry(alias, cert);
            ByteArrayOutputStream updated = new ByteArrayOutputStream();
            copy.store(updated, pw);
            service.getClass().getMethod("storeExtraTrustStore", byte[].class, char[].class)
                .invoke(service, updated.toByteArray(), pw);
            if (!liveTrustStore(service).containsAlias(alias)) {
                throw new IllegalStateException("TLS Manager did not keep trusted \"" + alias + "\".");
            }
        }
    }

    /**
     * Adds a key pair under a new alias and saves the keystore through TLS Manager.
     * Refuses an alias already in use rather than replace a key pair a connector may
     * be presenting.
     */
    static void add(String alias, PrivateKey key, X509Certificate[] chain) throws Exception {
        Object service = certificateService();
        char[] pw = password(service);
        synchronized (LOCK) {
            KeyStore live = liveKeyStore(service);
            if (live.containsAlias(alias)) {
                throw new IllegalArgumentException("TLS Manager already has \"" + alias
                    + "\"; choose another name.");
            }
            // A copy of the live store, the new entry added, written whole: TLS Manager
            // loads those bytes into its live keystore and persists them.
            ByteArrayOutputStream current = new ByteArrayOutputStream();
            live.store(current, pw);
            KeyStore copy = KeyStore.getInstance(live.getType());
            copy.load(new ByteArrayInputStream(current.toByteArray()), pw);
            copy.setKeyEntry(alias, key, pw, chain);
            ByteArrayOutputStream updated = new ByteArrayOutputStream();
            copy.store(updated, pw);
            service.getClass().getMethod("storeExtraKeyStore", byte[].class, char[].class)
                .invoke(service, updated.toByteArray(), pw);
            if (!liveKeyStore(service).containsAlias(alias)) {
                throw new IllegalStateException("TLS Manager did not keep \"" + alias + "\".");
            }
        }
    }

    private static Entry read(KeyStore ks, String alias, char[] pw) {
        try {
            Key key = ks.getKey(alias, pw);
            Certificate[] certs = ks.getCertificateChain(alias);
            if (!(key instanceof PrivateKey) || certs == null || certs.length == 0) {
                return null;
            }
            X509Certificate[] chain = new X509Certificate[certs.length];
            for (int i = 0; i < certs.length; i++) {
                if (!(certs[i] instanceof X509Certificate)) {
                    return null;
                }
                chain[i] = (X509Certificate) certs[i];
            }
            return new Entry(alias, (PrivateKey) key, chain);
        } catch (Exception e) {
            return null;
        }
    }
}
