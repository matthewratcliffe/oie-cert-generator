/*
 * Certificate Generator console UI.
 *
 * One page: pick a CA key pair from TLS Manager (one named "CA" is preselected),
 * give a subject, and generate a key pair with a certificate signed by it --
 * client and server authentication, valid 25 years or until the CA expires,
 * whichever is sooner. The result is saved as a TLS Manager key pair and offered
 * for download as PKCS#12 and PEM.
 *
 * The private key reaches this page once, in the response to the generate call,
 * and lives only in this component's state: it is never stored in the browser,
 * and navigating away drops it. Download it then, or export it from TLS Manager.
 *
 * Plain ES module JavaScript: no JSX, no imports, no build step. The console
 * dynamically import()s this file and passes its own `platform` into register().
 */

const API = '/api/certgen';
const DEFAULT_YEARS = 25;

/*
 * The engine serialises a Map through XStream, so "JSON" arrives shaped like
 * {"linked-hash-map":{"entry":[{"string":"ok","boolean":true}, ...]}} rather
 * than a plain object. Same decoder as the Key Store plugin.
 */
function decode(node) {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(decode);

    const keys = Object.keys(node);

    // A map: {"linked-hash-map": {...}} / {"map": {...}}
    const mapKey = keys.find(k => k === 'map' || k.endsWith('-map'));
    if (mapKey && keys.length === 1) {
        const inner = node[mapKey];
        if (inner === null) return {};
        let entries = inner.entry;
        if (entries == null) return {};
        if (!Array.isArray(entries)) entries = [entries];
        const out = {};
        for (const entry of entries) {
            const [k, v] = decodeEntry(entry);
            out[k] = v;
        }
        return out;
    }

    /*
     * A collection: {"list": {"string": [...]}} / {"list": null}.
     *
     * The name test is deliberately loose. An immutable list (List.of(), .toList())
     * serialises as java.util.ImmutableCollections$ListN wrapping a CollSer blob,
     * whose elements cannot be recovered at all -- the server side must never send
     * one. Recognising the shape anyway means the view gets an empty array instead
     * of an object, so a stray one degrades into "nothing to show" rather than
     * "(x || []).map is not a function".
     */
    const listKey = keys.find(k => k === 'list' || k === 'set'
        || /(^|[.$_-])(list|set|collection)/i.test(k));
    if (listKey && keys.length === 1) {
        const inner = node[listKey];
        if (inner === null) return [];
        const elemKey = Object.keys(inner).find(k => !k.startsWith('@'));
        if (elemKey === undefined) return [];
        const items = inner[elemKey];
        // A list of maps -- the CA list -- carries each element as {"entry": [...]}
        // under one "linked-hash-map" key, and a single one as an object, not an
        // array. Re-tag each element so decode() sees it as the map it is.
        const mapLike = elemKey === 'map' || elemKey.endsWith('-map');
        if (!mapLike && items !== null && typeof items === 'object' && !Array.isArray(items)) {
            return [];
        }
        return (Array.isArray(items) ? items : [items]).map(item => decode({ [elemKey]: item }));
    }

    const SCALARS = new Set(['string', 'boolean', 'int', 'long', 'double', 'float',
        'short', 'byte', 'char', 'big-decimal', 'big-int']);
    if (keys.length === 1 && SCALARS.has(keys[0])) {
        const v = node[keys[0]];
        return Array.isArray(v) ? v.map(decode) : decode(v);
    }

    const out = {};
    for (const k of keys) out[k] = decode(node[k]);
    return out;
}

function decodeEntry(entry) {
    if (entry === null || typeof entry !== 'object') return [String(entry), null];
    const props = Object.keys(entry);

    // Collapsed form: one property whose value is [key, value].
    if (props.length === 1 && Array.isArray(entry[props[0]])) {
        const arr = entry[props[0]];
        return [String(arr[0]), arr.length > 1 ? decode(arr[1]) : null];
    }
    const keyVal = entry[props[0]];
    const key = Array.isArray(keyVal) ? String(keyVal[0]) : String(keyVal);
    if (props.length < 2) return [key, null];
    const valueName = props[1];
    return [key, decode({ [valueName]: entry[valueName] })];
}

/*
 * The mirror of decode(): a Map parameter has to arrive XStream-shaped, so a
 * plain JSON object body is rejected outright -- plain JSON gives a 500, the XML
 * map gives a 200. The engine's own scripts in this repo talk XML to the API for
 * the same reason.
 */

/* The mirror of decode(): a Map parameter has to arrive XStream-shaped. */
function encodeMap(obj) {
    const esc = v => String(v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    const entries = Object.keys(obj)
        // An undefined value means "not supplied", which is different from empty:
        // the server leaves a field alone when the key is absent. That is what
        // makes a blank credential field mean "keep the stored one".
        .filter(k => obj[k] !== undefined && obj[k] !== null)
        .map(k => `<entry><string>${esc(k)}</string><string>${esc(obj[k])}</string></entry>`)
        .join('');
    return `<map>${entries}</map>`;
}

const ICON_CERT = 'M4 4h16v12H4zM8 20l4-2 4 2v-4M8 9h8M8 12h5';

/** Downloads bytes or text as a file, without a server round trip. */
function download(name, content, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function base64Bytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/** A file name from an alias: letters, digits, dot, dash, underscore. */
function fileBase(alias) {
    const base = String(alias || '').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
    return base || 'certificate';
}

function formatDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toISOString().slice(0, 10);
}

/** The CN of a subject typed as CN=x, O=y -- the default name in TLS Manager. */
function cnOf(subject) {
    const m = /(?:^|,)\s*CN\s*=\s*((?:\\,|[^,])*)/i.exec(subject || '');
    if (m) return m[1].replace(/\\,/g, ',').trim();
    return subject && !subject.includes('=') ? subject.trim() : '';
}

function keyLabel(k) {
    return String(k || '').replace('_P', ' P-').replace('_', ' ');
}

export function register(platform) {
    const React = platform.React;
    const h = React.createElement;

    async function call(method, path, body) {
        const headers = { Accept: 'application/json', 'X-Requested-With': 'oie-webadmin' };
        if (body !== undefined) headers['Content-Type'] = 'application/xml';
        const res = await fetch(API + path, {
            method,
            headers,
            credentials: 'same-origin',
            body: body === undefined ? undefined : encodeMap(body),
        });
        let payload = null;
        const text = await res.text();
        if (text) {
            try {
                payload = decode(JSON.parse(text));
            } catch (err) {
                payload = { error: text };
            }
        }
        if (!res.ok) {
            const error = new Error((payload && (payload.error || payload.message)) || `HTTP ${res.status}`);
            error.status = res.status;
            throw error;
        }
        return payload || {};
    }

    // ------------------------------------------------------------------
    // Presentation helpers -- the shell's own classes, as in Key Store.
    // ------------------------------------------------------------------
    const viewStyle = {
        display: 'block', overflowY: 'auto', height: '100%', boxSizing: 'border-box', padding: '1rem',
    };

    function Panel(title, children, key) {
        return h('div', { key, className: 'panel', style: { marginBottom: '11px' } }, [
            h('div', { key: 'h', className: 'panel-header' }, h('span', null, title)),
            h('div', { key: 'b', className: 'panel-body' }, children),
        ]);
    }

    function Field(label, control, hint, opts) {
        const o = opts || {};
        return h('div', {
            key: o.key || label,
            className: 'field',
            style: o.span ? { gridColumn: '1 / -1' } : undefined,
        }, [
            h('label', { key: 'l' }, label),
            control,
            hint ? h('div', { key: 'h', className: 'hint' }, hint) : null,
        ]);
    }

    function Button(label, onClick, opts) {
        const o = opts || {};
        return h('button', {
            key: o.key || label,
            type: 'button',
            className: 'btn' + (o.primary ? ' btn-primary' : ''),
            disabled: !!o.disabled,
            onClick,
            style: { marginRight: '6px', marginBottom: '6px' },
        }, label);
    }

    function Banner(kind, children, key) {
        const token = { error: '--err', warn: '--warn', ok: '--ok', info: '--accent' }[kind] || '--accent';
        return h('div', {
            key,
            className: 'hint',
            style: {
                background: `color-mix(in srgb, var(${token}) 14%, var(--bg1))`,
                border: `1px solid color-mix(in srgb, var(${token}) 55%, transparent)`,
                borderRadius: 'var(--radius)',
                color: 'var(--text)',
                fontSize: '11px',
                padding: '7px 11px',
                marginBottom: '9px',
                whiteSpace: 'pre-wrap',
            },
        }, children);
    }

    function Row(label, value, key) {
        return h('div', { key, style: { display: 'flex', gap: '9px', padding: '2px 0' } }, [
            h('span', { key: 'l', className: 'hint', style: { minWidth: '110px' } }, label),
            h('span', { key: 'v', className: 'mono', style: { wordBreak: 'break-all' } }, value),
        ]);
    }

    // ------------------------------------------------------------------
    // The page
    // ------------------------------------------------------------------
    function CertGenView() {
        const [authorities, setAuthorities] = React.useState(null);
        const [keyTypes, setKeyTypes] = React.useState(['RSA_2048']);
        const [loadError, setLoadError] = React.useState(null);
        const [caAlias, setCaAlias] = React.useState('');
        const [subject, setSubject] = React.useState('');
        const [alias, setAlias] = React.useState('');
        const [sans, setSans] = React.useState('');
        const [keyType, setKeyType] = React.useState('RSA_2048');
        const [years, setYears] = React.useState(String(DEFAULT_YEARS));
        const [password, setPassword] = React.useState('');
        const [busy, setBusy] = React.useState(false);
        const [error, setError] = React.useState(null);
        const [result, setResult] = React.useState(null);

        const load = React.useCallback(async () => {
            setLoadError(null);
            try {
                const r = await call('GET', '/authorities');
                if (r.ok === false) {
                    setLoadError(r.error || 'Could not read TLS Manager.');
                    setAuthorities([]);
                    return;
                }
                const list = Array.isArray(r.authorities)
                    ? r.authorities : (r.authorities ? [r.authorities] : []);
                setAuthorities(list);
                if (Array.isArray(r.keyTypes) && r.keyTypes.length) setKeyTypes(r.keyTypes);
                setCaAlias(current => current || r.defaultAlias || '');
            } catch (err) {
                setLoadError(err.message);
                setAuthorities([]);
            }
        }, []);
        React.useEffect(() => { load(); }, [load]);

        const ca = (authorities || []).find(a => a.alias === caAlias) || null;
        const yearsNum = Number(years);
        const yearsOk = Number.isFinite(yearsNum) && yearsNum > 0 && yearsNum <= 100;
        const wantedEnd = yearsOk ? new Date(Date.now() + yearsNum * 365.2425 * 86400000) : null;
        const capped = !!(ca && wantedEnd && new Date(ca.notAfter) < wantedEnd);
        const defaultName = cnOf(subject);

        async function generate() {
            setBusy(true);
            setError(null);
            setResult(null);
            try {
                const body = {
                    caAlias,
                    subject,
                    alias: alias.trim() || undefined,
                    subjectAltNames: sans,
                    keyType,
                    pkcs12Password: password || undefined,
                };
                // The server's default is 25 calendar years; send days only when changed.
                if (yearsNum !== DEFAULT_YEARS) {
                    body.validityDays = String(Math.round(yearsNum * 365.2425));
                }
                const r = await call('POST', '/issue', body);
                if (r.ok === false) {
                    setError(r.error || 'The certificate could not be generated.');
                } else {
                    setResult(r);
                    setPassword('');
                    setAlias('');
                }
            } catch (err) {
                setError(err.message);
            } finally {
                setBusy(false);
            }
        }

        const caOptions = (authorities || []).map(a => h('option', {
            key: a.alias,
            value: a.alias,
            disabled: !a.ca || a.expired,
        }, a.alias + (a.ca ? '' : ' (not a CA)') + (a.expired ? ' (expired)' : '')
            + ' -- ' + a.subject + ', to ' + formatDate(a.notAfter)));

        const canGenerate = !busy && !!caAlias && !!subject.trim() && yearsOk
            && !!ca && ca.ca && !ca.expired;

        const form = Panel('Generate a certificate', [
            loadError ? Banner('error', loadError, 'le') : null,
            authorities && authorities.length === 0 && !loadError
                ? Banner('warn', 'TLS Manager holds no key pairs. Add your CA there first, '
                    + 'then reload the CAs.', 'none')
                : null,
            h('div', { key: 'g', className: 'form-grid' }, [
                Field('Signing CA', h('select', {
                    value: caAlias,
                    disabled: !authorities || authorities.length === 0,
                    onChange: e => setCaAlias(e.target.value),
                }, [h('option', { key: '', value: '' },
                    authorities ? 'Choose a CA key pair' : 'Loading...')].concat(caOptions)),
                ca ? `${ca.subject}; ${ca.keyAlgorithm}; valid to ${formatDate(ca.notAfter)}`
                    : 'A TLS Manager key pair whose certificate is a CA.',
                { span: true, key: 'ca' }),
                Field('Subject', h('input', {
                    type: 'text', value: subject, spellCheck: false, autoComplete: 'off',
                    placeholder: 'CN=client1.example.org, O=hTrak, C=AU',
                    onChange: e => setSubject(e.target.value),
                }), 'A distinguished name. A bare name is taken as the CN.', { span: true, key: 'subject' }),
                Field('Subject alternative names', h('textarea', {
                    value: sans, rows: 2, spellCheck: false,
                    placeholder: 'DNS:client1.example.org, IP:10.0.0.5',
                    onChange: e => setSans(e.target.value),
                }), 'Optional, comma- or line-separated: DNS:, IP:, email:, URI:. Left empty, '
                    + 'a CN that is a host name goes in as DNS.', { span: true, key: 'sans' }),
                Field('Name in TLS Manager', h('input', {
                    type: 'text', value: alias, spellCheck: false, autoComplete: 'off',
                    placeholder: defaultName || 'from the CN',
                    onChange: e => setAlias(e.target.value),
                }), 'The new key pair\'s alias there; it must not be taken.', { key: 'alias' }),
                Field('Key', h('select', {
                    value: keyType,
                    onChange: e => setKeyType(e.target.value),
                }, keyTypes.map(k => h('option', { key: k, value: k }, keyLabel(k)))),
                'The new key pair\'s type.', { key: 'key' }),
                Field('Valid for (years)', h('input', {
                    type: 'number', min: 1, max: 100, value: years,
                    onChange: e => setYears(e.target.value),
                }), capped
                    ? `Cut to the CA's expiry, ${formatDate(ca.notAfter)}: a certificate cannot outlive its CA.`
                    : `Default ${DEFAULT_YEARS}, or until the CA expires if sooner.`, { key: 'years' }),
                Field('PKCS#12 password', h('input', {
                    type: 'password', value: password, autoComplete: 'new-password',
                    placeholder: 'leave empty to generate one',
                    onChange: e => setPassword(e.target.value),
                }), 'Protects the .p12 download only.', { key: 'pw' }),
            ]),
            error ? Banner('error', error, 'err') : null,
            h('div', { key: 'actions', style: { marginTop: '9px' } }, [
                Button(busy ? 'Generating...' : 'Generate', generate,
                    { primary: true, disabled: !canGenerate, key: 'go' }),
                Button('Reload CAs', load, { disabled: busy, key: 'reload' }),
            ]),
        ], 'form');

        let resultPanel = null;
        if (result) {
            const base = fileBase(result.alias);
            resultPanel = Panel('Generated: ' + result.alias, [
                result.saved
                    ? Banner('ok', `Saved in TLS Manager as "${result.alias}". The private key is on `
                        + 'this page only until you leave it: download what you need now.', 'saved')
                    : Banner('warn', 'Not saved in TLS Manager. The private key is on this page '
                        + 'only until you leave it: download it now.', 'notsaved'),
                result.cappedToCa
                    ? Banner('warn', `Valid only until the CA expires, ${formatDate(result.notAfter)}.`, 'cap')
                    : null,
                Row('Subject', result.subject, 's'),
                Row('Issuer', result.issuer, 'i'),
                Row('Serial', result.serial, 'n'),
                Row('Valid', formatDate(result.notBefore) + ' to ' + formatDate(result.notAfter), 'v'),
                Row('Key', keyLabel(result.keyType), 'k'),
                result.pkcs12PasswordGenerated ? Row('.p12 password', result.pkcs12Password, 'pw') : null,
                h('div', { key: 'dl', style: { marginTop: '11px' } }, [
                    Button('Download .p12', () => download(base + '.p12',
                        base64Bytes(result.pkcs12), 'application/x-pkcs12'), { primary: true, key: 'p12' }),
                    Button('Certificate .pem', () => download(base + '.crt.pem',
                        result.certificatePem, 'application/x-pem-file'), { key: 'crt' }),
                    Button('Chain .pem', () => download(base + '.chain.pem',
                        result.chainPem, 'application/x-pem-file'), { key: 'chain' }),
                    Button('Private key .pem', () => download(base + '.key.pem',
                        result.privateKeyPem, 'application/x-pem-file'), { key: 'pkey' }),
                ]),
            ], 'result');
        }

        return h('div', { className: 'view', style: viewStyle }, [form, resultPanel]);
    }

    const safely = (label, fn) => {
        try {
            fn();
        } catch (err) {
            console.warn('[certgen] could not register ' + label, err);
        }
    };

    safely('icon', () => platform.registerIcon('certgen', ICON_CERT));
    safely('certificate generator view', () => {
        platform.registerView('/certificate-generator', platform.reactView(CertGenView), {
            title: 'Certificate Generator',
        });
        platform.registerNavItem({
            id: 'certgen',
            label: 'Certificate Generator',
            icon: 'certgen',
            path: '/certificate-generator',
            section: 'Plugins',
            order: 76,
        });
    });
}
