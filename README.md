# Certificate Generator

Generates key pairs with certificates for **mutual TLS**, signed by a CA key pair
held in [TLS Manager](https://github.com/NovaMap-Health/tls-manager-plugin), from
the Open Integration Engine web administrator.

```
./build.sh
cp dist/certgen-0.1.0.zip <engine repo>/extensions/
docker compose up -d --force-recreate engine
./scripts/oie-check-extensions.sh "Certificate Generator"
```

Then open **Certificate Generator** under Plugins in the web administrator.

## What it makes

Pick a **signing CA** -- one of TLS Manager's local key pairs; the first CA whose
name contains "CA" is selected for you -- and give a **subject**
(`CN=client1.example.org, O=hTrak, C=AU`; a bare name is taken as the CN). It
generates a new key pair and a certificate for it signed by the CA:

- **client and server authentication** (extendedKeyUsage serverAuth and
  clientAuth), so one certificate serves either end of an mTLS link;
  basicConstraints CA:false
- valid **25 years**, or until the CA expires if that is sooner -- a certificate
  cannot usefully outlive its issuer, so the end date is cut to the CA's and the
  page says so. Any other number of years can be given.
- an RSA 2048 key by default; RSA 3072/4096 and EC P-256/P-384 on request
- **subject alternative names** as given (`DNS:`, `IP:`, `email:`, `URI:`). Left
  empty, a CN that is a host name goes in as a DNS name, which TLS servers need.

The new key pair is **saved in TLS Manager** under the name you give (default:
the CN), so TLS connectors can present it, and offered for **download** as
PKCS#12 (password-protected; one is generated if you leave it empty) and as PEM
certificate, chain and private key. The private key is on the page only until
you leave it; afterwards it is in TLS Manager.

It refuses a signer that is not a CA (no basicConstraints CA:true, or a keyUsage
without keyCertSign), an expired CA, a malformed subject, and a name TLS Manager
already has.

## How it works

TLS Manager keeps its local key pairs in an "additional keystore" -- a PKCS#12 in
the engine's configuration table, or a file -- and holds it in memory. This
extension reads that keystore and adds to it **through TLS Manager's own
certificate service**, which reloads the live keystore and persists it in one
call, so a new key pair is usable at once without a restart. TLS Manager is
reached by reflection: it is a third-party extension, and this one must still
load without it (the page then says TLS Manager is missing).

Certificates are built and signed with BouncyCastle from the engine's own
server-lib. No JCA provider is registered, so the engine's crypto setup is left
as it was. Nothing is bundled.

## API

Under `/api/certgen`, XStream maps in and out like the engine's own API:

| | |
| --- | --- |
| `GET /authorities` | TLS Manager's key pairs (alias, subject, expiry, whether each is a usable CA) and the default |
| `POST /issue` | `caAlias`, `subject`, `alias`, `subjectAltNames`, `keyType`, `validityDays`, `pkcs12Password`, `save` -- returns the certificate details, PEM and base64 PKCS#12 |

Both sit behind the **Generate certificates** permission. Grant it as narrowly as
the permission to manage TLS Manager: it hands out keys the engine's partners
will trust.

## Build

`build.sh` compiles in a JDK container against the jars of the engine image
(`oie/engine:4.6.0` by default), runs a self-test of the issuing rules against
throwaway CAs -- including a full PKIX path validation of what it issues -- and
packages `dist/certgen-<version>.zip`. Tags `v*` publish the zip as a GitHub
release.
