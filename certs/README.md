# certs/ — TLS 1.3 test certificates for sarm

Self-signed **ECDSA P-256 (secp256r1)** test certificates for exercising the
sarm TLS 1.3 server implementation against the cipher suite it supports,
`TLS_AES_128_GCM_SHA256`.

## Files

| File       | Contents                                                        |
|------------|-----------------------------------------------------------------|
| `key.pem`  | EC P-256 (secp256r1 / prime256v1) **private key** (chmod 600)   |
| `cert.pem` | Self-signed certificate (public), signed with ecdsa-with-SHA256 |
| `cert.der` | DER form of `cert.pem` (what the TLS 1.3 `Certificate` message carries) |
| `embed_cert.sh` | Generates `src/tls/cert_data.S` from `cert.der` and `key.pem` |

## Embedding into the server (PLAN.MD Phase 15)

PLAN.MD Phase 15 is explicit: **no general X.509 parser**. Instead
`cert.der` and the raw 32-byte private scalar from `key.pem` are
embedded as literal bytes into `src/tls/cert_data.S` (`tls_cert_der` /
`tls_priv_key`) by `./embed_cert.sh`, and `tls_certificate_write`
(`src/tls/handshake/certificate.S`) just copies `tls_cert_der` onto the
wire, unparsed. Run it after `./generate.sh` any time the certificate
or key changes:

```sh
./generate.sh -f     # regenerate key.pem / cert.pem / cert.der
./embed_cert.sh       # regenerate ../src/tls/cert_data.S
```

`src/tls/cert_data.S` is gitignored — like `key.pem`, it embeds private
key material (as literal `.byte` data instead of PEM), so it must be
regenerated locally rather than committed. `make` does not regenerate
it automatically; both scripts above are a required manual step before
the first build on a fresh checkout.

## Why ECDSA P-256?

sarm's TLS implementation (see `src/defs.S`) is locked to:

- cipher suite `TLS_AES_128_GCM_SHA256` (`0x1301`) — the only suite implemented
- signature scheme `ecdsa_secp256r1_sha256` (`0x0403`) — the only scheme the
  server's `CertificateVerify` uses and the client must advertise
- named group `secp256r1` (`0x0017`) for the ECDSA certificate chain
  (X25519 `0x001D` is used for the ECDHE key exchange)

So the certificate **must** be an ECDSA P-256 cert — an RSA cert would fail the
handshake, because the server cannot produce an `ecdsa_secp256r1_sha256`
`CertificateVerify` from an RSA key.

## How to generate

Requires OpenSSL 3.x (has `genpkey -algorithm EC` and `-addext`). On macOS:
`brew install openssl` if `/usr/bin/openssl` is LibreSSL.

Either run `./generate.sh` in this directory, or by hand:

```sh
# 1. EC P-256 private key (unencrypted — a test server must load it without a passphrase)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
chmod 600 key.pem

# 2. Self-signed certificate
openssl req -new -x509 -key key.pem -sha256 -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -out cert.pem

# 3. DER copy for embedding/parsing
openssl x509 -in cert.pem -outform der -out cert.der
```

## How to validate

### 1. Inspect the certificate

```sh
openssl x509 -in cert.pem -text -noout
```

Check: `Signature Algorithm: ecdsa-with-SHA256`, `Public-Key: (256 bit)`,
`ASN1 OID: prime256v1` / `NIST CURVE: P-256`, and the SANs
`DNS:localhost, IP:127.0.0.1, IP:::1`.

### 2. Confirm cert and key belong together

Both hashes must match:

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | shasum -a 256
openssl pkey -in key.pem -pubout -outform der | shasum -a 256
```

### 3. Live TLS 1.3 handshake with the exact cipher

```sh
openssl s_server -accept 8443 -cert cert.pem -key key.pem \
  -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -quiet &

openssl s_client -connect 127.0.0.1:8443 \
  -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 \
  -servername localhost -CAfile cert.pem
```

Expected client output: `Protocol: TLSv1.3`, `Cipher is TLS_AES_128_GCM_SHA256`,
`Verify return code: 0 (ok)`.

## Notes for later (TLS 1.3 testing with sarm)

- **Self-signed**: test clients must trust it explicitly — `curl --cacert certs/cert.pem`,
  `openssl s_client -CAfile certs/cert.pem`, or `-k` / `-no_verify` to skip
  verification. sarm (the server) never checks its own cert, so this is only
  a client-side concern.
- **`cert.der` is what goes on the wire**: the TLS 1.3 `Certificate` message
  carries the cert in DER. Parse/embed `cert.der`; keep `key.pem` for signing
  `CertificateVerify` (ecdsa_secp256r1_sha256 over P-256).
- **TLS 1.3 cipher suites don't select the key type** — but this server's only
  supported `CertificateVerify` scheme (`ecdsa_secp256r1_sha256`) does: ECDSA P-256.
- **Named-group check**: the client must offer `secp256r1` for the cert chain
  and `x25519` for ECDHE, matching `NAMED_GROUP_SECP256R1` / `NAMED_GROUP_X25519`
  in `src/defs.S`. OpenSSL's defaults already do this.
- **`s_server` gotcha**: run it with `-quiet` when backgrounding — interactive
  mode blocks on stdin and the handshake can stall.
- **Validity**: 10 years from generation (current pair: 2026-08-15 → 2036-08-12).
- **Hygiene**: `certs/` is *not* in `.gitignore`, and `key.pem` is a private key.
  If this repo is shared, add `certs/key.pem` to `.gitignore` or keep the certs
  out of version control. Regenerating is cheap (`./generate.sh`).
