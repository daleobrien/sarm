# TLS Handshake Message Module (PLAN.MD Phases 10, 12-15, 17-18)

## Overview

The handshake module parses and generates TLS 1.3 handshake messages.
Phase 12 covers the first message a server ever sees: the ClientHello
(RFC 8446 §4.1.2) — this is where interoperability starts, checking a
real client's offer against everything this server supports. Phase 13
covers the reply: the ServerHello (RFC 8446 §4.1.3), which fixes the
negotiated parameters and carries the server's half of the X25519 key
exchange. Phase 14 needs the handshake traffic keys before it can send
anything else, so this is also where the Phase 10 key schedule (skipped
until now — nothing needed it) actually gets implemented: it turns the
ServerHello's ECDHE shared secret into the keys that encrypt
EncryptedExtensions (RFC 8446 §4.3.1), the first message either side
sends under handshake traffic protection. Phase 15 sends the server's
authentication material — the Certificate message (RFC 8446 §4.4.2) —
built from an ECDSA P-256 certificate and private key embedded at build
time (see `certs/`), not parsed from X.509 at runtime. Phase 17 proves
the server actually holds that certificate's private key: the
CertificateVerify message (RFC 8446 §4.4.3) signs the running
handshake transcript with the embedded ECDSA P-256 private key
(Phase 16's `p256_ecdsa_sign_with_k`), so any client that later
validates the certificate chain can trust the rest of the handshake
came from its owner. Phase 18 closes out the handshake proper: the
Finished message (RFC 8446 §4.4.4) proves the server computed the
*same* key schedule and saw the *same* handshake transcript as the
client, using an HMAC-SHA256 MAC keyed off the server handshake
traffic secret (now persisted in `tls_state` for exactly this purpose)
rather than another signature.

## Module Structure

### `client_hello.S` — `tls_parse_client_hello`

Parses a ClientHello body (legacy_version through the end of
extensions — the handshake message *after* its 4-byte type+length
header) with the same strict, exact-fit bounds checking as
`src/tls/record/parse.S`: every variable-length field must fit inside
what came before it, and the extensions block must exactly fill the
remainder of the buffer.

On success, `client_random`, the `legacy_session_id` (echoed verbatim
by the ServerHello, §4.1.3) and the client's X25519 public key (from
`key_share`) are copied into `tls_state`, and the negotiated ALPN
protocol (`"h2"`) is recorded there — Phase 14 (EncryptedExtensions)
echoes it back. `legacy_version` and the compression methods are
validated then discarded: this server does no compression.

Five requirements are enforced, in order, each mapped to the alert a
real TLS stack expects:

| §    | Requirement                                        | Alert on failure         |
|------|-----------------------------------------------------|---------------------------|
| 12.1 | `supported_versions` offers TLS 1.3 (`0x0304`)      | `protocol_version`        |
| 12.2 | `cipher_suites` offers `TLS_AES_128_GCM_SHA256`      | `handshake_failure`       |
| 12.3 | `supported_groups` **and** `key_share` offer X25519  | `handshake_failure`       |
| 12.4 | the ALPN extension offers `"h2"`                     | `no_application_protocol` |
| 12.5 | `server_name`, if present, matches `tls_sni_hostname`| `unrecognized_name`       |

SNI (§12.5) supports exactly one configured hostname
(`tls_sni_hostname` in `src/tls/data.S`, currently `"localhost"`) —
there's no virtual-host infrastructure to pick a hostname from, so a
ClientHello with no `server_name` extension at all is accepted
unconditionally. Any structural malformation (a length that doesn't
fit, a truncated field, an extensions block that under/overruns the
buffer) is `decode_error`, checked before any requirement above.

Unrecognized extension types are skipped by length (RFC 8446 §4.2) —
only `supported_versions`, `supported_groups`, `key_share`, `alpn` and
`server_name` are acted on.

### `server_hello.S` — `tls_build_server_hello` / `tls_server_hello_write`

Generates the ServerHello (RFC 8446 §4.1.3) in reply to an already-
validated ClientHello. Split into two functions so the RNG-dependent
half stays out of the way of deterministic wire-format testing:

- `tls_server_hello_write` is a pure serializer: it reads
  `server_random`, the `legacy_session_id` echo and `server_key_share`
  straight out of `tls_state` and writes the handshake header + body.
  Everything else this server ever emits is fixed — `legacy_version =
  0x0303`, cipher `TLS_AES_128_GCM_SHA256`, `legacy_compression_method
  = 0`, and exactly two extensions: `supported_versions` (selecting TLS
  1.3) and `key_share` (one X25519 `KeyShareEntry`).
- `tls_build_server_hello` does the actual work PLAN.MD Phase 13 calls
  for: draws `server_random` and a fresh ephemeral X25519 key pair from
  `crypto_random_bytes` (`src/crypto/random.S`, `/dev/urandom`),
  computes the ECDHE `shared_secret` against the client's `key_share`,
  stores both into `tls_state`, and calls `tls_server_hello_write`. The
  ephemeral private scalar lives only on its own stack frame and is
  wiped before returning — nothing past this call needs it again, only
  the shared secret the key schedule (Phase 10) consumes.

### `key_schedule.S` — `tls_derive_handshake_secrets`

Runs the RFC 8446 §7.1 key schedule from the ECDHE shared secret
(`TLS_SHARED_SECRET`, filled by `tls_build_server_hello`) through the
handshake traffic keys and the Master Secret: Early Secret and both
"derived" collapses depend on nothing but fixed constants (an all-zero
IKM and `SHA-256("")`), so they're recomputed on every call rather than
cached; the Handshake Secret is extracted from the shared secret; the
client/server handshake traffic secrets — transient, kept only in a
reused stack scratch buffer — feed `HKDF-Expand-Label` for `"key"` and
`"iv"` into `tls_state`; and the Master Secret is stored for Phase 19's
application traffic secrets. The caller supplies the
ClientHello..ServerHello transcript hash (`tls_transcript_hash`); every
other input already lives in `tls_state` or is a compile-time constant.

### `encrypted_extensions.S` — `tls_encrypted_extensions_write`

Serializes EncryptedExtensions (RFC 8446 §4.3.1): the 4-byte handshake
header followed by exactly one extension, ALPN, echoing back whatever
`tls_parse_client_hello` negotiated (`TLS_ALPN_LEN`/`TLS_ALPN` — always
`"h2"` when the ClientHello parser succeeded, since that's the only
protocol this server offers). A pure serializer like
`tls_server_hello_write` — no keys or randomness involved — so the
caller does the actual "send encrypted" part of Phase 14 by running
`tls_derive_handshake_secrets` first and then sealing this message with
`tls_record_encrypt` under the server's handshake traffic key.

### `certificate.S` — `tls_certificate_write`

Serializes the Certificate handshake message (RFC 8446 §4.4.2): the
4-byte handshake header, an empty `certificate_request_context` (this
server never replies to a CertificateRequest), and a
`certificate_list` of exactly one `CertificateEntry` — the DER
certificate embedded at build time, with no per-entry extensions.
PLAN.MD Phase 15 is explicit that this should **not** be a general
X.509 parser: the certificate and its ECDSA P-256 private key are
generated once (`certs/generate.sh`) and embedded into
`src/tls/cert_data.S` as literal `.byte` data by `certs/embed_cert.sh`
— `tls_certificate_write` just copies `tls_cert_der` onto the wire
byte-for-byte, and `tls_priv_key` (the raw 32-byte private scalar) sits
alongside it, unused until Phase 16/17 sign CertificateVerify with it.
A pure serializer like `tls_encrypted_extensions_write` — no key
material or randomness involved in producing *this* message — so the
caller sends it the same way: `tls_derive_handshake_secrets` then
`tls_record_encrypt` under the server's handshake traffic key.

`.byte` data instead of `.incbin` is a deliberate choice: `cert_data.S`
is assembled from two different working directories (the top-level
Makefile from the repo root, `tests/unit/Makefile` from `tests/unit/`),
and `.incbin`'s path is resolved relative to the assembler's cwd, so no
single relative path could satisfy both. Literal bytes have no such
problem — see `src/h2_huffman_table.S` for the same pattern used
elsewhere in this codebase.

### `certificate_verify/` — `tls_certificate_verify_write`

Generates the CertificateVerify handshake message (RFC 8446 §4.4.3),
split into three files (one function each, matching `server_hello/`):

- **`content_hash.S`** — `tls_certificate_verify_content_hash`: builds
  the exact "Content" RFC 8446 §4.4.3 specifies —
  `64*0x20 || "TLS 1.3, server CertificateVerify" || 0x00 ||
  transcript_hash` (130 bytes total) — and SHA-256s it. The 98-byte
  fixed prefix is never actually concatenated into one buffer; it's
  fed to the streaming SHA-256 API as a separate `sha256_update` from
  the transcript hash. Pure and deterministic — no key material or
  randomness — so it's tested directly against a from-scratch Python
  transliteration of the RFC's Content construction.
- **`sign_with_k.S`** — `tls_certificate_verify_sign_with_k`: signs
  that digest with the server's embedded private key (`tls_priv_key`,
  `src/tls/cert_data.S`) via `p256_ecdsa_sign_with_k` (Phase 16.5).
  Like `p256_ecdsa_sign_with_k` itself, the nonce `k` is a caller-
  supplied argument rather than drawn here, keeping this function
  deterministic and testable against fixed vectors — the RNG-dependent
  half lives one layer up, in `write.S`.
- **`write.S`** — `tls_certificate_verify_write`: draws a fresh random
  nonce (`crypto_random_bytes`, retrying up to 4 times on the
  ~2^-256-probability `r == 0`/`s == 0` failure per FIPS 186-4), calls
  `sign_with_k`, DER-encodes the resulting `(r,s)` with
  `p256_ecdsa_der_sig_encode` (`src/crypto/p256_ecdsa/der_encode.S` —
  a new leaf function alongside Phase 16's `sign`/`verify`, since
  DER — unlike the raw fixed-width `(r,s)` those functions use — is
  what actually goes on the wire), and serializes the 4-byte handshake
  header, the fixed `signature_algorithm` (`ecdsa_secp256r1_sha256`,
  `0x0403` — the only scheme this server supports, `SIG_ECDSA_SECP256R1_SHA256`
  in `defs.S`) and the length-prefixed signature. The nonce and the raw
  `(r,s)` are wiped from the stack before returning, the same
  discipline as the ephemeral X25519 scalar in `tls_build_server_hello`.
  Like `tls_build_server_hello`, the caller sends the result the usual
  way: `tls_record_encrypt` under the server's handshake traffic key,
  after feeding it to `tls_transcript_add` for Phase 18's Finished.

### `finished/` — `tls_finished_write`

Generates the server's Finished handshake message (RFC 8446 §4.4.4),
split into three files (one function each, the same convention as
`certificate_verify/`):

- **`finished_key.S`** — `tls_finished_key`: derives
  `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", 32)`. A
  thin wrapper over the already-verified `hkdf_expand_label` (Phase
  10) — BaseKey is passed in rather than hardcoded, since the
  derivation itself doesn't care which handshake traffic secret it's
  keying off (only `write.S` below pins it to the server's).
- **`verify_data.S`** — `tls_finished_verify_data`: computes
  `verify_data = HMAC(finished_key, transcript_hash)`, wrapping
  `hmac_sha256` (`src/crypto/hmac.S`, PLAN.MD §3.3) the same way
  `finished_key.S` wraps `hkdf_expand_label`. Unlike Phase 17's
  content hash, the transcript hash here is passed through unchanged
  — RFC 8446 §4.4.4 hashes the running transcript directly, with no
  extra framing.
- **`write.S`** — `tls_finished_write`: reads the server's
  `TLS_SERVER_HS_TRAFFIC_SECRET` (now persisted in `tls_state`
  specifically for this — Phase 10's key schedule previously treated
  it as transient scratch, since nothing needed it again until now),
  derives `finished_key` and `verify_data`, and serializes the 4-byte
  handshake header (type 20, fixed length 32) followed directly by
  `verify_data`. Unlike CertificateVerify, Finished has no randomness
  and no failure mode — HMAC-SHA256 always succeeds — so this is a
  plain serializer, the same shape as `tls_encrypted_extensions_write`.
  The caller sends the result the usual way: `tls_record_encrypt`
  under the server's handshake traffic key, after which the connection
  moves to the application traffic keys derived from
  `tls_master_secret` (Phase 19).

## API Reference

### `tls_parse_client_hello`
```
Input:
  x0 = pointer to the ClientHello body (starts at legacy_version, i.e.
       past the 4-byte handshake header)
  x1 = body length

Output (carry clear — success):
  x0 = 0
  tls_client_random, tls_session_id_len, tls_session_id,
  tls_client_key_share, tls_alpn_len and tls_alpn are filled in
  (src/tls/data.S)

Output (carry set — failure):
  x0 = TLS_ALERT_DECODE_ERROR / _PROTOCOL_VERSION / _HANDSHAKE_FAILURE
       / _NO_APPLICATION_PROTOCOL / _UNRECOGNIZED_NAME
```

### `tls_build_server_hello`
```
Input:
  x0 = pointer to the output buffer (>= 122 bytes: 4-byte header + up
       to 86 + 32 body)

Output (carry clear — success):
  x0 = total message length. tls_server_random, tls_server_key_share
       and tls_shared_secret are filled in (src/tls/data.S)

Output (carry set — failure):
  x0 = TLS_ALERT_INTERNAL_ERROR (crypto_random_bytes failed)
```

### `tls_server_hello_write`
```
Input:
  x0 = pointer to the output buffer

Output:
  x0 = total message length (no failure mode — pure serialization of
       whatever tls_state currently holds)
```

### `tls_derive_handshake_secrets`
```
Input:
  x0 = pointer to the 32-byte ClientHello..ServerHello transcript hash

Output:
  none (void, no failure mode). tls_handshake_secret, tls_client_hs_key,
  tls_client_hs_iv, tls_server_hs_key, tls_server_hs_iv and
  tls_master_secret are filled in (src/tls/data.S)
```

### `tls_encrypted_extensions_write`
```
Input:
  x0 = pointer to the output buffer (>= 45 bytes)

Output:
  x0 = total message length (no failure mode — pure serialization of
       whatever tls_state currently holds)
```

### `tls_certificate_write`
```
Input:
  x0 = pointer to the output buffer (>= 13 + the embedded certificate
       length)

Output:
  x0 = total message length (no failure mode — pure serialization of
       the certificate embedded at build time, tls_cert_der in
       src/tls/cert_data.S)
```

### `tls_certificate_verify_content_hash`
```
Input:
  x0 = pointer to a 32-byte digest output buffer
  x1 = pointer to the 32-byte transcript hash (tls_transcript_hash)

Output:
  none (void) — 32 digest bytes written to [x0]
```

### `tls_certificate_verify_sign_with_k`
```
Input:
  x0 = sig_r out (32 bytes), x1 = sig_s out (32 bytes)
  x2 = pointer to the 32-byte transcript hash
  x3 = k, the nonce (32 bytes)

Output:
  x0 = 0 on success, 1 on failure (r == 0 or s == 0 — see
       p256_ecdsa_sign_with_k)
```

### `tls_certificate_verify_write`
```
Input:
  x0 = pointer to the output buffer (>= 80 bytes)
  x1 = pointer to the 32-byte transcript hash

Output (carry clear — success):
  x0 = total message length

Output (carry set — failure):
  x0 = TLS_ALERT_INTERNAL_ERROR (crypto_random_bytes failed, or every
       retry produced r == 0 / s == 0)
```

### `tls_finished_key`
```
Input:
  x0 = pointer to the 32-byte BaseKey (a handshake traffic secret)
  x1 = pointer to the 32-byte output buffer

Output:
  none (void) — 32 key bytes written to [x1]
```

### `tls_finished_verify_data`
```
Input:
  x0 = pointer to the 32-byte finished_key (from tls_finished_key)
  x1 = pointer to the 32-byte transcript hash
  x2 = pointer to the 32-byte output buffer

Output:
  none (void) — 32 verify_data bytes written to [x2]
```

### `tls_finished_write`
```
Input:
  x0 = pointer to the output buffer (>= 36 bytes)
  x1 = pointer to the 32-byte transcript hash

Output:
  x0 = total message length (36) — no failure mode, HMAC-SHA256
       never fails. Reads its BaseKey from
       tls_state's TLS_SERVER_HS_TRAFFIC_SECRET field
       (tls_server_hs_traffic_secret, src/tls/data.S)
```

## Build Integration

Follows the same convention as `src/tls/record/` and
`src/tls/transcript/`: each submodule compiles to its own object file,
picked up automatically by the top-level Makefile's recursive wildcard
and by an explicit pattern rule in `tests/unit/Makefile`.

## Testing

- `tests/unit/test_tls_client_hello.c` — 106 tests covering:
  - The real RFC 8448 §3 ClientHello wire trace (which lacks ALPN, so
    it doubles as a live `no_application_protocol` test case while
    pinning `client_random`/`key_share` extraction against known-good
    bytes)
  - A synthetic-ClientHello builder exercising each requirement
    (§12.1-§12.5) in isolation — one extension removed or corrupted at
    a time
  - Structural bounds checking: truncated buffers, an oversized
    session ID, a mismatched extensions length, a missing null
    compression method
- `tests/unit/test_tls_server_hello.c` — 57 tests covering:
  - `tls_server_hello_write` byte-for-byte, with an empty and a full
    32-byte session ID echo
  - `tls_build_server_hello` end-to-end: the returned shared secret is
    checked against an independently computed `X25519(client scalar,
    server's public key)` — a real ECDHE cross-check rather than a
    fixed vector
  - Two consecutive calls draw different `server_random` /
    `server_key_share` values (the RNG is actually being used)
- `tests/unit/test_tls_key_schedule.c` — 11 tests covering:
  - `tls_derive_handshake_secrets` against the full RFC 8448 §3 trace:
    the ECDHE shared secret and the ClientHello..ServerHello transcript
    hash go in, `tls_handshake_secret` / `tls_server_hs_key` /
    `tls_server_hs_iv` / `tls_master_secret` are checked against the
    RFC's published values, and `tls_client_hs_key`/`tls_client_hs_iv`
    are cross-checked by expanding the RFC's published
    client_handshake_traffic_secret independently
  - Determinism (the same inputs reproduce the same secrets) and
    transcript-dependence (a different transcript hash changes the
    traffic keys but not the shared-secret-derived handshake secret)
- `tests/unit/test_tls_encrypted_extensions.c` — 28 tests covering:
  - `tls_encrypted_extensions_write` byte-for-byte, for the real `"h2"`
    ALPN echo and the degenerate empty-name case
  - A full seal/open round trip through `tls_record_encrypt` /
    `tls_record_decrypt` under the RFC 8448 server handshake traffic
    key/IV: the message and its ALPN survive the wire, and a tampered
    key is rejected
- `tests/unit/test_tls_certificate.c` — 11 tests covering:
  - `tls_certificate_write` byte-for-byte against `certs/cert.der` read
    straight off disk (not a hardcoded vector — the cert can be
    regenerated any time via `certs/generate.sh` + `certs/embed_cert.sh`
    without breaking this test)
  - Determinism (the same build-time-embedded certificate reproduces
    identical output across calls)
- `tests/unit/test_p256_ecdsa/der_encode.c` — 36 tests: `p256_ecdsa_der_sig_encode`
  against DER encodings from Python's `cryptography` library
  (`encode_dss_signature`), covering small values, values needing a
  0x00 pad byte, values with several leading zero bytes to strip, and
  random P-256 scalars
- `tests/unit/test_tls_certificate_verify/` — one suite per
  `certificate_verify/*.S` module (PLAN.MD Phase 17):
  - `content_hash.c` — 9 tests: `tls_certificate_verify_content_hash`
    against a from-scratch Python transliteration of RFC 8446 §4.4.3's
    Content construction, plus determinism
  - `sign_with_k.c` — 40 tests: `tls_certificate_verify_sign_with_k`
    against Python-computed `(r,s)` vectors over the server's real
    embedded private key, each independently cross-checked by
    DER-encoding and verifying with `cryptography` against the
    server's real public key
  - `write.c` — 6 tests: `tls_certificate_verify_write`'s output
    parsed structurally (handshake header, `signature_algorithm`,
    length-prefixed DER signature) and checked with `p256_ecdsa_verify`
    against the server's real public key; two calls over the same
    transcript produce different signatures (the RNG is actually
    used); a signature is rejected against a transcript hash other
    than the one it was signed over
- `tests/unit/test_tls_finished/` — one suite per `finished/*.S`
  module (PLAN.MD Phase 18):
  - `finished_key.c` — 9 tests: `tls_finished_key` against vectors
    computed by manually assembling RFC 8446's HkdfLabel struct bytes
    and feeding them to `cryptography`'s `HKDFExpand` — cross-checking
    both the `"finished"` label and the empty-context path against a
    real, independently-implemented HKDF-Expand — plus determinism
  - `verify_data.c` — 9 tests: `tls_finished_verify_data` against
    vectors cross-checked with `cryptography`'s `HMAC`, plus
    transcript-hash dependence
  - `write.c` — 16 tests: `tls_finished_write`'s full 36-byte output
    (handshake header + verify_data) against a Python reference built
    from the same finished_key/verify_data functions validated above,
    with `tls_server_hs_traffic_secret` set directly per vector

## References

- RFC 8446 — TLS 1.3 (§4.1.2: ClientHello, §4.1.3: ServerHello, §4.3.1:
  EncryptedExtensions, §4.4.2: Certificate, §4.4.3: CertificateVerify,
  §4.4.4: Finished, §4.2: Extensions, §4.2.8: key_share, §4.2.3:
  signature_algorithms, §6.2: Alert descriptions, §7.1: key schedule)
- RFC 7748 — Elliptic Curves for Security (§5: the X25519 base point)
- RFC 6066 — TLS Extensions: server_name (§3)
- RFC 7301 — ALPN (§3.1: the ProtocolNameList wire format)
- RFC 8448 — Example Handshake and Traffic Keys for TLS 1.3 (§3: the
  ClientHello wire trace and the key-schedule values)
- RFC 5280 — X.509 (informational only: this server does not parse
  it — see `certs/README.md` for the certificate generated for Phase 15)
- PLAN.MD — Phase 10: TLS 1.3 key schedule, Phase 12: ClientHello
  Parser, Phase 13: ServerHello, Phase 14: EncryptedExtensions,
  Phase 15: Certificate handling, Phase 16: ECDSA P-256, Phase 17:
  CertificateVerify, Phase 18: Finished
