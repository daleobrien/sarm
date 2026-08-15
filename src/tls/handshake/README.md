# TLS Handshake Message Module (PLAN.MD Phases 12-13)

## Overview

The handshake module parses and generates TLS 1.3 handshake messages.
Phase 12 covers the first message a server ever sees: the ClientHello
(RFC 8446 §4.1.2) — this is where interoperability starts, checking a
real client's offer against everything this server supports. Phase 13
covers the reply: the ServerHello (RFC 8446 §4.1.3), which fixes the
negotiated parameters and carries the server's half of the X25519 key
exchange.

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

## References

- RFC 8446 — TLS 1.3 (§4.1.2: ClientHello, §4.1.3: ServerHello, §4.2:
  Extensions, §4.2.8: key_share, §6.2: Alert descriptions)
- RFC 7748 — Elliptic Curves for Security (§5: the X25519 base point)
- RFC 6066 — TLS Extensions: server_name (§3)
- RFC 8448 — Example Handshake and Traffic Keys for TLS 1.3 (§3: the
  ClientHello wire trace)
- PLAN.MD — Phase 12: ClientHello Parser, Phase 13: ServerHello
