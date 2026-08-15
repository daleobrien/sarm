# TLS Handshake Message Module (PLAN.MD Phase 12)

## Overview

The handshake module parses and validates TLS 1.3 handshake messages —
this phase covers the first one a server ever sees: the ClientHello
(RFC 8446 §4.1.2). This is where interoperability starts: a real TLS
1.3 client's offer is checked against everything this server actually
supports, with an RFC 8446 §6.2 alert for anything it doesn't.

## Module Structure

### `client_hello.S` — `tls_parse_client_hello`

Parses a ClientHello body (legacy_version through the end of
extensions — the handshake message *after* its 4-byte type+length
header) with the same strict, exact-fit bounds checking as
`src/tls/record/parse.S`: every variable-length field must fit inside
what came before it, and the extensions block must exactly fill the
remainder of the buffer.

On success, `client_random` and the client's X25519 public key (from
`key_share`) are copied into `tls_state`, and the negotiated ALPN
protocol (`"h2"`) is recorded there — Phase 14 (EncryptedExtensions)
echoes it back. `legacy_version`, the session ID and the compression
methods are validated then discarded: this server does no session
resumption and no compression.

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

## API Reference

### `tls_parse_client_hello`
```
Input:
  x0 = pointer to the ClientHello body (starts at legacy_version, i.e.
       past the 4-byte handshake header)
  x1 = body length

Output (carry clear — success):
  x0 = 0
  tls_client_random, tls_client_key_share, tls_alpn_len and tls_alpn
  are filled in (src/tls/data.S)

Output (carry set — failure):
  x0 = TLS_ALERT_DECODE_ERROR / _PROTOCOL_VERSION / _HANDSHAKE_FAILURE
       / _NO_APPLICATION_PROTOCOL / _UNRECOGNIZED_NAME
```

## Build Integration

Follows the same convention as `src/tls/record/` and
`src/tls/transcript/`: each submodule compiles to its own object file,
picked up automatically by the top-level Makefile's recursive wildcard
and by an explicit pattern rule in `tests/unit/Makefile`.

## Testing

See `tests/unit/test_tls_client_hello.c` — 104 tests covering:
- The real RFC 8448 §3 ClientHello wire trace (which lacks ALPN, so it
  doubles as a live `no_application_protocol` test case while pinning
  `client_random`/`key_share` extraction against known-good bytes)
- A synthetic-ClientHello builder exercising each requirement
  (§12.1-§12.5) in isolation — one extension removed or corrupted at a
  time
- Structural bounds checking: truncated buffers, an oversized session
  ID, a mismatched extensions length, a missing null compression
  method

## References

- RFC 8446 — TLS 1.3 (§4.1.2: ClientHello, §4.2: Extensions, §6.2:
  Alert descriptions)
- RFC 6066 — TLS Extensions: server_name (§3)
- RFC 8448 — Example Handshake and Traffic Keys for TLS 1.3 (§3: the
  ClientHello wire trace)
- PLAN.MD — Phase 12: ClientHello Parser
