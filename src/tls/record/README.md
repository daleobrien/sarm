# TLS Record Layer Module

## Overview

The TLS record layer (RFC 8446 §5) wraps every TLS 1.3 message in a record envelope with a 5-byte header followed by the message content. Before handshake keys are established, records are transmitted in plaintext. After key setup, each record is sealed with AES-128-GCM.

## Module Structure

This module has been split into focused submodules for clarity and maintainability:

### Submodules

- **`parse.S`** — `tls_record_parse`
  - Parse and validate a TLS record from a buffer
  - Checks content type (20-23), version (0x0301 or 0x0303), and fragment length bounds
  - Returns content type, fragment pointer, and record length

- **`write.S`** — `tls_record_write`
  - Generate a plaintext TLS record (RFC 8446 §5.1)
  - Constructs 5-byte header: type || version (0x0303) || length
  - Copies fragment to output buffer
  - Rejects zero-length handshake fragments (RFC 8446 §5.1)

- **`nonce.S`** — `tls_record_nonce`
  - Build per-record nonce for AEAD (RFC 8446 §5.3)
  - Computes: nonce = IV XOR (0x00000000 || sequence_number)
  - Exposed for testing and handshake verification

- **`encrypt.S`** — `tls_record_encrypt`
  - Seal plaintext fragment into TLSCiphertext (RFC 8446 §5.2)
  - Outer header: type 23, version 0x0303, length = plaintext_len + 1 + 16
  - AEAD plaintext: fragment || inner_content_type || padding
  - Additional data: 5-byte record header (authenticated)
  - Rejects zero-length handshake/alert content

- **`decrypt.S`** — `tls_record_decrypt`
  - Open TLSCiphertext record (RFC 8446 §5.2)
  - Verifies AEAD tag with record header as additional data
  - Finds inner content type by scanning from end for first non-zero octet
  - Removes padding (everything after the inner type byte)
  - Validates inner type in range 20-23

- **`read_record.S`** — `tls_read_record` (PLAN.MD Phase 20)
  - The network-level counterpart to `tls_record_parse`: reads one
    complete record straight off a file descriptor (header, then
    exactly `fragment_length` more bytes, via `raw_read_exact` —
    deliberately not `transport_read`, to avoid recursing back into
    its own `TRANSPORT_TLS` branch) and hands the assembled buffer to
    `tls_record_parse` for validation
  - Used by `tls_server_handshake` (`src/tls/server/`) to read the
    ClientHello and the client's Finished, and by `transport_read`'s
    own `TRANSPORT_TLS` branch to pull each application_data record
    off the wire post-handshake

- **`next_client_seq.S`** / **`next_server_seq.S`** — `tls_record_next_client_seq`, `tls_record_next_server_seq`
  - Manage per-connection, per-direction sequence counters
  - Return current counter, then increment exactly once per call
  - Reset to zero at connection start and on key change (key schedule responsibility — see `tls_derive_application_secrets`, PLAN.MD Phase 19)
  - Sequence stored in `src/tls/data.S` as `tls_client_seq` / `tls_server_seq`

- **`application_write.S`** — `tls_app_data_write` (PLAN.MD Phase 19)
  - Seal one outgoing application_data record under the server's
    application traffic key/IV (`tls_derive_application_secrets`,
    `src/tls/handshake/application_secrets.S`)
  - A thin, `tls_state`-aware specialization of `tls_record_encrypt`:
    pulls `TLS_SERVER_APP_KEY`/`TLS_SERVER_APP_IV` and the next
    sequence number (`tls_record_next_server_seq`) so the caller only
    hands over plaintext and a destination buffer
  - Mechanical composition of two already-verified primitives — no
    algorithmic content of its own

- **`application_read.S`** — `tls_app_data_read` (PLAN.MD Phase 19)
  - Open one incoming TLSCiphertext record under the client's
    application traffic key/IV, mirroring `tls_app_data_write` for the
    read direction
  - A thin, `tls_state`-aware specialization of `tls_record_decrypt`:
    pulls `TLS_CLIENT_APP_KEY`/`TLS_CLIENT_APP_IV` and the next
    sequence number (`tls_record_next_client_seq`)

### Constants

**`_constants.S`** — Extracted constants for safe inclusion
- Defines `.equ` values for all TLS record layer constants
- Used by submodules to avoid macro redefinition when compiled separately
- Mirrors definitions from `src/defs.S`

### Common Header

**`common.S`** — Shared documentation
- Contains the full RFC 8446 and PLAN.MD context for the record layer
- Included by submodules for reference (documentation only)

## API Reference

All functions follow standard ARM64 ABI unless noted. Errors are signaled with the carry flag set and an error code in `x0`.

### `tls_record_parse`
```
Input:
  x0 = buffer pointer
  x1 = buffer length

Output (carry clear — success):
  x0 = content type (20-23)
  x1 = fragment pointer
  x2 = fragment length
  x3 = total record length (header + fragment)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_SHORT / _TYPE / _VERSION / _LENGTH / _BOUNDS
```

### `tls_record_write`
```
Input:
  x0 = content type (20-23)
  x1 = fragment pointer (ignored if frag_len == 0)
  x2 = fragment length (0 to TLS_MAX_PLAINTEXT = 16384)
  x3 = output buffer pointer

Output (carry clear — success):
  x0 = total record length (5 + fragment_length)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
```

### `tls_record_nonce`
```
Input:
  x0 = IV pointer (12 bytes)
  x1 = record sequence number (64-bit)
  x2 = nonce output buffer (12 bytes)

Output:
  (void) — 12-byte nonce written to [x2]
```

### `tls_record_encrypt`
```
Input:
  x0 = inner content type (20-23)
  x1 = plaintext fragment pointer (ignored if pt_len == 0)
  x2 = plaintext length (0 to TLS_MAX_PLAINTEXT)
  x3 = AES-128 key pointer (16 bytes)
  x4 = write IV pointer (12 bytes)
  x5 = record sequence number (64-bit)
  x6 = output buffer pointer

Output (carry clear — success):
  x0 = total record length (5 + plaintext_length + 1 + 16)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
```

### `tls_record_decrypt`
```
Input:
  x0 = record buffer pointer (header + ciphertext + tag)
  x1 = buffer length
  x2 = AES-128 key pointer (16 bytes)
  x3 = read IV pointer (12 bytes)
  x4 = record sequence number (64-bit)
  x5 = plaintext output buffer pointer

Output (carry clear — success):
  x0 = content length (bytes before inner type, padding removed)
  x1 = inner content type (20-23)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_SHORT / _LENGTH / _BOUNDS / _MAC / _INNER
```

### `tls_record_next_client_seq`, `tls_record_next_server_seq`
```
Input:
  (none)

Output:
  x0 = current sequence number (counter incremented by 1)
```

### `tls_read_record`
```
Input:
  x0 = file descriptor
  x1 = pointer to the destination buffer
  x2 = destination buffer capacity in bytes (>= TLS_RECORD_HEADER_LEN)

Output (carry clear — success):
  x0 = content type (20..23)
  x1 = pointer to the fragment (buf + TLS_RECORD_HEADER_LEN)
  x2 = fragment length in bytes
  x3 = total record length (header + fragment)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_SHORT (I/O error or EOF) / _LENGTH (record too
       large for the buffer) / _TYPE / _VERSION / _BOUNDS (from
       tls_record_parse)
```

### `tls_app_data_write`
```
Input:
  x0 = plaintext fragment pointer (ignored when len == 0)
  x1 = fragment length in bytes (0..TLS_MAX_PLAINTEXT)
  x2 = pointer to the output buffer (>= 5 + len + 17 bytes)

Output (carry clear — success):
  x0 = total record length (5 + len + 17)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY (propagated from
       tls_record_encrypt)

Reads TLS_SERVER_APP_KEY / TLS_SERVER_APP_IV from tls_state and
consumes the next server sequence number (tls_record_next_server_seq).
```

### `tls_app_data_read`
```
Input:
  x0 = pointer to the record buffer (header + ciphertext + tag)
  x1 = number of bytes available in the buffer
  x2 = pointer to the plaintext output buffer (>= len - 16 bytes)

Output (carry clear — success):
  x0 = content length in bytes (padding and the type byte removed)
  x1 = inner content type (20..23)

Output (carry set — failure):
  x0 = TLS_RECORD_ERR_SHORT / _LENGTH / _BOUNDS / _MAC / _INNER
       (propagated from tls_record_decrypt)

Reads TLS_CLIENT_APP_KEY / TLS_CLIENT_APP_IV from tls_state and
consumes the next client sequence number (tls_record_next_client_seq).
```

## Build Integration

- Each submodule is compiled as a separate ARM64 object file
- The Makefile's `rwildcard` pattern finds all `.S` files recursively
- Test build (`tests/unit/Makefile`) includes `tls/record/*.S` files via explicit pattern rules
- No external compilation flags or special handling required

## Testing

All 773 record-layer tests pass:
- RFC 8448 §3 record parsing (ClientHello, ServerHello, zero-length application_data)
- Malformed record rejection with correct error codes
- Plaintext record generation (byte-for-byte RFC 8448 vectors)
- Nonce construction verification
- Encrypt/decrypt roundtrips and RFC vectors
- Padding stripping (RFC 8446 §5.4)
- Sequence counter increment and independence
- Error cases: tag tamper, key mismatch, truncation, all-zero plaintext, invalid inner types

`tests/unit/test_tls_application/` (PLAN.MD Phase 19) covers
`tls_app_data_write`/`tls_app_data_read` alongside
`tls_derive_application_secrets`:
- `write.c` / `read.c` — RFC 8448 §3's actual server/client
  application_data records (`RFC_SAP_KEY`/`RFC_CAP_KEY`) as the
  primary cross-check, plus Python-generated vectors (via
  `cryptography`'s `AESGCM`) covering multiple lengths including the
  zero- and one-byte edge cases, a `tls_server_seq`/`tls_client_seq`
  increment check per call, an oversized-plaintext rejection, and a
  tampered-tag MAC-failure rejection

`tests/unit/test_tls_record/read_record.c` (PLAN.MD Phase 20) covers
`tls_read_record` over a real `socketpair()`: a full record delivered
across two separate `write()` calls (forcing the underlying
`raw_read_exact` to loop across short reads), EOF before a complete
header, a record whose claimed length exceeds the destination buffer,
and an `application_data`-typed record round-tripping correctly.

`tls_server_handshake` (`src/tls/server/`, Phase 20) — the driver that
sequences this whole module against a live connection — is validated
by a real end-to-end interop test rather than a synthetic unit test:
a genuine TLS 1.3 client (Python's `ssl` module, and separately `curl`
built against LibreSSL) completing the full handshake and then
multiple HTTP/2 requests/responses over the resulting encrypted
connection, byte-for-byte matching the plaintext response. See
`src/tls/server/README.md`.

## References

- RFC 8446 — TLS 1.3 (§5: Record Protocol, §5.3: per-record nonce and
  sequence numbers, §7.1: key schedule)
- RFC 8448 — Example Handshake and Traffic Keys for TLS 1.3 (§3: Wire
  Formats, including the client/server application_data records)
- PLAN.MD — Phase 11: TLS Record Layer Implementation, Phase 19: TLS
  application data
