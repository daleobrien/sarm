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

- **`seq.S`** — `tls_record_next_client_seq`, `tls_record_next_server_seq`
  - Manage per-connection, per-direction sequence counters
  - Return current counter, then increment exactly once per call
  - Reset to zero at connection start and on key change (key schedule responsibility)
  - Sequence stored in `src/tls/data.S` as `tls_client_seq` / `tls_server_seq`

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

## References

- RFC 8446 — TLS 1.3 (§5: Record Protocol)
- RFC 8448 — Example Handshake and Traffic Keys for TLS 1.3 (§3: Wire Formats)
- PLAN.MD — Phase 11: TLS Record Layer Implementation
