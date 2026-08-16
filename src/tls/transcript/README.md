# TLS Handshake Transcript Module

## Overview

The transcript is the running SHA-256 over every handshake message in
the exact order they are exchanged, each in its wire form:

```
transcript = SHA256( msg1 || msg2 || ... || msgN )
msg_i      = HandshakeType(1) || uint24 length(3) || body
```

RFC 8446 §4.4.1 — the handshake message headers are included; the
5-byte TLS record header is not. The state lives in the per-connection
global `tls_transcript_ctx` (`src/tls/data.S`, a `SHA256_CTX` laid out
by the `SHA256_CTX_*` offsets in `defs.S`). Like `tls_state` it is a
process-global: a connection handler is one process, so there is
exactly one handshake per process.

Built on the streaming `sha256_init` / `sha256_update` / `sha256_final`
from `src/crypto/sha256.S`; no libc or external crypto required.

## Module Structure

- **`init.S`** — `tls_transcript_init`
  - Start a fresh transcript (PLAN.MD §9.1): seed `tls_transcript_ctx`
    with the FIPS 180-4 IV and zero the counters
  - A tail call into `sha256_init` — no stack frame
  - Call once per handshake before the ClientHello arrives

- **`add.S`** — `tls_transcript_add`
  - Feed one complete handshake message: the type octet, the 3-byte
    big-endian length, then the body
  - Synthesises the 4-byte wire header so callers only need type + body
  - `len == 0` is valid (empty body); messages must be fed in exchange
    order — the transcript is order-sensitive by construction

- **`hash.S`** — `tls_transcript_hash`
  - Snapshot the current transcript hash into a 32-byte buffer (PLAN.MD
    §9.2) *without* disturbing the running transcript
  - Finalises a scratch copy of `tls_transcript_ctx`, so the TLS 1.3 key
    schedule can take the hash at several points — e.g.
    `hash(ClientHello)` for the handshake secret, then
    `hash(ClientHello || ServerHello)` for the traffic secrets (RFC
    8446 §7.1) — and keep feeding afterwards

## API Reference

### `tls_transcript_init`
```
Input:  none
Output: none (void)
```

### `tls_transcript_add`
```
Input:
  x0 — HandshakeType octet (e.g. TLS_HS_CLIENT_HELLO)
  x1 — pointer to the message body (ignored when len == 0)
  x2 — body length in bytes (0..0xFFFFFF)

Output: none (void) — the transcript is updated in place
```

### `tls_transcript_hash`
```
Input:
  x0 — pointer to a 32-byte digest output buffer

Output: none (void) — 32 digest bytes written to [x0]
```

## Build Integration

Each submodule is compiled as a separate ARM64 object file, following
the same convention as `src/tls/record/`. The top-level Makefile's
recursive wildcard picks up `transcript/*.S` automatically; the test
Makefile (`tests/unit/Makefile`) has an explicit pattern rule.

## Testing

See `tests/unit/test_tls_transcript/` — 39 tests split into `init.c`,
`add.c`, and `hash.c`, one self-contained binary per file.
