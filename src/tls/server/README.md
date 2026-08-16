# TLS Server Handshake Driver (PLAN.MD Phase 20)

## Overview

Every other module under `src/tls/` implements one piece of the TLS
1.3 handshake or record layer, unit-tested in isolation against fixed
vectors — none of them do any socket I/O, and none of them know about
each other. This module is the one function that ties them together
against a real, live connection: `tls_server_handshake` reads the
ClientHello, sends the server's flight, verifies the client's
Finished, and leaves the connection ready for `src/transport/`'s
`TRANSPORT_TLS` mode to carry ordinary HTTP/2 traffic over it.

This is genuinely new content, not just glue: getting a from-scratch
TLS 1.3 handshake to interoperate with a real client surfaced three
bugs that no per-module unit test could have caught, because each one
only exists at the *sequencing* level:

1. **The outer record type of every ciphertext is `application_data`
   (23), never the inner message's real type.** RFC 8446 §5.2 is
   explicit about this — "the outer type of every ciphertext" — but
   it's easy to write `tls_read_record`'s caller as if a handshake
   message under handshake keys still shows up as record type
   `handshake` (22) on the wire. It doesn't; only *plaintext* handshake
   records (ClientHello, ServerHello) do. The client's Finished has to
   be read expecting type 23, then decrypted, and only *then* does the
   inner type (checked via `tls_record_decrypt`'s second return value)
   read `handshake`.
2. **Sequence numbers are shared state across key epochs, and RFC 8446
   §5.3 resets them "at the beginning of a connection and whenever the
   key changes."** `tls_client_seq`/`tls_server_seq` serve both the
   handshake epoch (EncryptedExtensions..Finished, and the client's own
   Finished) and the application epoch (everything after) — one
   physical counter, two logical epochs. Deriving the application
   traffic keys resets both counters for the *new* epoch, so it must
   happen strictly after the handshake epoch's own last use of them
   (reading the client's Finished), not before.
3. **The reset in (2) only covers the handshake→application
   transition within one connection — it says nothing about the
   *next* connection.** This server handles one connection at a time
   (PLAN.MD's connection-per-loop model, no fork), and
   `tls_client_seq`/`tls_server_seq` are single global counters. A
   second connection's handshake-epoch messages (its own
   EncryptedExtensions..Finished) must start those counters at 0 too,
   or they silently continue from wherever the *previous* connection's
   application traffic left them — a bug that is invisible on the
   first connection a freshly started process ever handles and fires
   on every connection after that.

All three were found and fixed by driving the real handshake against
independent TLS implementations (Python's `ssl` module and `curl`
built against LibreSSL) rather than trusting the code to be correct
because each underlying primitive was already unit-tested — the same
principle the `verified-asm-crypto` workflow applies to arithmetic, one
level up the stack.

## Module Structure

### `handshake.S` — `tls_server_handshake`

One function (see its own doc comment for the full step-by-step),
covering the entire server side of RFC 8446 §2's Figure 1 for a 1-RTT
handshake:

1. `tls_transcript_init`, and reset `tls_client_seq`/`tls_server_seq`
   to 0 (see bug #3 above)
2. Read + parse the ClientHello (`tls_read_record`,
   `tls_transcript_add`, `tls_parse_client_hello`)
3. Build and send the ServerHello, then run the key schedule for the
   handshake traffic keys (`tls_build_server_hello`,
   `tls_derive_handshake_secrets`)
4. Send EncryptedExtensions, Certificate, CertificateVerify, and
   Finished, each encrypted under the server handshake key via a local
   `tls_record_encrypt` + `transport_write` helper
5. Read and verify the client's Finished — tolerating one
   middlebox-compatibility `change_cipher_spec` record first (RFC 8446
   Appendix D.4) — using the persisted `tls_client_hs_traffic_secret`
   (Phase 20 added this field; Phase 10's key schedule originally
   treated it as transient scratch since nothing needed it again until
   now)
6. Only now derive the application traffic keys
   (`tls_derive_application_secrets`, see bug #2 above), mark
   `TLS_HS_CONNECTED`, flip `transport_mode` to `TRANSPORT_TLS`, and
   zero `transport_read`'s TLS-mode stage buffer (`tls_read_stage_len`/
   `tls_read_stage_pos`) in case a *previous* connection left unread
   plaintext staged there

No error alert is ever sent back to the client on failure — this
function reports carry-set to its caller, which closes the connection.
Structured alerts are PLAN.MD Phase 23's job (TLS negative tests);
Phase 20's job is the happy path that gets the existing HTTP/2 stack
running over real TLS bytes.

### Scratch buffers

`tls_hs_msg_buf` (2 KB) and `tls_hs_record_buf` (~16.4 KB), both in
`src/tls/data.S`, hold one plaintext handshake message body and one
wire record respectively — deliberately separate from `src/data.S`'s
`buf` (the HTTP request/response buffer), so the TLS module has no
dependency on the HTTP layer and every test binary that links any part
of it doesn't need to link `src/data.S` too.

## Integration

`src/sarm/main.S`'s accept loop peeks (`MSG_PEEK`) each new
connection's first byte: `0x16` (a TLS handshake record, RFC 8446
§5.1) runs `tls_server_handshake` and, on success, hands the connection
straight to `h2_connection_loop` — the existing HTTP/2 implementation,
completely unaware that TLS is involved, exactly matching PLAN.MD's
Phase 20 diagram (`TCP socket → TLS transport → existing H2`). Any
other first byte falls through to the existing plaintext `child` path,
unchanged. There is no HTTP/1-over-TLS support (see
`src/transport/transport_read.S`'s and `transport_write.S`'s doc
comments) — a deliberate scope line matching the diagram, which shows
only H2 behind the TLS transport.

`src/transport/transport_read.S` and `transport_write.S`'s
`TRANSPORT_TLS` branches (previously `ENOTSUP` stubs) now call
`tls_app_data_read`/`tls_app_data_write` (`src/tls/record/`,
PLAN.MD Phase 19), chunking/staging so every `transport_read`/
`transport_write` call still gets exactly the byte count it asked for
regardless of TLS record boundaries. Both branches are built on
`raw_read_exact`/`raw_write_all` (`src/transport/raw_read.S`,
`raw_write.S`) — the mode-independent socket I/O primitives extracted
from the previous `TRANSPORT_PLAIN` bodies, needed because
`tls_read_record` and the `TRANSPORT_TLS` branches themselves must
never call back into `transport_read`/`transport_write` (which would
just dispatch straight back and recurse).

## Testing

Validated end-to-end against two independent real TLS 1.3
implementations rather than a synthetic unit test — mocking a correct
ECDHE/HKDF-driven client well enough to prove anything would mean
half-reimplementing a TLS client in the test harness:

- Python's `ssl` module (`PROTOCOL_TLS_CLIENT`, ALPN `h2`): full
  handshake completes, `version() == "TLSv1.3"`,
  `cipher() == TLS_AES_128_GCM_SHA256`, `selected_alpn_protocol() ==
  "h2"`
- `curl --http2 -k https://127.0.0.1:PORT/` (LibreSSL): full handshake
  and multiple consecutive HTTP/2 requests each return `200` with the
  real embedded response body, byte-for-byte identical to the same
  request over plaintext HTTP/2

The record-layer and key-schedule pieces `tls_server_handshake`
sequences are each independently unit-tested already (Phases 10,
12-19); see `src/tls/handshake/README.md` and
`src/tls/record/README.md`.

## References

- RFC 8446 — TLS 1.3 (§2: Protocol Overview / Figure 1, §4.4.4:
  Finished, §5.2: outer record type is always `application_data` for
  ciphertext, §5.3: sequence number resets, Appendix D.4: middlebox
  compatibility mode)
- PLAN.MD — Phase 20: Connect TLS to existing HTTP/2
