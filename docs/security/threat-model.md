# sarm — security inventory and threat model

Step 1 of the programme in [docs/SECURITY.md](../SECURITY.md). This document
is an **inventory**, not a change: it records what the checked-out tree
actually does, so every later step (guard pages, boundary tests, differential
crypto tests, fuzzing, syscall allowlisting) has a written baseline to test
against. No source file is modified by this step.

Everything below was read out of the tree at commit `9ef5e46` and is cited by
path (and line where it helps). Where the inventory found something worth
acting on later, it is recorded in [§9](#9-observations-carried-forward) and
nowhere else — this document does not fix anything.

---

## 1. Adversary model

`sarm` is a single-binary static server: no libc, no heap, no dynamic linking,
and **no filesystem access at request time at all** — every asset is embedded
in `.data` by `embed_www.sh` and looked up by a linear table scan
(`src/file/lookup_embedded.S`).

Assumed attacker capabilities (the "can" list from `docs/SECURITY.md` §1):
open arbitrary numbers of TCP connections; send arbitrary, truncated,
fragmented or oversized bytes at any protocol stage; replay/reorder; force
races between concurrent connections; disconnect at any byte; send valid but
expensive cryptographic input; and inspect the distributed binary.

Assumed **not** available initially: arbitrary process-memory reads, arbitrary
code execution, debugger attach in production, post-deployment modification of
the executable.

The invariant the whole programme defends: *network input can move an attacker
from the first list to the second only through a memory-safety, length-
arithmetic, or protocol-state defect in this tree.*

One structural mitigation is worth stating up front, because it changes the
weight of several findings below: **one process serves one connection.**
Workers `accept` and `fork`; the child serves that connection to completion and
`_exit`s (`src/sarm/main.S:675-745`, `src/sarm/child_end.S`). Every global
listed in §5 is therefore per-connection by copy-on-write — a corrupted parsing
buffer, HPACK table or TLS key block cannot be observed by another connection,
and a crash costs one connection, not the server. Cross-connection state
disclosure is not in the current threat surface; cross-*request* state within
one kept-alive or multiplexed connection is (see §7.3).

---

## 2. Network entrypoints

Every byte an attacker controls enters through one of these, in this order.

| # | Entrypoint | Code | Notes |
|---|---|---|---|
| 1 | `accept` / `accept4` on the shared listening socket | `src/sarm/main.S:675-681` | `listen(128)` backlog; one `fork` per accepted connection |
| 2 | First `read()` — protocol detection | `src/sarm/main.S:780` | up to `BUF_SIZE` (16384) into `buf`; first byte `0x16` → TLS, else plaintext |
| 3 | TLS handshake reader | `src/tls/server/handshake.S` → `src/tls/record/read_record.S` | consumes the bytes from (2) first, then reads into `tls_hs_record_buf` |
| 4 | TLS record layer (post-handshake) | `src/tls/record/application_read.S`, `src/transport/transport_read.S:72` | ciphertext into `tls_read_raw_buf`, decrypted in place into `tls_read_stage_buf` |
| 5 | Plaintext HTTP/1 read loop | `src/sarm/child.S:132` | into `buf`, bounded by `BUF_SIZE - bytes_read` |
| 6 | HTTP/2 preface + frame loop | `src/h2/h2_verify_preface.S:41`, `src/h2/h2_connection_loop.S` via `h2_read_exact` | frame headers and payloads into `h2_frame_buf` / `h2_wait_buf` |
| 7 | HPACK decoder | `src/hpack/**` | operates on the HEADERS payload already in `h2_frame_buf` |

Three protocols share one port. Detection is a single byte test on the first
real `read` (the `MSG_PEEK` was removed in Plan.md Phase 2 Step 9), so the
bytes are handed to the chosen path rather than re-read:

* `0x16` → `tls_server_handshake` → **always** `h2_connection_loop`. There is
  no HTTP/1-over-TLS path.
* `"PRI "` → h2c (cleartext HTTP/2) via `h2_probe`.
* anything else → HTTP/1.1.

Attack surface reachable **before** any authentication or crypto: the TLS
record parser and the ClientHello parser (§3.1), the h2 frame header parser and
HPACK (§3.3), and the whole HTTP/1 parser (§3.4). Nothing in this server ever
requires the client to prove anything, so all of it is pre-auth by definition.

---

## 3. Externally controlled lengths

The core of the inventory. For each wire-derived length: where it is read, what
bound is enforced, and what buffer it can reach. This is the list §5 of
`docs/SECURITY.md` ("audit all length arithmetic") and Steps 6–8 (fuzzing) work
through.

### 3.1 TLS record and handshake

| Length | Source | Bound enforced | Destination |
|---|---|---|---|
| record fragment length (2 octets) | `src/tls/record/parse.S` | `<= 2^14` for types 20/21/22, `<= 2^14+256` for type 23; fragment must not run past the buffer end (`TLS_RECORD_ERR_LENGTH` / `_BOUNDS`) | `tls_hs_record_buf` (16448 B) / `tls_read_raw_buf` (16448 B) |
| handshake message length (3 octets) | `src/tls/server/handshake.S`, `TLS_HS_HEADER_LEN` | must fit inside the record fragment | `tls_hs_msg_buf` (2048 B) |
| `legacy_session_id` (1 octet) | `client_hello.S:110-118` | `<= 32` **and** must fit the body remainder | `tls_session_id` (32 B) |
| `cipher_suites` (2 octets) | `client_hello.S:131+` | `>= 2`, must fit the body remainder | not copied — scanned |
| `legacy_compression_methods` | `client_hello.S` | exactly one byte, value 0 (RFC 8446 §4.1.2) | not copied |
| extensions block length | `client_hello.S` | must **exactly** fill the remainder of the body | — |
| per-extension length | `client_hello.S` | must fit inside the extensions block | key_share → `tls_client_key_share` (32 B), ALPN → `tls_alpn` (16 B) |
| AEAD tag / inner-type scan | `src/tls/record/decrypt.S` | `TLS_RECORD_ERR_MAC` / `_INNER` / `_EMPTY` | in-place |

The ClientHello parser is a hand-written strict-bounds recursive-descent walk
with `x9` = cursor, `x10` = body end, `x13` = extensions end; every field
compares `cursor + field_len` against the applicable end before reading
(`b.hi .Lch_decode_error`). It is a leaf function — no calls, no stack frame.
It is also the single largest pre-auth parser in the tree and the highest-value
fuzz target (Step 7).

### 3.2 Record-layer staging

`transport_read` must return exactly what its caller asked for, but a decrypted
record rarely matches; plaintext is staged and doled out
(`tls_read_stage_len`/`_pos`, and the plaintext-mode equivalents
`plain_read_stage_*`). These three-way offset/length/position triples are
arithmetic on attacker-influenced record sizes and are a distinct class from
the parsers above: the bug shape here is a stale or unreset `pos > len`, not an
oversized field. `h2_connection_loop` resets the plain staging pair at the
start of every connection precisely because `no_fork` reuses the process.

### 3.3 HTTP/2 and HPACK

| Length | Source | Bound enforced | Destination |
|---|---|---|---|
| frame payload length (24-bit) | `h2_parse_frame_header.S` | `h2_validate_frame.S`: `<= 2^24-1` **and** `<= H2C_MAX_RX_FRAME_SIZE` (2^14 default) → `FRAME_SIZE_ERROR` | `h2_frame_buf` (9 + 16384) or `h2_wait_buf` (same) |
| stream id (31-bit) | `h2_parse_frame_header.S` | R bit masked; `h2_validate_stream_id.S`; table is 32 entries with CLOSED-slot recycling | `h2_streams` (32 × 32 B) |
| SETTINGS entries | `h2_handle_settings.S` | payload must be a multiple of 6 | `h2_conn` fields |
| WINDOW_UPDATE increment | `h2_handle_window_update.S` | window may not exceed `H2_MAX_FLOW_WINDOW` (2^31-1) → `FLOW_CONTROL_ERROR` | `H2C_WINDOW`, `H2S_WINDOW` |
| PADDED pad length | `h2_handle_headers.S`, `h2_handle_data.S` | pad must not exceed the remaining payload | — |
| HPACK integer (RFC 7541 §5.1) | `h2_hpack_decode_int.S` | bounded to 32 bits; overflow → `COMPRESSION_ERROR`, which also bounds the continuation loop | — |
| HPACK string length | `h2_hpack_decode_string.S` | Huffman output bounded by `H2_HPACK_STR_BUF_SIZE` (4096); bad padding / EOS / overflow → `COMPRESSION_ERROR` | `h2_hpack_str_buf` |
| HPACK table index | `h2_hpack_table_lookup.S` | beyond static(61)+dynamic space → `COMPRESSION_ERROR` | — |
| HPACK dynamic size update | `dynamic_table/resize.S` | above the advertised 4096 → `COMPRESSION_ERROR` | `h2_hpack_dyn_bytes` (4096) |
| decoded field count | `h2_hpack_decode_block.S` | `H2_HPACK_MAX_FIELDS` (32) | `h2_hpack_fields` (32 × 32 B) |
| `range` header value | `h2_build_request.S:209-216` | compared against `h2_range_buf_size` (64) before copy | `h2_range_buf` |

HPACK is the deepest attacker-controlled decode path in the tree (integer →
string → Huffman → table → field → request struct), and it is stateful across
the whole connection: RFC 9113 §4.3 makes one bad index a connection-level
failure. It is the second-highest-value fuzz target.

### 3.4 HTTP/1 and the shared request path

| Length | Source | Bound enforced | Destination |
|---|---|---|---|
| request bytes read | `src/sarm/child.S:127-137` | `BUF_SIZE` (16384); buffer full without `\r\n\r\n` → 431 | `buf` (16385 B, rounded) |
| header terminator scan | `src/parse/parse_header_end.S` | bounded by bytes read | — |
| path | `src/parse/parse_path.S` | 4096 cap → 414; `DOCROOT` prefix prepended; repeated slashes collapsed | `filename_buf` (4097 B) |
| query string | `parse_path.S` | `query_buf_size` (4096) | `query_buf` |
| `Host:` / `:authority` | `get_header_field.S`, `h2_build_request.S` | `AUTHORITY_BUF_SIZE` (256) | `authority_buf` (257 B) |
| `Range:` value | `parse_range.S`, `h2_parse_range.S`, `atoi_n.S` | resolved against the embedded entry size by `h2_resolve_range.S` | `response` range fields |
| `%XX` escapes | `src/file/decode_url.S` | in-place decode; `%00` and truncated escapes rejected; runs **before** the traversal check so `%2e%2e%2f` is caught | `filename_buf` |
| response header assembly | `http1_write_response.S` | `RESPONSE_HEADER_SIZE` (512); overflow → 500 | `header_buf` |
| pipelined leftover shift | `child.S` (`Lcheck_leftover`) | `request_total_len - request_header_len` | `buf` |

Path safety is four sequential filters — `parse_path` → `decode_url` →
`check_path_safety` (printable ASCII 0x20–0x7E only) → `check_path_traversal`
(a segment exactly `..` is rejected; `foo..txt` and `...` are allowed). Because
lookup is a scan of an embedded table and never an `open`, traversal failure is
a 404-class outcome rather than a filesystem escape — but the filters are still
the tested contract (`tests/test_security.sh`).

### 3.5 Length arithmetic notes

All of the above is 64-bit register arithmetic over values that the wire caps
at 16 or 24 bits, then bound-checked against a buffer end held in a register.
The classic `ptr + len` wrap is therefore not reachable from a single wire
field; the residual risk lives in *sums* — `cursor + field_len` inside the
ClientHello and HPACK walks, `header + payload` in the h2 loop, and the
staging-offset triples in §3.2 — and in any future field whose length is
composed from more than one wire value. There is no `adds`/`b.cs` checked-add
idiom in the tree today; bounds are enforced by comparison against a
pre-computed end pointer instead. Step 5 of the programme is the audit that
decides whether that is sufficient everywhere.

---

## 4. Secret inventory

Where secret material lives, for how long, and who can reach it.

### 4.1 Long-lived

| Secret | Location | Lifetime |
|---|---|---|
| ECDSA P-256 private scalar (32 B) | `src/tls/cert_data.S:59` (`tls_priv_key`), generated by `certs/embed_cert.sh` from `certs/key.pem` | the life of the binary — static `.data` |
| Certificate DER | `src/tls/cert_data.S:13` (`tls_cert_der`) | public; copied to the wire verbatim, never parsed |

The private scalar is embedded as literal `.byte` data in a **writable**
`.data` section, and `certs/key.pem` is checked into the repository. Today's
key is a self-signed `localhost` development certificate, so nothing
confidential is currently exposed — but the shape is exactly the one
`docs/SECURITY.md` §9 warns about, and it is the decision Step 13 has to
settle before any real deployment. Recorded in §9.

### 4.2 Per-connection

All in `src/tls/data.S` (`tls_state`, 544 B, offsets in `defs.S:940-1010`):

`tls_shared_secret` (X25519 output) · `tls_handshake_secret` ·
`tls_master_secret` · `tls_client_hs_traffic_secret` ·
`tls_server_hs_traffic_secret` · `tls_client_hs_key`/`_iv` ·
`tls_server_hs_key`/`_iv` · `tls_client_app_key`/`_iv` ·
`tls_server_app_key`/`_iv`.

Non-secret but security-relevant in the same block: `tls_client_random`,
`tls_server_random`, both key shares, `tls_transcript_hash_field`, the two
sequence numbers, the negotiated ALPN and the echoed session id.

These are **not cleared** between connections in the process — they do not need
to be on the forked path (the child `_exit`s), but under `no_fork` the same
process serves connection after connection. `no_fork` is a debug/profiling
mode, not a production one.

### 4.3 Ephemeral

| Secret | Where | Handling |
|---|---|---|
| ephemeral X25519 private scalar | `tls_build_server_hello` stack frame | wiped before return |
| ECDSA nonce `k` (32 B) | `certificate_verify/write.S`, `sp+32` | wiped before return; redrawn on the ~2^-256 `r==0`/`s==0` retry, capped at 4 attempts |
| raw `(r,s)` | same frame, `sp+64` / `sp+96` | wiped before return |

### 4.4 Entropy

`src/crypto/random.S` — `getentropy(2)` on macOS, `getrandom(2)` with
`flags = 0` on Linux (blocks until the CSPRNG is seeded). No file descriptor,
no `/dev/urandom`, and therefore no fallback path to audit. Three calls per TLS
connection: `server_random` and the ephemeral X25519 scalar
(`server_hello/build.S:46,52`), and the ECDSA nonce
(`certificate_verify/write.S:70`).

Failure handling is **fail-closed**: `crypto_random_bytes` returns carry-set
with an errno, and `tls_certificate_verify_write` maps that straight to
`TLS_ALERT_INTERNAL_ERROR` (`write.S:41`) rather than substituting anything.
The Linux loop treats a zero-length fill as an error rather than spinning. This
is the property `docs/SECURITY.md` §16 asks for; it is currently asserted only
by construction, not by a test.

### 4.5 Secrets in output

There is no logging of any kind in the server — no `stderr` writes, no debug
output, no error file. The only bytes that reach a client are: TLS records
sealed from `tls_write_record_buf`, HTTP/1 headers from `header_buf` + an
embedded body, and h2 frames from `h2_frame_buf` / `transport_writev_scratch`.
The disclosure risk is therefore entirely *over-read into an adjacent
buffer*, not accidental printing — which makes the `.bss`/`.data` adjacency map
in §5 the thing that matters, and Step 10's canary test the right detector.

---

## 5. Memory: allocations and buffers

**There is no dynamic allocation.** `mmap`, `munmap` and `brk` appear in
`defs.S` but are called from nowhere in `src/` (§6). Every buffer is a
fixed-size `.bss`/`.data` global or a stack frame. Consequences: no heap
overflow, no use-after-free, no allocator metadata to corrupt — and no
allocator red zones either, which is exactly why Step 2's guard pages have to
be built by hand around the assembly functions.

Static buffers, by module:

| Buffer | Size (B) | Module |
|---|---|---|
| `buf` | 16400 (`BUF_SIZE` + 1, rounded) | `src/data.S` — HTTP/1 request + first-read staging |
| `filename_buf` | 4112 | `src/parse/data.S` |
| `query_buf` | 4096 | `src/parse/data.S` |
| `authority_buf` | 272 | `src/parse/data.S` |
| `header_buf` | 512 (`RESPONSE_HEADER_SIZE`) | `src/http1/data.S` |
| `request` / `response` | 80 / 64 | `src/data.S` |
| `h2_frame_buf` | 16393 | `src/h2/data.S` |
| `h2_wait_buf` | 16393 | `src/h2/data.S` |
| `h2_streams` | 1024 (32 × 32) | `src/h2/data.S` |
| `h2_conn` / `h2_frame_header` | 112 / 16 | `src/h2/data.S` |
| `h2_range_buf` / `h2_cr_buf` | 64 / 64 | `src/h2/` |
| `h2_hpack_str_buf` | 4096 | `src/hpack/data.S` |
| `h2_hpack_fields` | 1024 (32 × 32) | `src/hpack/data.S` |
| `h2_hpack_dyn_entries` | 2048 (128 × 16) | `src/hpack/dynamic_table/data.S` |
| `h2_hpack_dyn_bytes` | 4096 | `src/hpack/dynamic_table/data.S` |
| `tls_state` | 544 | `src/tls/data.S` |
| `tls_hs_msg_buf` | 2048 | `src/tls/data.S` |
| `tls_hs_record_buf` | 16448 | `src/tls/data.S` |
| `tls_transcript_ctx` | 112 (`SHA256_CTX_SIZE`) | `src/tls/data.S` |
| `tls_read_raw_buf` | 16448 | `src/transport/data.S` |
| `tls_read_stage_buf` | 16384 | `src/transport/data.S` |
| `tls_write_record_buf` | 16448 | `src/transport/data.S` |
| `plain_read_stage_buf` | 16384 | `src/transport/data.S` |
| `transport_writev_scratch` | 16672 | `src/transport/data.S` |
| `sha256_ctx` | 112 (`SHA256_CTX_SIZE`) | `src/crypto/data.S` |
| embedded assets + paths + ETags | `.incbin` × 6 plus tables, 80 B/entry | `src/embedded.S` |
| certificate + private scalar | 470 + 32 | `src/tls/cert_data.S` |

Everything above — including the embedded assets, the certificate and the
private scalar — is emitted into **writable** `.data`/`.bss`. Nothing is in a
read-only section. See §9.

Adjacency matters for over-read: `tls_state` (every traffic key) sits
immediately before `tls_hs_msg_buf` and `tls_hs_record_buf` in the same object,
and the transport staging buffers are contiguous with each other. An
over-read of a few hundred bytes past a record buffer reaches key material
without leaving the module. Guard pages (Step 2) cannot be placed between
statically laid-out globals, so the boundary tests in Step 3 have to copy the
function's inputs into a guarded mapping rather than test the globals in situ.

Stack usage is declared per function in the file headers (the "Stack Usage"
field that `scripts/abi.py` and `validate_clobbers.py` check). There are no
variable-length stack allocations anywhere in the tree.

---

## 6. Syscall inventory

Actual call sites, whole tree, excluding the `.equ` definitions in `defs.S`:

| Syscall | Call sites | Phase |
|---|---|---|
| `socket`, `bind`, `listen`, `setsockopt` | `main.S:463,485,497,474` | startup |
| `sigaction` / `rt_sigaction`, `sigreturn` | `main.S:167,184,519,535,633-662`, `sig_tramp` | startup |
| `sysctlbyname` | `main.S:231` | startup only (`--workers auto`, `hw.logicalcpu`) |
| `fork` / `clone` | `main.S:576,587,710,721` | worker spawn + per connection |
| `accept` / `accept4` | `main.S:675,681` | per connection |
| `kill` | `main.S:312` | `worker_shutdown` only |
| `setsockopt` (`SO_RCVTIMEO`) | `main.S:759`, `child.S:84` | per connection |
| `read` | `main.S:780`, `child.S:132`, `h2_verify_preface.S:41`, `raw_read.S:43`, `transport_read.S:72` | per connection |
| `write` / `writev` | `raw_write.S:44`, `raw_writev.S:63` | per response |
| `close` | `main.S:731,740,749,835`, `child_end.S:30,38`, `worker_shutdown` | teardown |
| `shutdown` | `main.S:828` | shutdown |
| `exit` | `main.S:318,367,842`, `child_end.S:48` | teardown |
| `getentropy` (macOS) / `getrandom` (Linux) | `crypto/random.S` | per TLS connection |

**No filesystem syscall is called from anywhere in `src/`.** `open`, `openat`,
`stat64`, `fstat64`, `getdirentries64`, `unlink`, `unlinkat`, `renameatx_np`,
`execve`, `mmap`, `munmap`, `dup2`, `pipe`, `wait4`, `getpeername`,
`nanosleep`, `setitimer`, `gettimeofday`, `recvfrom`, `proc_info` and
`getpid` are **defined in `defs.S` but never invoked** — leftovers from the
pre-embedded era. That makes the allowlist for Step 11 exactly the table above,
and the test assertion is strong and simple: after startup, a traced workload
must show no `open`/`openat`/`execve` at all, because no code path issues one.

Two footnotes for the tracing test: `sysctlbyname` is startup-only and only on
the `--workers auto` path, and the entropy call is the only syscall in the
whole crypto tree.

---

## 7. Protocol states

### 7.1 TLS 1.3 handshake (`tls_hs_state`, `defs.S:917-925`)

```
TLS_HS_START ──ClientHello valid──► CH_RECEIVED ──► SH_SENT ──► EE_SENT
     │                                                              │
     └──any parse/requirement failure──► FAILED ◄──────────┐        ▼
                                                          │   CERT_SENT
   CONNECTED ◄──client Finished verified── FIN_SENT ◄──────┴──  CV_SENT
```

`FAILED` is terminal — the connection must close. `CONNECTED` is the only state
in which application data is accepted, and reaching it switches
`transport_mode` to `TRANSPORT_TLS`. The negotiated parameters are fixed, not
chosen: one cipher suite (`TLS_AES_128_GCM_SHA256`), one group (X25519), one
signature scheme (ecdsa_secp256r1_sha256), ALPN `h2` **required**. A client
that does not offer all of them is rejected at ClientHello with the matching
RFC 8446 §6.2 alert (`protocol_version`, `handshake_failure`,
`no_application_protocol`, `unrecognized_name`, `illegal_parameter`,
`decode_error`).

Because ALPN `h2` is mandatory, **every** TLS connection goes to
`h2_connection_loop`; the HTTP/1 state machine is unreachable over TLS.

For Step 7, the transition table to fuzz is: for each of the nine states, every
handshake message type (`defs.S:841-851`) and every record content type
(20/21/22/23), including repeats — the property being that each pair either
advances the state or lands cleanly in `FAILED`.

### 7.2 HTTP/2 streams (`defs.S:660-680`)

States `IDLE`, `OPEN`, `HALF_CLOSED_REMOTE`, `HALF_CLOSED_LOCAL`, `CLOSED`;
events `RECV_HEADERS`, `RECV_DATA`, `RECV_END_STREAM`, `RECV_RST_STREAM`,
driven through the transition table in `h2_stream_event.S`. Table is 32 fixed
entries (`H2_MAX_STREAMS`), `stream_id == 0` marks free, CLOSED entries are
recycled so a connection can serve far more than 32 requests.
`MAX_CONCURRENT_STREAMS` is 32 and is advertised; a HEADERS frame that would
exceed it is refused with `GOAWAY(ENHANCE_YOUR_CALM)`.

One server-internal flag rides above the wire flags: `H2S_FLAG_SERVING`
(`0x100`), set while `h2_process_request` is writing a response. It exists
because `h2_write_body` keeps dispatching client frames while blocked on flow
control, so without it a WINDOW_UPDATE could re-enter the handler and send the
same response twice, recursively. That re-entrancy — request service nested
inside flow-control waiting, with frames landing in `h2_wait_buf` rather than
`buf` — is the most state-dense region in the server and the place a state
fuzzer (Step 7) is most likely to find something.

Connection-level state is `h2_conn` (`H2C_*`, 112 B): peer settings, ACK
received, last stream id, connection send window, GOAWAY received.

### 7.3 HTTP/1 (no explicit state variable)

Per connection: read → `parse_header_end` finds `\r\n\r\n` → `verify_http_version`
→ `parse_request` → dispatch (GET / HEAD / OPTIONS / `BREW`→418 / else 501) →
`create_response` → `http1_write_response` → `http1_keepalive_continue`.

The keep-alive decision is a pure predicate (`http1_should_keep_alive`) over
the raw request buffer, the method id and the status, stashed in
`keep_alive_decision` so the `Connection:` header sent and the socket behaviour
cannot disagree. It closes when: no request was observed, the method is not
GET/HEAD/OPTIONS, the status indicates the parser lost sync (400/408/413/431/500),
the request carries `Content-Length` or `Transfer-Encoding` (sarm never reads a
body, so it cannot skip one to find the next request line), an HTTP/1.0 request
did not ask for keep-alive, or the request said `Connection: close`.

Refusing any request with a body or `Transfer-Encoding` on a kept-alive
connection is what keeps request smuggling out of scope structurally rather
than by parsing carefully — there is no second interpretation of a message
boundary to disagree about. Step 8's smuggling corpus should confirm that
rather than assume it.

`http1_reset_request` is the single audited place clearing per-request state:
`request`, `response`, the filename/query/authority/range/header buffers, the
`embedded_*` globals, `resource_type`, `file_des` → -1. It deliberately leaves
`clientfd`, `itoa_buf`, and `buf`/`request_header_len` alone. **Any state not
in that list persists across requests on one connection** — that is the
cross-request contamination surface, and it is the one place where "one process
per connection" does not do the isolation for us.

---

## 8. Resource limits currently enforced

| Bound | Value | Where |
|---|---|---|
| listen backlog | 128 | `main.S:497` |
| idle/receive timeout | `RECV_TIMEOUT` = 10 s per read | `config.S`, armed at `main.S:759` before the first read and again in `child.S:84` |
| HTTP/1 requests per connection | `HTTP1_KEEPALIVE_BUDGET` = 100 | `config.S`, `request_budget` |
| request header bytes | `BUF_SIZE` = 16384 → 431 | `child.S` |
| path length | 4096 → 414 | `parse_path.S` |
| response header bytes | 512 → 500 | `http1_write_response.S` |
| h2 receive frame size | 2^14 (`H2C_MAX_RX_FRAME_SIZE`) | `h2_validate_frame.S` |
| h2 concurrent streams | 32 | `defs.S`, advertised in SETTINGS |
| HPACK dynamic table | 4096 B / 128 entries | `defs.S`, `dynamic_table/` |
| HPACK decoded fields per block | 32 | `defs.S` |
| TLS record plaintext / ciphertext | 2^14 / 2^14+256 | `record/parse.S` |
| worker processes | `--workers N`, clamped to `[1, MAX_WORKERS=64]` | `main.S`, `config.S` |

Not bounded anywhere in the server: **the number of concurrent connections**
(one forked process each, so the real ceiling is the OS process/fd limit), and
**total handshake duration** (only the per-read `SO_RCVTIMEO` applies, so a
client that dribbles one byte per 9 seconds holds a process indefinitely).
Both are inputs to Step 12, not defects to fix here.

---

## 9. Observations carried forward

Found while taking the inventory. Each belongs to a later step; none is acted
on by Step 1.

1. **The private scalar is embedded in writable `.data`, and `certs/key.pem`
   is in the repository.** Today it is a self-signed `localhost` dev key, so
   nothing is currently exposed — but the deployment story (§9 of
   `docs/SECURITY.md`: per-deployment or hardware-backed key) has to be settled
   before this pattern meets a real certificate. → Step 13.
2. **No section is read-only.** Embedded assets, the certificate, the Huffman
   and status tables, and the private scalar all land in writable `.data`. A
   write primitive could rewrite served content or the key in place. → Step 13.
3. **Key material is adjacent to attacker-filled record buffers** within
   `src/tls/`. This raises the value of over-read testing specifically at the
   `tls_hs_record_buf` / `tls_hs_msg_buf` boundaries. → Steps 2, 3, 10.
4. **Bounds are enforced by comparison against an end pointer, never by a
   checked-add idiom.** Sound for single 16/24-bit wire fields in 64-bit
   registers; the audit target is composed sums (ClientHello and HPACK cursor
   walks, the staging offset triples). → Step 5.
5. **Fail-closed entropy handling is asserted by construction, not by test.**
   No test forces `crypto_random_bytes` to fail and checks that the handshake
   aborts. → Steps 3, 10.
6. **`defs.S` defines ~20 filesystem and process syscalls that nothing calls.**
   Harmless today, but they make the "no filesystem access" claim readable only
   by tracing, not by inspection. The allowlist in §6 is the tested form. →
   Step 11.
7. **No concurrent-connection cap and no total-handshake-duration cap.** The
   per-read timeout does not bound a slow client's total hold on a process. →
   Step 12.
8. **The h2 flow-control re-entrancy path** (`h2_write_body` dispatching frames,
   serving nested requests, `H2S_FLAG_SERVING` guarding double-send) is the
   densest state region and deserves targeted state fuzzing rather than only
   byte-level fuzzing. → Step 7.
9. **`no_fork` mode reuses one process across connections** without clearing
   `tls_state`. It is a debug/profiling mode only, but any test harness that
   uses it inherits cross-connection state. → Steps 3, 10.

---

## 10. What Step 1 delivers

A reviewable inventory, no code changes: the entrypoints an attacker can reach
(§2), every wire-derived length and the bound that constrains it (§3), where
secrets live and for how long (§4), the complete static buffer map with no heap
anywhere (§5), the exact syscall allowlist (§6), and the three protocol state
machines with their transition tables named (§7).

Steps 2 and 3 build on §5 (guard pages around functions whose inputs are
statically-allocated globals) and §3 (the boundary corpus: 0, 1, block−1,
block, block+1, large, maximum). Step 11 tests §6 directly. Steps 6–8 fuzz the
parsers named in §3.1, §3.3 and §3.4, in that priority order.
