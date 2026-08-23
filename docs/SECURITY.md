# sarm — security

The threat model, the attack-surface inventory, the fourteen-step test
programme that was built against it, what that programme found, and what is
left. The full narrative of any step is in its commit message.

**Status.** Steps 1–14 are complete. Every step has a suite in `make test` or
`make test-security`. Four production defects were found and fixed (§11), one
of them a remote pre-authentication crash. §14 is the open work.

`sarm` is a hand-written ARM64 assembly server with no libc, no heap, no
dynamic linking and no filesystem access while serving. It is a fun project.
Assume it has vulnerabilities.

---

## 1. Adversary model

Assume an attacker **can**: open arbitrary numbers of TCP connections; send
arbitrary, truncated, fragmented, reordered or oversized bytes at any protocol
stage; force races between concurrent connections; disconnect at any byte; send
valid but expensive cryptographic input; and inspect the distributed binary.

Assume they initially **cannot**: read arbitrary process memory, execute
arbitrary code, attach a debugger in production, or modify the executable after
deployment.

> The invariant the whole programme defends: *network input can move an
> attacker from the first list to the second only through a memory-safety,
> length-arithmetic, or protocol-state defect in this tree.*

The standard to test against:

> Arbitrary network input can cause only a bounded, clean rejection. It can
> never cause an out-of-bounds access, integer wraparound, undefined protocol
> state, unbounded resource consumption, filesystem access, or any output
> derived from memory outside the explicitly defined response buffers.

**One process serves one connection.** Workers `accept` and `fork`; the child
serves that connection to completion and `_exit`s (`src/sarm/main.S`,
`src/sarm/child_end.S`). Every global in §5 is therefore per-connection by
copy-on-write — a corrupted buffer, HPACK table or key schedule cannot be
observed by another connection, and a crash costs one connection, not the
server. Cross-*connection* disclosure is out of the surface; cross-*request*
state within one kept-alive or multiplexed connection is not (§7.3).

Note that removing filesystem access reduces attack surface but does **not**
protect a key already in process memory. An attacker with an arbitrary read
primitive, or the binary itself, may recover an embedded private key (§13.3).

---

## 2. Network entrypoints

| # | Entrypoint | Code |
|---|---|---|
| 1 | `accept`/`accept4` on the shared listening socket | `src/sarm/main.S` — `listen(128)`, one `fork` per connection |
| 2 | First `read()`, protocol detection | `src/sarm/main.S` — up to `BUF_SIZE` (16384) into `buf` |
| 3 | TLS handshake reader | `src/tls/server/handshake.S` → `src/tls/record/read_record.S` |
| 4 | TLS record layer, post-handshake | `src/tls/record/application_read.S`, `src/transport/transport_read.S` |
| 5 | Plaintext HTTP/1 read loop | `src/sarm/child.S` |
| 6 | HTTP/2 preface + frame loop | `src/h2/h2_verify_preface.S`, `src/h2/h2_connection_loop.S` |
| 7 | HPACK decoder | `src/hpack/**`, over the HEADERS payload already in `h2_frame_buf` |

Three protocols share one port; detection is a single byte test on the first
real `read` (the `MSG_PEEK` was removed in `Plan.md` Phase 2). `0x16` →
`tls_server_handshake` → **always** `h2_connection_loop` (ALPN `h2` is
mandatory, so there is no HTTP/1-over-TLS path). `"PRI "` → h2c. Anything else
→ HTTP/1.1.

Nothing in this server ever requires a client to prove anything, so the whole
surface is pre-authentication by definition.

---

## 3. Externally controlled lengths

### 3.1 TLS record and handshake

| Length | Source | Bound enforced | Destination |
|---|---|---|---|
| record fragment length (2 octets) | `record/parse.S` | `<= 2^14` for types 20/21/22, `<= 2^14+256` for type 23; must not run past the buffer end | `tls_hs_record_buf` / `tls_read_raw_buf` (16448 B) |
| handshake message length (3 octets) | `server/handshake.S` | the fragment must be at least `TLS_HS_HEADER_LEN` (added by Step 7 — §11); the message's own declared length is **not** checked (§14 A1) | `tls_hs_msg_buf` (2048 B) |
| `legacy_session_id` | `client_hello.S` | `<= 32` and must fit the body remainder | `tls_session_id` (32 B) |
| `cipher_suites` | `client_hello.S` | `>= 2`, even, must fit the remainder | scanned, not copied |
| extensions block / per-extension | `client_hello.S` | block must *exactly* fill the body; each extension must fit inside it | key_share → 32 B, ALPN → 16 B |
| AEAD tag / inner-type scan | `record/decrypt.S` | `_MAC` / `_INNER` / `_EMPTY` | in place |

The ClientHello parser is a hand-written strict-bounds recursive-descent walk
(`x9` cursor, `x10` body end, `x13` extensions end); every field compares
`cursor + field_len` against the applicable end before reading. It is a leaf
function with no calls and no stack frame, and it is the largest pre-auth
parser in the tree.

### 3.2 Record-layer staging

`transport_read` must return exactly what its caller asked for; a decrypted
record rarely matches, so plaintext is staged and doled out
(`tls_read_stage_len`/`_pos`, and the plaintext equivalents). The bug shape
here is a stale `pos > len`, not an oversized field. `h2_connection_loop`
resets the plain staging pair at the start of every connection precisely
because `no_fork` reuses the process.

### 3.3 HTTP/2 and HPACK

| Length | Bound enforced |
|---|---|
| frame payload length (24-bit) | `<= 2^24-1` and `<= H2C_MAX_RX_FRAME_SIZE` (2^14) → `FRAME_SIZE_ERROR` |
| stream id (31-bit) | R bit masked; table is 32 entries with CLOSED-slot recycling |
| SETTINGS entries | payload must be a multiple of 6 |
| WINDOW_UPDATE increment | window may not exceed 2^31-1 → `FLOW_CONTROL_ERROR` |
| PADDED pad length | must not exceed the remaining payload |
| HPACK integer | bounded to 32 bits; every octet checked against the block end |
| HPACK string length | checked against the block end **before** the read; Huffman output bounded by 4096 |
| HPACK table index / size update | beyond static(61)+dynamic, or above 4096 → `COMPRESSION_ERROR` |
| decoded field count | 32 (`H2_HPACK_MAX_FIELDS`) |
| `range` header value | compared against `h2_range_buf_size` (64) before copy |

HPACK is the deepest attacker-controlled decode path (integer → string →
Huffman → table → field → request struct) and it is stateful across the whole
connection: RFC 9113 §4.3 makes one bad index a connection-level failure.

### 3.4 HTTP/1 and the shared request path

| Length | Bound enforced |
|---|---|
| request bytes read | `BUF_SIZE` (16384); buffer full without `\r\n\r\n` → 431 |
| path | 4096 → 414; `DOCROOT` prepended; repeated slashes collapsed |
| query string | `query_buf_size` (4096) |
| `Host:` / `:authority` | `AUTHORITY_BUF_SIZE` (256) |
| `Range:` value | resolved against the embedded entry size; `atoi_n` rejects 19+ digits |
| `%XX` escapes | in-place; `%00` and truncated escapes rejected; runs **before** the traversal check so `%2e%2e%2f` is caught |
| response header assembly | `RESPONSE_HEADER_SIZE` (512) → 500 |
| pipelined leftover shift | `request_total_len - request_header_len` |

Path safety is four sequential filters — `parse_path` → `decode_url` →
`check_path_safety` (printable ASCII only) → `check_path_traversal` (a segment
exactly `..` is rejected; `foo..txt` and `...` are allowed). Because lookup is
a scan of an embedded table and never an `open`, a traversal failure is a
404-class outcome rather than a filesystem escape — but the filters are still
the tested contract.

### 3.5 The length-arithmetic audit (Step 5)

All of the above is 64-bit register arithmetic over values the wire caps at 16
or 24 bits, then bound-checked against an end pointer. The classic `ptr + len`
wrap is therefore not reachable from a single wire field; the residual risk
lives in *sums*.

A **site** is any instruction where a wire-derived value takes part in
arithmetic whose result reaches an address, a length or a bound comparison.
Each of ~120 sites got one of three verdicts:

| Verdict | Meaning |
|---|---|
| **width** | Cannot wrap because every operand is an 8/16/24-bit wire field in a 64-bit register, and the result is compared against an end pointer before use. Sound — but the soundness lives outside the instruction. |
| **checked** | Carries its own overflow check (`ckadd`/`ckrange`/`ckfits`, added to `src/defs.S` by this step). Sound locally. |
| **fixed** | Was neither. |

Applying the checked idiom to all ~120 sites would be churn. The rule adopted:

> Use the checked idiom wherever the operand's width is not visible at the
> instruction, and wherever a value crosses a function boundary before being
> used as a length.

`ckrange` is the important macro: "does this field fit?" is two questions —
does `base + len` wrap, and is it past `end` — and asking only the second is
what makes a comparison against a precomputed end pointer meaningless the
moment `len` stops being width-limited.

**Verdicts.** TLS record layer, ClientHello, the HTTP/2 frame loop and the
HTTP/1 request path are all **width**. Two are worth naming. The ClientHello's
list-length checks are safe *because* the arithmetic is 32-bit and the fields
are 16-bit — the width argument in its purest form and its most fragile. And
`transport_read`'s drain uses `subs`/`b.gt` — **signed** — so a stale
`pos > len` goes negative, fails the branch and falls into a fresh `read()`
that resets both counters; the state repairs itself rather than copying a
negative count as 2^64. A future change from `b.gt` to `b.ne` would be a bug.

HPACK was the exception, and produced three of the four findings in §11.

**Carried forward** (see §14 A3): `h2_huffman_decode` still trusts its length
argument, and is one new caller away from being the same defect again;
`h2_hpack_dyn_insert`'s entry-size sum reads as unbounded and is safe only by
a width established two functions away; `h2_resolve_range` would accept
`start > end` if it were ever reached with one; and **the width argument is not
machine-checkable** — every verdict above is a human reading two functions, and
nothing in the build re-derives it when a field changes size.

---

## 4. Secrets

**Long-lived.** One ECDSA P-256 private scalar (32 B) and the certificate DER,
embedded as literal `.byte` data in `src/tls/cert_data.S` by
`certs/embed_cert.sh`. Since Step 13 both are **read-only** —
`__DATA_CONST` on macOS, `.rodata` on Linux, mapped `r--` in the running
process and checked by name. `certs/key.pem` is in the repository; today it is
a self-signed `localhost` development key. The deployment question is open —
§13.3.

**Per-connection.** All in `tls_state` (544 B, `src/tls/data.S`): the shared
secret, handshake and master secrets, the four traffic secrets, and the four
key/IV pairs. These are **not** cleared between connections in the process.
They do not need to be on the forked path — the child `_exit`s — but under
`no_fork` the same process serves connection after connection. `no_fork` is a
debug/profiling mode, not a production one.

**Ephemeral.** The ephemeral X25519 scalar, the ECDSA nonce `k` and the raw
`(r,s)` live in stack frames and are wiped before their function returns. `k`
is redrawn on the ~2^-256 `r==0`/`s==0` retry, capped at 4 attempts.

**Entropy.** `getentropy(2)` on macOS, `getrandom(2)` with `flags = 0` on
Linux. No file descriptor, no `/dev/urandom`, so no fallback path to audit.
Three calls per TLS connection: server random, ephemeral X25519 scalar, ECDSA
nonce. Failure handling is **fail-closed**: `crypto_random_bytes` returns carry
set with an errno and `tls_certificate_verify_write` maps that straight to
`TLS_ALERT_INTERNAL_ERROR` rather than substituting anything. This is asserted
by construction and still not by a test — §14 A4.

### 4.5 Secrets in output

There is **no logging of any kind** in the server — no `stderr` writes, no
debug output, no error file. The only bytes reaching a client are TLS records
sealed from `tls_write_record_buf`, HTTP/1 headers from `header_buf` plus an
embedded body, and h2 frames from `h2_frame_buf`/`transport_writev_scratch`.
The disclosure risk is therefore entirely *over-read into an adjacent buffer*,
which makes the adjacency map in §5 the thing that matters. Step 10's canary
probe is the detector, and it asserts the no-logging property too: the run
fails on any byte written to stdout or stderr.

---

## 5. Memory

**There is no dynamic allocation.** `mmap`, `munmap` and `brk` are defined in
`defs.S` and called from nowhere. Every buffer is a fixed-size `.bss`/`.data`
global or a stack frame; there are no variable-length stack allocations. So:
no heap overflow, no use-after-free, no allocator metadata to corrupt — and no
allocator red zones either, which is exactly why the guard pages in Steps 2–9
have to be built by hand around the functions under test.

The writable buffers, by module:

| Buffer | Size (B) | Module |
|---|---:|---|
| `buf` — HTTP/1 request + first-read staging | 16400 | `src/data.S` |
| `filename_buf` / `query_buf` / `authority_buf` | 4112 / 4096 / 272 | `src/parse/data.S` |
| `header_buf` | 512 | `src/http1/data.S` |
| `request` / `response` | 80 / 64 | `src/data.S` |
| `h2_frame_buf` / `h2_wait_buf` | 16393 each | `src/h2/data.S` |
| `h2_streams` / `h2_conn` | 1024 / 112 | `src/h2/data.S` |
| `h2_hpack_str_buf` / `h2_hpack_fields` | 4096 / 1024 | `src/hpack/data.S` |
| `h2_hpack_dyn_entries` / `_dyn_bytes` | 2048 / 4096 | `src/hpack/dynamic_table/data.S` |
| `tls_state` | 544 | `src/tls/data.S` |
| `tls_hs_msg_buf` / `tls_hs_record_buf` | 2048 / 16448 | `src/tls/data.S` |
| `tls_read_raw_buf` / `_stage_buf` / `tls_write_record_buf` | 16448 / 16384 / 16448 | `src/transport/data.S` |
| `plain_read_stage_buf` / `transport_writev_scratch` | 16384 / 16672 | `src/transport/data.S` |
| `sha256_ctx` / `tls_transcript_ctx` | 112 each | `src/crypto/`, `src/tls/` |

Everything the server never writes is in a read-only section since Step 13
(§13.1): the embedded assets, the certificate, the private scalar, the crypto
constants and every dispatch table.

**Adjacency matters for over-read.** `tls_state` — every traffic key — sits
immediately before `tls_hs_msg_buf` and `tls_hs_record_buf` in the same object,
and the transport staging buffers are contiguous. An over-read of a few hundred
bytes past a record buffer reaches key material without leaving the module.
Guard pages cannot be placed between statically laid-out globals, so the
boundary tests copy a function's inputs into a guarded mapping rather than
testing the globals in situ.

---

## 6. Syscalls

The complete set, whole tree, excluding `.equ` definitions:

| Syscall | Phase |
|---|---|
| `socket`, `bind`, `listen`, `setsockopt` | startup |
| `sigaction`/`rt_sigaction`, `sigreturn` | startup |
| `sysctlbyname` | startup only, `--workers auto` |
| `setrlimit` / `prlimit64` | startup — `RLIMIT_CORE` to zero (§13.2) |
| `fork`/`clone`, `accept`/`accept4` | worker spawn, per connection |
| `kill` | `worker_shutdown` only |
| `setsockopt` (`SO_RCVTIMEO`), `setitimer` | per connection (§8) |
| `read`, `write`/`writev` | per connection / per response |
| `close`, `shutdown`, `exit` | teardown |
| `getentropy` / `getrandom` | per TLS connection |

**No filesystem syscall is called from anywhere in `src/`.** `open`, `openat`,
`stat64`, `execve`, `mmap`, `wait4` and about fifteen others are defined in
`defs.S` and never invoked — leftovers from the pre-embedded era.

This is written down as `tests/syscall_allowlist.txt` and checked two ways
(Step 11). **Adding a line to that file is a change to this table.**

*Statically*, `scripts/syscall_audit.py` makes a stronger claim than any trace
can: every syscall goes through the `SCWINUM`/`SCWISVC` macro pair, which
materialises the number as an **immediate**, there is no libc, and nothing is
dynamically linked — so the set of syscalls the binary *can* make is decidable
from the disassembly. Three checks: every `SCWINUM` site in `src/` (44 sites,
21 distinct, platform-blind so an `#ifdef` arm you are not building still has
to be justified); every `svc` in the built binary (36 on macOS, 15 on Linux);
and an explicitly forbidden set (`open`, `openat`, `execve`, `unlink`,
`chroot`, `ptrace`, …) that fails by name. An `svc` the audit **cannot**
resolve is itself a failure — at that moment the claim has stopped being true
and needs re-arguing.

*Dynamically*, `tests/test_syscalls.sh` runs the hostile workload under
`strace` in an empty directory. A representative Linux run (30 connections):
thirteen syscalls, all allowlisted, no `open`, no `openat`, no `mmap`. Where no
tracer is available the dynamic check reports **skipped**, not passed.
`SECURITY.md`'s filesystem-non-access question is answered the same way from
outside: the server is started in an empty read-only directory and serves the
whole workload out of it.

---

## 7. Protocol states

### 7.1 TLS 1.3 handshake (`tls_hs_state`)

```
TLS_HS_START ──ClientHello valid──► CH_RECEIVED ──► SH_SENT ──► EE_SENT
     │                                                              │
     └──any parse/requirement failure──► FAILED ◄──────────┐        ▼
                                                          │   CERT_SENT
   CONNECTED ◄──client Finished verified── FIN_SENT ◄──────┴──  CV_SENT
```

`FAILED` is terminal. `CONNECTED` is the only state in which application data
is accepted, and reaching it switches `transport_mode` to `TRANSPORT_TLS`. The
negotiated parameters are fixed, not chosen: one cipher suite
(`TLS_AES_128_GCM_SHA256`), one group (X25519), one signature scheme
(ecdsa_secp256r1_sha256), ALPN `h2` **required**. A client that does not offer
all of them is rejected at ClientHello with the matching RFC 8446 §6.2 alert.

### 7.2 HTTP/2 streams

`IDLE`, `OPEN`, `HALF_CLOSED_REMOTE`, `HALF_CLOSED_LOCAL`, `CLOSED`, driven
through `h2_stream_event.S`. 32 fixed entries; CLOSED entries are recycled so a
connection can serve far more than 32 requests. Exceeding
`MAX_CONCURRENT_STREAMS` is `GOAWAY(ENHANCE_YOUR_CALM)`.

One server-internal flag rides above the wire flags: `H2S_FLAG_SERVING`, set
while `h2_process_request` writes a response. It exists because `h2_write_body`
keeps dispatching client frames while blocked on flow control, so without it a
WINDOW_UPDATE could re-enter the handler and send the same response twice,
recursively. That re-entrancy is the most state-dense region in the server and
the one place still wanting a targeted **state** fuzzer — §14 A5.

### 7.3 HTTP/1

Read → `parse_header_end` → `verify_http_version` → `parse_request` → dispatch
(GET/HEAD/OPTIONS, else 501) → `create_response` →
`http1_write_response` → `http1_keepalive_continue`.

The keep-alive decision is a predicate (`http1_should_keep_alive`) over the raw
request buffer, the method id and the status, stashed in `keep_alive_decision`
so the `Connection:` header and the socket behaviour cannot disagree. It closes
when: no request was observed; the method is not GET/HEAD/OPTIONS; the status
says the parser lost sync (400/408/413/431/500); the request carries
`Content-Length` or `Transfer-Encoding` (sarm never reads a body, so it cannot
skip one to find the next request line); an HTTP/1.0 request did not ask for
keep-alive; or the request said `Connection: close`.

Refusing any request with a body on a kept-alive connection is what keeps
request smuggling out of scope *structurally* rather than by parsing carefully
— there is no second interpretation of a message boundary to disagree about.
Step 8's `keepalive` campaign checks the whole rule as an iff against a
reference, and separately asserts on every kept-alive verdict that a reference
scan finds neither header.

`http1_reset_request` is the single audited place clearing per-request state,
and it deliberately leaves `clientfd`, `itoa_buf` and `buf`/`request_header_len`
alone. **Any state not in that list persists across requests on one
connection** — the cross-request contamination surface, and the one place where
"one process per connection" does not do the isolation for us.

---

## 8. Resource limits

| Bound | Value | Where |
|---|---|---|
| listen backlog | 128 | `main.S` |
| idle/receive timeout | `RECV_TIMEOUT` = 10 s **per read** | `config.S` |
| total connection lifetime | `CONN_DEADLINE` = 120 s | `config.S`, `setitimer(ITIMER_REAL)` in the forked child |
| HTTP/1 requests per connection | `HTTP1_KEEPALIVE_BUDGET` = 100 | `config.S` |
| request header bytes | `BUF_SIZE` = 16384 → 431 | `child.S` |
| path / response header | 4096 → 414 / 512 → 500 | `parse_path.S`, `http1_write_response.S` |
| h2 frame size / streams | 2^14 / 32 | `h2_validate_frame.S`, advertised in SETTINGS |
| HPACK dynamic table / fields | 4096 B, 128 entries / 32 | `defs.S` |
| TLS record plaintext / ciphertext | 2^14 / 2^14+256 | `record/parse.S` |
| worker processes | `--workers N`, clamped to `[1, 64]` | `main.S` |

**`CONN_DEADLINE` is what Step 12 added.** Before it, the only time limit was
`RECV_TIMEOUT`, which bounds **one `read()`** — nothing bounded how many times
a client could restart it. Measured at one byte every 4 seconds, a connection
was still holding at 32 s and would have held indefinitely. The same attack has
three shapes: an HTTP/1 header a byte at a time, an h2c frame header a byte at
a time, and — the one the protocol actively invites — a real ClientHello
followed by `change_cipher_spec` records forever, which RFC 8446 Appendix D.4
requires a server to tolerate and sets no limit on.

The bound is one syscall in one place: a one-shot `setitimer(ITIMER_REAL)`
armed in `Lmain_child`, with `SIGALRM` keeping its default disposition — so
expiry terminates the process, and terminates it *without a core dump*, which
matters because a core here is a complete memory disclosure. Three properties
follow from *where* it is armed: in `Lmain_child` rather than `Lmain_serve`, so
`no_fork` debug mode cannot kill the server; after the `fork`, so accept
workers (which sit in `accept()` by design) never carry it; and nothing
branches on the result, because a connection served without its ceiling is
strictly better than one refused.

It is a **ceiling, not a policy**. `RECV_TIMEOUT` still drops idle clients at
10 s with a 408; the keep-alive budget still bounds a well-behaved connection's
reuse. `CONN_DEADLINE` only decides the case neither covers: a client that is
neither idle nor finished. It also does not distinguish a slow attacker from a
slow network, which is why the constant is in `config.S`.

**Still unbounded, on purpose:** the number of concurrent connections, and
total bytes read per connection. Both are recorded decisions with triggers —
§14 C1, C2. What Step 12 changed is the *shape* of the exposure:

```
before:  live processes  ≈  connection rate × (attacker's patience)
after:   live processes  ≤  connection rate × CONN_DEADLINE
```

A slow-connection flood now reaches a steady state and clears itself instead of
accumulating without limit.

---

## 9. Observations carried forward

The register. Numbering is the original inventory's and is referenced from
source comments; gaps are deliberate.

| # | Observation | State |
|---|---|---|
| 1 | The private scalar is embedded in the binary, and `certs/key.pem` is in the repository | **partly fixed** (Step 13 — no longer writable); deployment story open, §13.3 |
| 2 | No section is read-only | **fixed** (Step 13, §13.1) |
| 3 | Key material is adjacent to attacker-filled record buffers | recorded — raises the value of over-read testing at the `tls_hs_record_buf`/`tls_hs_msg_buf` boundaries, which Steps 2, 3 and 10 do |
| 4 | Bounds are enforced by end-pointer comparison, never a checked-add idiom | **partly fixed** (Step 5, §3.5); residual is that the width argument is a human reading two functions |
| 5 | Fail-closed entropy is asserted by construction, never tested | **open** — §14 A4 |
| 6 | `defs.S` defines ~20 filesystem/process syscalls nothing calls | **fixed** by the allowlist (§6) |
| 7 | No concurrent-connection cap, no handshake-duration cap | **half closed** (Step 12); the connection cap is a recorded decision, §14 C1 |
| 8 | The h2 flow-control re-entrancy path deserves targeted *state* fuzzing | **open** — §14 A5 |
| 9 | `hkdf_expand`, `hkdf_expand_label` and `x25519_fe_sqr_times` had preconditions enforced by documentation only | **fixed** (Step 5, §11) |
| 10 | The GCM length block is assembled in three places; the exported `ghash` has no caller in the server | **fixed** (§14 A2) — one `.Lgcm_ghash_lengths` in `gcm/data.S`, called by all three. Sabotage: corrupting it now turns the `ghash`, `aes_gcm_encrypt` *and* `aes_gcm_decrypt` sweeps red; on the three-copy version the same edit to `ghash.S` left the other two green. `ghash` stays exported and stays caller-less **by decision** — it is the differential oracle for the shared core, and a routine no test can call on its own is a routine no sweep can isolate |
| 11 | `tls_read_record` cannot return `TLS_RECORD_ERR_BOUNDS` | recorded — it reads exactly `total` bytes and hands parse a buffer of exactly `total`, so one of parse's five branches is dead from the socket's perspective. The real check is the `_LENGTH` size test. Stated so an empty bucket is not mistaken for coverage |
| 12 | `tls_server_handshake` ignores the handshake message's own 3-octet length | **open** — §14 A1 |
| 13 | A handshake record with a fragment shorter than 4 bytes crashed the server pre-auth | **fixed** (Step 7, §11) |
| 14 | An unbounded number of `change_cipher_spec` records is tolerated | **fixed** (Step 12, §8) |
| 16 | `parse_path` read one byte past its length argument, in three places | **fixed** (Step 8, §11) |
| 17 | `http1_should_keep_alive` is not the pure predicate its header claims, and its check order is load-bearing | recorded — it calls `get_header_field`, which answers a header name that is a strict *prefix* of the one it wants (`Content-Lengths:`) by branching to `reply_status(400)` from inside `http1_write_response`. The client still gets exactly one response, because the decision is made before the `writev`. What stops the 400's own encode escaping again is that the status check runs *before* the header lookups. **Reorder those two blocks and the request becomes an infinite loop.** |
| 18 | `decode_url` requires a length of at least 1 | recorded — it loads the first byte before consulting the length and tests the decremented length for *equality* with zero, so 0 underflows past it. Every caller passes at least the 4-byte docroot; the precondition is now in the routine's header |
| 19 | `no_fork` reuses one process across connections without clearing `tls_state` | recorded — debug/profiling mode only, but any harness using it inherits cross-connection state |
| 20 | `transport_read` holds two copies of the same drain loop | recorded — `.Ltr_plain_loop`/`.Ltr_tls_loop`. Step 9's sabotage table shows both are correct today *and* that a fix to one would not reach the other |
| 21 | The HTTP/1 leftover shift is now covered | **fixed** (Step 9's `pipeline` campaign) |

---

## 10. The programme

Fourteen steps, all landed. Suites live in `tests/security/` (per-function) and
`tests/` (per-process); see [tests/security/README.md](../tests/security/README.md)
for how each harness works.

| Step | What it built | Where |
|---|---|---|
| 1 | This inventory (§§1–9), no code changes | — |
| 2 | `guard_pages.h` — guarded buffers with `PROT_NONE` either side, plus its own self-test | `tests/security/` |
| 3 | Every crypto primitive at `0, 1, block±1, large, max`, against a deliberately naive C reference pinned to FIPS/RFC vectors | `test_bounds_*` |
| 4 | Random-vector differential testing, ~430k vectors per run, replayable from one seed | `test_diff_*` |
| 5 | The length-arithmetic audit (§3.5) and an integer-overflow corpus | `test_overflow_*` |
| 6 | Fuzzing the TLS record layer — 6 campaigns | `test_fuzz_tls_record.c` |
| 7 | Fuzzing the handshake — ClientHello, flights, and a real client driven to `Finished` | `test_fuzz_tls_handshake.c` |
| 8 | Fuzzing HTTP/1 request parsing — 7 campaigns, 5 differential | `test_fuzz_http.c` |
| 9 | Socket fragmentation — the same bytes delivered whole and in pieces, compared | `test_frag_socket.c`, `test_frag_http.c` |
| 10 | The secret-leak probe against a live server, in both fork and `no_fork` mode | `tests/test_leak.sh` |
| 11 | The syscall allowlist, static and traced (§6) | `scripts/syscall_audit.py`, `tests/test_syscalls.sh` |
| 12 | Resource limits under attack; added `CONN_DEADLINE` (§8) | `tests/test_limits.sh` |
| 13 | Binary and OS hardening (§13) | `tests/test_hardening.sh` |
| 14 | Continuous fuzzing: a soak runner on random seeds, preserved inputs, a minimiser and a regression corpus | `scripts/fuzz_soak.py`, `scripts/fuzz_minimize.py`, `tests/security/corpus/` |

**Scale.** The committed suites run from a fixed seed in a few seconds — that
is deliberate, because a corpus that changes from run to run cannot distinguish
a regression from a coincidence. The long runs behind these documents were
`SARM_FUZZ_MULT` soaks on two or three seeds each: 228 M record-layer cases,
803 M handshake cases, 320 M HTTP cases, 1.73 M fragmented deliveries plus
15 M prefix sweeps, and a first 455 M-case soak over thirteen seeds nobody had
run. No crash, no hang, no invariant violation, no differential disagreement in
any of them, after the fixes in §11.

---

## 11. Defects found and fixed

Four in production code. Three were found by a fuzzer on its first run.

**A five-byte pre-authentication crash** (Step 7, `src/tls/server/handshake.S`).
`tls_server_handshake` skipped the 4-byte handshake header by pointer
arithmetic and subtracted it from the fragment length — unsigned, with nothing
establishing that the fragment was that long. So `16 03 01 00 00`, five bytes,
the first thing any peer says, made the length `2^64 - 4` and
`tls_transcript_add` start hashing the address space. `tls_record_parse` was
right to accept the record; a zero-length fragment is legal at the record layer
and the record layer has no idea what a handshake header is. The missing check
belongs to the driver and is now two instructions after the content-type test.
This is the only place in the tree where a peer-controlled length was consumed
before being bounded.

**Three HPACK length defects** (Step 5, `src/hpack/`). The 32-bit integer bound
tested a single bit (`tbnz x2, #32`), so 48 of the 128 possible final octets
escaped it, accepting values up to 29,796,335,743. The continuation loop was
bounded only by the shift counter, so a prefix of all ones at the tail of a
block read up to five octets past it. And — the serious one — string lengths
were validated only *after* the read: a 5-octet HEADERS payload declaring a 4 GB
Huffman string sent `h2_huffman_decode` walking ~2.5 KB off the end of
`h2_frame_buf` into a header value, and a literal on the incremental-indexing
path was `memcpy`'d out of adjacent memory first and rejected second. In a tree
where key material shares a `.bss` neighbourhood with the record buffers (§5),
that is the disclosure shape. The block end is now threaded down through
`decode_block` → `decode_field` → `decode_string` → `decode_int`/`huffman` and
every length is checked with `ckrange` before a byte is touched.

**Three reads past the length argument in `parse_path`** (Step 8). The filename
copy loop's bound was `b.hi` where the index is of the byte *about to be*
loaded; the "is `/` the last char" check had the same off-by-one; and the `" /"`
search window is 17 bytes wide while the minimum length it required was 16. All
three comments describe the check that was intended. Not reachable from the
server — `child.S` NUL-terminates `buf`, and a header ends `\r\n\r\n` — but
both reasons are properties of the *caller*, not of the routine, and
`parse_h2_path` already exists next door.

**Three preconditions enforced by documentation only** (Step 5). `hkdf_expand`
assembles its input in a 640-byte stack frame and overran it past
`infolen = 607` — over the saved registers and the return address;
`hkdf_expand_label`'s 520-byte HkdfLabel buffer had the same shape *and*
truncated the length octet it wrote, so a peer would be handed a label nobody
sent; `x25519_fe_sqr_times` runs a do-while, so `count == 0` wrapped to 2^64
iterations and never returned. None was reachable — every caller passes a
compile-time constant — but the failure mode is a smashed frame or a hang
rather than a wrong answer. The two HKDF routines now return carry set with the
output untouched; `sqr_times` returns a copy of its input, which is what
`a^(2^0)` means.

---

## 12. Method

The rules the whole programme runs on. They are the reason a green run means
anything.

**Guard pages, because there is nothing to instrument.** The routines are
hand-written `.S`: ASan, MSan and libFuzzer coverage all work by rewriting
compiler IR that does not exist here, and there is no allocator, so there are
no heap red zones. Every generated input is placed so its **last byte is the
last byte of a page**, with `PROT_NONE` immediately after, and every output
buffer is sized to exactly what the contract permits. "Did not read past the
input" is then answered by the MMU, on the instruction that got it wrong.
Where the output buffer is a server global that cannot be guarded, the 16-byte
alignment padding is filled with `0xA5` and checked after.

**A crash is not the only failure.** Each campaign checks the routine's whole
published output contract on every case — error-code range, pointer placement,
length relations, and "a rejected record left the output buffer byte-for-byte
as the poison it was filled with".

**Verified by sabotage.** A check that has only ever been seen to pass is not
evidence. Every suite has a table of production lines broken on purpose, one at
a time, and the failure each produced. Across the programme that is roughly
forty sabotages. Two *missed* on the first attempt, and the misses were the
most useful results: a bound widened past `authority_buf` was invisible because
nothing in the corpus generated a `Host:` value near 256 bytes, and a
`memcpy` sabotage did nothing because in Mach-O a `.global memcpy` in assembly
and C's `memcpy()` are two different symbols — the harness had been testing
libc's memcpy the whole time. **A sabotage that does not fail is a claim about
the harness, not about the server.**

**Non-vacuity.** A generator that drifts still satisfies every invariant on the
accepting path, vacuously. So each campaign tallies which outcome every case
reached and declares which it *must* reach; an empty required bucket fails the
run. That is not hypothetical — the first run of the record suite printed
`VACUOUS: 20000 cases and not one reached "past the buffer"`, which turned out
to be observation 11 above. The same idea in the live-server harnesses is a
check that the attack still reaches its target: *the drip outlived
`RECV_TIMEOUT` on the way there*, *the sampler saw the server's children*, *a
complete handshake is measurably expensive*.

**Determinism, and preserved bytes.** A case is a pure function of
`(seed, index)` through splitmix64, so a single case replays in-process under a
debugger. But a seed-based reproducer means whatever its *generator* means
today: replaying the five-byte crash above, after later work on that generator,
now yields a well-formed 238-byte flight. So the harness copies each case's
input into a shared page before the call and writes it out on failure. The
minimiser (delta debugging, with the replay exit code as its only oracle) took
that 238-byte capture back down to the same five bytes in 49 replays. Entries
land in `tests/security/corpus/`, replayed before every campaign on every run,
with an attribution row in `corpus/MANIFEST.md` — because a corpus file nobody
can explain is a file nobody dares delete.

**Corpus entries must fail individually.** Reverting the three `parse_path`
instructions *one at a time* showed the three preserved inputs reached only two
of the three sites. The missing entry was then derived rather than argued
about: revert the one instruction, re-fuzz, minimise, keep. 17 bytes.

**What a clean run is and is not evidence of.** The campaigns test the routines
they name; generated inputs are not all inputs; a guard page catches an access
that leaves the buffer, not one that stays inside it and is still wrong. And a
soak that finds nothing has tested more inputs than the committed suite — once.
Nothing re-runs them. The only inputs this tree keeps asking about forever are
the ones in `corpus/`, and the only way in is by failing.

**Nothing measures coverage.** Recorded four times across the fuzzing steps and
still open — §14 D1. It has two flavours: a branch the corpus never reached,
and a routine the harness never called. Both look identical from outside.

---

## 13. Hardening (Step 13)

Nothing here fixes a bug — Steps 2–9 did that. What this changes is what a bug
would be *worth*.

### 13.1 Read-only data, and no relocations

`src/defs.S` gained a `rodata` macro (`__DATA_CONST,__const` on Mach-O,
`.rodata` on ELF, `.data` under `-DSARM_NO_RODATA` for the control build) and
35 files changed over, generators included. On Mach-O the section is
deliberately `__DATA_CONST` and not `__TEXT,__const`: putting data in `__TEXT`
would make it read-only by making it *executable*.

| | before | after |
|---|---|---|
| macOS `__DATA_CONST` (r--) | — | 160 KB |
| macOS `__DATA` (rw-) | 336 KB | 176 KB |
| Linux `.rodata` / `.data` | — / 252 KB | 154 KB / 100 KB |

Four tables that held **pointers** now hold link-time **offsets**
(`h2_frame_handlers`, `h2_hpack_static_table`, `status_table`,
`embedded_files`), at a cost of one `add` per pointer read. An address in
static data is not a constant, it is a relocation — and the Linux build has no
dynamic linker at all, so a `-pie` link of pointer-bearing tables would produce
177 `R_AARCH64_RELATIVE` relocations and nobody to apply them. Position
independence and absolute addresses in static data are, for this binary,
mutually exclusive.

```
Linux:  177 dynamic relocations  →  0      ET_EXEC @ 0x400000  →  ET_DYN, randomised
macOS:  177 chained fixups       →  0
```

**The binary asks the loader to relocate nothing**, so the read-only regions
are read-only from the first instruction rather than write-then-protect.

Link flags: `-pie` on both; `--no-dynamic-linker -z noexecstack -z separate-code`
on Linux. `-z noexecstack` is the most valuable of them for this binary: the
Linux link had been a bare `ld` emitting no `PT_GNU_STACK`, and on arm64 a
*missing* `PT_GNU_STACK` is not "default" — `elf_read_implies_exec()` turns it
into a personality flag that makes every readable mapping in the process
executable.

### 13.2 No core dumps, from inside the process

`main.S` sets `RLIMIT_CORE` to zero at startup, before the listening socket
exists — rlimits are inherited across `fork()`, so one call covers every worker
and every child. Failure is **fatal**, which is the opposite of the `setitimer`
decision in §8: a failed deadline costs one connection's boundedness, a failed
core limit costs the private key on the first crash. arm64 Linux has no
`setrlimit`, so it uses `prlimit64(0, …)`; `struct rlimit` is two 64-bit fields
on both platforms.

Both new syscalls were caught by Step 11's audit *before* this step's own test
ran — the same thing that happened to `setitimer` in Step 12.

### 13.3 The private key

`SECURITY.md`'s four options, costed against this build:

| Option | What it would take here |
|---|---|
| A — hardware-backed key | A signing interface the TLS code calls instead of `p256_ecdsa_sign`, plus a syscall to reach the device. Strongest, and it breaks the "no filesystem, no dependencies" property the allowlist rests on |
| **B — generate at deployment** | `certs/generate.sh` + `embed_cert.sh` run in the deployment pipeline, not the repository. **Fits this build exactly** — the certificate is already a build input |
| C — ephemeral / per-installation | As B, plus accepting that the certificate changes when the image is rebuilt. Fine behind ACME; not for a pinned certificate |
| D — embedded encrypted key | Rejected: a passphrase would have to reach a process that deliberately cannot read one. It moves the secret rather than removing it, and costs the containment property |

Step 13 changed one thing and states the rest. The change: the key is not in
writable memory, so a write primitive can no longer replace it in place (a
substitution attack against a pinned certificate). Unchanged: an *arbitrary
read* still reaches it, exactly as it reaches any in-process key. Which of A–D
applies is a deployment decision — §14 C3.

### 13.4 Evaluated and not adopted

A "no" here is a decision, not an omission.

**BTI.** Enforced only when the ELF carries the feature note *and* every
indirect branch target carries a landing pad. This tree has ~200 hand-written
routines reached by `blr`; marking the binary without a landing pad at every
one turns a missed function into a `SIGILL` on whatever path first reaches it.
Doing it properly means a `bti c` at every global entry point enforced by
`scripts/abi.py` — a change to the assembly conventions of the whole tree, not
a link flag.

**PAC.** Same shape, worse ratio: it changes the stack discipline that
`abi.py` and every "Stack Usage" header describe, and buys protection against
return-address overwrites in a server with no attacker-writable return
addresses on record — a claim §14 B2 is what would test.

**Stack canaries.** A C compiler feature; there is no C in the server.

**RELRO.** Protects the GOT and PLT of a dynamically linked binary. This one
has neither, and after §13.1 no relocations to protect.

**`mprotect`-ing `.data` after startup.** `.data` holds `tls_state` and every
buffer; there is no point after which it stops being written. The useful subset
is exactly what §13.1 did statically.

### 13.5 The test

`tests/test_hardening.sh` + `tests/hardening_checks.py`, 10 checks on macOS and
16 on Linux, in `make test`. Nothing in it reads the Makefile or trusts a flag.

**binary** — PIE; no segment writable-and-executable at current or maximum
protection; 11 named constants inside the read-only region, private scalar
included; 4 named mutable globals outside it; zero load-time fixups. On ELF
also `PT_GNU_STACK` and `.rodata`'s own `r--` segment. The ELF side parses the
file directly, so a macOS host can inspect the Linux artifact.

**process** — the same claims about a running server: `__DATA_CONST` mapped
`r--` (`vmmap`) or the read-only segment `r--p` (`/proc/pid/maps`), no `rwx`
mapping, a non-executable stack, and on Linux a zero core limit read out of
`/proc/pid/limits`. A file can be marked however it likes.

**cores** — the built binary really does contain the `setrlimit`/`prlimit64`
call; and a connection is opened, the child `SIGSEGV`'d, and no core must
appear — gated on a control program that *does* dump under `ulimit -c
unlimited`, so a machine where nothing ever dumps reports **skipped**.

**controls** — two deliberately unhardened builds
(`make variant VARIANT_CFLAGS=-DSARM_NO_RODATA` and `make variant LDFLAGS=""`),
each of which must fail a named subset. arm64 macOS cannot link a non-PIE
executable, so that control is reported skipped there rather than faked.

**container** — `--docker` runs the seven ELF checks against the stripped
binary the image actually ships. That is why three tables that had no `.global`
now have one: a security check that cannot see the thing it checks in the
shipped artifact is not a check.

---

## 14. What is left

Ordered by what a defect would cost, not by effort. An item is not finished
until §9's register says so.

### Phase A — gaps that could become defects

**A1 — Handshake message framing and reassembly.** Observation 12. Read each
handshake message's 3-octet length and require it to agree with the fragment
the record carries (cheap, and it closes the "almost always"). Then either
implement a reassembly layer between `tls_read_record` and the driver, or write
down in `src/tls/server/README.md` that sarm deliberately requires each message
to arrive in exactly one record, with the argument for why that is safe. A
recorded refusal is an acceptable outcome; silence is not. *Test:* new
`test_fuzz_tls_handshake.c` cases for a declared length longer and shorter than
the fragment, and a Finished with a wrong declared length — currently accepted.

**A2 — The GCM length block, written three times.** **Done** — see §9,
observation 10. `.Lgcm_ghash_lengths` in `src/crypto/gcm/data.S` now owns the
block and the 16 bytes it is assembled in, which came out of three separate
stack layouts on the way (352 → 336 in both AES-GCM routines, 112 → 96 in
`ghash`). The proof this item asked for holds: one corruption, three red
sweeps. Two things worth keeping in mind for the next change here. `data.S` is
`#include`d rather than linked, so each of its five users carries its own copy
of the shared core — sharing here is of *source*, which is what the sabotage
tests, not of a single linked instance. And nothing in either Makefile treats
`data.S` as a dependency, so an edit to it rebuilds nothing: the first run of
this sabotage passed against stale objects and looked like a disproof.

**A3 — The four length-audit items.** §3.5's carried-forward list. Items 1, 2
and 4 are small defensive checks giving each routine the bound it currently
borrows from its caller, using `ckrange`. Item 3 — machine-checking the width
argument — should be attempted last, and the useful version is a *guard*, not a
proof: assert the field widths the verdicts depend on, so widening one fails
something. *Test:* an HPACK/HTTP-2 fuzz campaign, which does not exist yet.

**A4 — Fail-closed entropy is never tested.** Observation 5, sitting under a P0
row ("ECDSA nonce/randomness failure → private-key compromise"). Make the
failure injectable without shipping the injection — `make variant` is the
precedent — and assert that the handshake aborts, that nothing wire-bound
depends on the missing bytes, and that nothing signs with a zero or stale
nonce. Then walk every caller of `crypto_random_bytes` and confirm each checks
the return.

**A5 — State fuzzing of the h2 flow-control re-entrancy.** Observation 8. Drive
the state machine by *transitions* rather than bytes — frame dispatch
sequences, nested-request depths, window updates — checking after each that one
response per stream holds, `H2S_FLAG_SERVING` is never observed set twice,
nothing writes after close, and window accounting never goes negative.
Observation 17 is the instructive one: that is the class of bug state fuzzing
finds and byte fuzzing does not. *Sabotage:* remove the `H2S_FLAG_SERVING`
guard.

### Phase B — never turned into steps

**B1 — Constant-time testing** (P1; no timing harness exists). Start with the
audit, not the measurement: list every routine in `src/crypto/` touching secret
data and state, per routine, whether its control flow or memory access depends
on a secret. Then measure the ones answered "no, by construction" — that claim
is exactly what a timing harness can falsify. `scripts/benchmarks/bench_<fn>.c`
and `measure_noise_floor.py` already give per-function timing with a known
noise floor; the new work is two input classes and a distribution comparison.
All constant-time claims in this tree are currently **structural arguments
about emitted instructions**, and there is no PMU access on this machine.

**B2 — Stack-corruption testing.** Canaries and guard pages around stack frames
on the paths that take network input. The specific question is the one §13.4
leaves open: can any peer-controlled length or copy reach a return address?
Step 5's audit and the PAC decision both assume not. Re-read the PAC paragraph
once this has an answer.

**B3 — Long-running chaos tests** (P2). A sustained hostile-workload run
against a live server — `tests/hostile_workload.py` and `rps_bench.sh` are the
pieces — checking resource drift over hours: process count, descriptor count,
memory, and that `CONN_DEADLINE` keeps the steady state bounded. Note
`fuzz_soak.py` is adjacent but different: it runs *campaigns* on random seeds,
not a *server* under load. Not part of `make test`.

### Phase C — bounded by decision, not by code

These are not bugs. Each names its trigger.

**C1 — No concurrent-connection cap.** *Trigger:* any step that touches the
process model. A cap means the parent tracking live children, which means
reaping them, which means giving up `SIGCHLD = SIG_IGN` with `SA_NOCLDWAIT` and
adding a `wait4` loop to the accept path — a change to the process model the
whole multicore worker design rests on. It belongs with `Lmain_fork_failed`,
which already drops a connection when `fork` fails.

**C2 — No bytes-per-connection counter.** *Trigger:* **a body-reading path.**
Nothing accumulates input across reads today except the request header, which
has its own cap.

**C3 — The private key's deployment story.** *Trigger:* **before a real
certificate is pointed at this server.** The analysis is written (§13.3); the
decision is not made.

### Phase D — test-harness limits

**D1 — Nothing measures coverage.** The highest-leverage item here: it turns
every sabotage table from a hand-built proof into something derivable, and it
unblocks mutation from the corpus (which is replayed, not fuzzed from, because
without coverage there is no signal to tell a productive mutation from an
unproductive one).

**D2 — The seven fragmentation campaigns have no replay entry**, because a case
there is bytes *plus cuts*. Until the corpus format carries the split plan, the
harness exits **2** rather than answering wrongly — a distinction that matters:
before that exit code existed, the minimiser shrank a real hang to zero bytes
and called it minimal.

**D3 — Three fragmentation gaps.** The handshake driver is not fragmented end
to end ("a ClientHello split across five packets still completes a handshake"
is asserted nowhere — do this with A1, which needs the same client); EOF is not
swept at every byte (a small extension of `frag_plan` — truncate rather than
cut — with a different invariant: not equality, but "fails cleanly with
`_SHORT`, having written nothing past what arrived"); and a reset during the
handshake is untested (`close()` instead of `shutdown(SHUT_WR)`).

**D4 — The lost EOF wakeup is worked around, not understood.**
`shutdown(SHUT_WR)` on an `AF_UNIX` socketpair sometimes fails to wake a peer
already asleep in `read()` on this kernel; the fragmentation feeder now outlives
its last write and prods the reading thread with `SIGURG` until the reader
confirms it has stopped. A 90-line model measures it — 61 lost wakeups in
320,000 deliveries across 16 concurrent processes — and is the thing to hand to
anyone taking it further. **Nothing in `src/` depends on the answer**: sarm's
sockets are `AF_INET` and no reader of theirs is woken by a peer inside the same
process. Listed so it is not filed as understood.

---

## 15. Priorities

The ranking the programme was built against, for re-reading when deciding what
to do next.

| Priority | Area | Risk |
|---|---|---|
| **P0** | Out-of-bounds read/write | Remote code execution or secret disclosure |
| **P0** | Integer overflow in lengths | Bypass bounds checks |
| **P0** | TLS state-machine errors | Authentication/protocol bypass |
| **P0** | ECDSA nonce/randomness failure | Private-key compromise |
| **P0** | Private key embedded identically in distributed binaries | Offline extraction risk |
| **P1** | DoS / resource exhaustion | Service unavailable |
| **P1** | Secret copies and logging | Key leakage |
| **P1** | Crypto correctness differential testing | Broken TLS security |
| **P1** | Constant-time audit | Side-channel exposure |
| **P2** | Syscall sandboxing | Defence in depth |
| **P2** | Binary hardening | Defence in depth |
| **P2** | Long-running chaos testing | Reliability/security regression |

Of these, the P0 rows are all covered by a committed suite except **ECDSA
nonce/randomness failure** (§14 A4) and the **distributed-binary key** (§14 C3).
P1's constant-time row has nothing at all (§14 B1).

---

## 16. Running it

```bash
make test              # everything, including every security harness above
make test-security     # tests/security/ alone: bounds, differential, overflow, fuzz, frag
make fuzz-soak         # random seeds, not part of make test
```

```bash
python3 scripts/fuzz_soak.py --mult 8 --keep-going
```

Working rules for anyone continuing the programme:

- **Assembly changes** — run `scripts/abi.py`, `scripts/regpressure.py` and
  `scripts/validate_clobbers.py` before considering a `.S` edit done
  (skill: `sarm-static-analysis`).
- **Crypto arithmetic** — the `verified-asm-crypto` workflow is mandatory:
  Python prototype, cross-check, then port. Do not hand-derive in `.S`.
- **Every new check needs a sabotage row and a non-vacuity control** (§12).
- **Never fix a fuzzer finding without preserving the input.** The harness does
  this automatically into `findings/`; minimise with `scripts/fuzz_minimize.py`,
  commit under `tests/security/corpus/<suite>/<campaign>/`, and add the
  attribution row in `corpus/MANIFEST.md`.
- **Any change to `tests/syscall_allowlist.txt` is a threat-model change** — §6
  changes with it, and `tests/test_syscalls.sh` runs *before* the new step's own
  test. That audit has already caught a missing allowlist entry ahead of two
  steps' own suites.
