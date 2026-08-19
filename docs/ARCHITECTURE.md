# Architecture

How `sarm` is put together. Written for someone (or something) that needs to
change it. Every function lives in its own `.S` file with a header comment
naming its inputs, outputs, clobbered registers and stack usage — this document
is the map, those headers are the contract.

---

## Shape of the thing

```
accept()
   │
   fork()  ── parent ──► back to accept()
   │
   child (serves exactly one connection, then _exit)
   │
   ├─ peek first byte ──┬─ 0x16 ──► TLS 1.3 handshake ──► HTTP/2 over TLS
   │                    ├─ "PRI " ─► HTTP/2 cleartext (h2c)
   │                    └─ else ───► HTTP/1.1
   │
   └──────────────────────────► embedded asset table ──► response
```

One process per connection, no threads, no heap, no libc. The parent does
nothing but `accept` and `fork`; each child serves its one connection to
completion and exits.

All mutable state is `.bss`/`.data` globals (`src/data.S`, `src/tls/data.S`,
`src/h2/data.S`) with no locking, and the fork is what makes that safe: every
child gets a private copy-on-write image, so one connection can never observe
another's parsing buffers, HPACK dynamic table or TLS keys. The code is written
as though one connection is in flight because, within a process, one always is.

That is the single biggest architectural constraint. Connections already run
concurrently across cores, but the concurrency lives entirely in the kernel's
process isolation — so moving to threads or an event loop would mean making
roughly 86 writable globals worker- or connection-local first. See
`docs/MULTICORE-BASELINE.md` for the full inventory.

## Build and link

- `Makefile` compiles every `src/**/*.S` with `cc -g -O3 -c`, links with
  `ld -l System -e _main -arch arm64`. No libc symbols are called — only raw
  `svc` syscalls.
- Two generated files are built first and are never edited by hand:
  `embed_www.sh` → `src/embedded.S` (the `www/` tree), and
  `certs/embed_cert.sh` → `src/tls/cert_data.S` (DER certificate + private scalar).
- `src/config.S` (user constants) and `src/defs.S` (syscall numbers, struct
  offsets, macros, wire constants) are `#include`d, never compiled standalone.
- Platform differences live behind `#ifdef __linux__` in `defs.S`: syscall
  register (`x16`+`svc #0x80` vs `x8`+`svc #0`), error convention (macOS sets
  carry with errno in `x0`; the `SCERR` macro normalises Linux's negative return
  to the same shape, so `b.cs` works identically), relocation operators
  (`@PAGE`/`@PAGEOFF` vs `:pg_hi21:`/`:lo12:`, behind `adr_l`/`ldr_l`/`str_l`),
  `accept` vs `accept4`, `sigaction` vs `rt_sigaction`, `SO_NOSIGPIPE`.

## Module map

| Path | Role |
|---|---|
| `src/sarm/` | Lifecycle: `_main`, listen/accept loop, protocol detection, `child`, `child_end` |
| `src/transport/` | The I/O seam: `transport_read`/`transport_write` dispatch on `transport_mode` to raw sockets or TLS records |
| `src/tls/` | TLS 1.3 — `server/` (handshake driver), `handshake/` (message builders + key schedule), `record/` (record layer), `transcript/` |
| `src/crypto/` | `sha256/`, `hmac.S`, `hkdf/`, `aes128/`, `gcm/`, `x25519/`, `p256/` (field), `p256_scalar/`, `p256_point/`, `p256_ecdsa/`, `random.S` |
| `src/h2/` | HTTP/2 (RFC 9113): connection loop, frame parse/validate/dispatch, stream engine, flow control, response encoders |
| `src/hpack/` | HPACK (RFC 7541): integer/string/field/block decode, Huffman, static + `dynamic_table/` |
| `src/http1/` | HTTP/1 method handlers, response encoder, status table, error pages |
| `src/parse/` | Request line, headers, path, query, `Range:` |
| `src/file/` | Embedded lookup, MIME detection, `%XX` decode, path-safety checks |
| `src/util/` | `write_all`, `memcpy`, `strlen`, `streqn`, `streqn_i`, `itoa`, `atoi`, `atoi_n` |
| `src/data.S`, `src/defs.S`, `src/config.S` | Shared globals, shared definitions, user configuration |

`src/tls/server/`, `src/tls/record/`, `src/tls/handshake/` and
`src/tls/transcript/` each carry their own `README.md` with the detail this
table compresses.

---

## Startup and the accept loop

`src/sarm/main.S:_main`:

1. If `argv[1]` starts below `'A'` it is parsed as a port (`atoi`, byte-swapped
   into the `sockaddr_in`). A leading letter (`./sarm d`) instead sets the
   `no_fork` debug flag — connections are then served inline in the one
   process, which is what makes `scripts/profile_workload.py` able to attribute
   a whole workload to a single `getrusage`. Because argv[1] is either a port
   or the flag, `no_fork` mode always listens on the default port.
2. `socket` → `setsockopt(SO_REUSEADDR)` → `bind` → `listen(5)`.
3. `SIGCHLD` → `SIG_IGN` with `SA_NOCLDWAIT` so the kernel reaps children and
   nothing ever has to `wait()`; `SIGPIPE` → `SIG_IGN` so `write()` returns
   `EPIPE` instead of killing the process.
4. Loop: `accept` → `fork`.
   - **parent**: `close(clientfd)` and straight back to `accept`. If the fork
     failed it closes the connection and carries on rather than serving it on
     the accept loop, where it could block every later one.
   - **child**: `close(sockfd)` — holding the listening socket open would keep
     the port bound after the parent exits — then arm `SO_RCVTIMEO` and
     `recvfrom(MSG_PEEK, 1)`.
     - `0x16` (TLS handshake record) → `tls_server_handshake(fd)`, then straight
       into `h2_connection_loop` over the now-encrypted transport. There is no
       HTTP/1-over-TLS path.
     - anything else → `child`, unchanged plaintext path.
     - either way, `child_end` closes the fd and `_exit`s. Under `no_fork` it
       branches back to `accept` instead.

Why fork at all: an HTTP/2 connection is persistent, so serving one on the
accept loop would strand every other connection in the listen backlog until it
ended. Browsers routinely open a second connection, and those requests would
simply hang.

The peek is what makes one port serve all three protocols; the byte stays on the
socket, so the chosen path reads it normally.

## The plaintext connection (`src/sarm/child.S`)

`read()` into `buf`; on the first read `h2_probe` tests for the HTTP/2 client
preface prefix. Match → `h2_connection_loop` owns the rest of the connection.
No match → HTTP/1: `parse_header_end` finds `\r\n\r\n` (buffer full → 431, never
completes → 400, `ETIMEDOUT` → 408, peer reset → silent close),
`verify_http_version` (HTTP/1.1 must carry `Host:`; bare `HTTP/` → 505),
`parse_request`, then dispatch on method: GET, HEAD, OPTIONS, `BREW` → 418,
anything else → 501.

## The two protocol-neutral structs

Both protocols converge on fixed-layout globals (field offsets in `defs.S`,
storage in `src/data.S`) — this is what keeps the response machinery shared:

- **`request`** (`REQ_*`) — method id, docroot-prefixed decoded path + length,
  query, authority (`Host:` or `:authority`), stream id (0 for HTTP/1), range
  pointer/length, forbidden flag. Filled by `parse_request` or `h2_build_request`.
- **`response`** (`RESP_*`) — status, content type + length, content length,
  body pointer + length, range start/end (`-1` = none). Filled by
  `create_response`; consumed by `http1_write_response` or
  `h2_write_headers`/`h2_write_body`.

## The transport seam (`src/transport/`)

Every byte in or out of the HTTP/2 engine passes through `transport_read`
(wrapped by `h2_read_exact`) and `transport_write` (wrapped by `write_all`).
They dispatch on the runtime global `transport_mode`:

- `TRANSPORT_PLAIN` — raw `read`/`write` syscalls.
- `TRANSPORT_TLS` — `tls_app_data_read`/`tls_app_data_write`.

The read side stages: one decrypted record rarely matches what the caller asked
for, so plaintext lands in `tls_read_stage_buf` and is doled out across as many
`transport_read` calls as it takes (`tls_read_stage_len`/`_pos`). This seam is
the entire reason TLS could be added without touching the HTTP/2 engine.

## TLS 1.3 (`src/tls/`)

Server-side only, one cipher suite (`TLS_AES_128_GCM_SHA256`), one key exchange
group (X25519), one signature scheme (ECDSA P-256 + SHA-256), ALPN `h2` required.
Wire constants and `tls_state` field offsets are in `defs.S`; the per-connection
`tls_state` block is in `src/tls/data.S` (randoms, key shares, shared secret,
transcript hash, handshake/master secrets, four traffic keys + IVs, sequence
numbers, negotiated ALPN).

`tls_server_handshake` (`src/tls/server/handshake.S`) drives:

```
ClientHello ─► parse + validate (version, cipher, group, ALPN)
            ─► ServerHello (server random, key share)
            ─► X25519 shared secret ─► HKDF key schedule ─► handshake keys
            ─► EncryptedExtensions ─► Certificate
            ─► CertificateVerify  (ECDSA P-256 over the transcript)
            ─► Finished           (HMAC over the transcript)
            ─► application traffic secrets ─► TRANSPORT_TLS
```

The transcript (`src/tls/transcript/`) is a streaming SHA-256 over every
handshake message, snapshot-able mid-flight — CertificateVerify and Finished
each need the hash *as of* their own position. The record layer
(`src/tls/record/`) parses/writes records, derives per-record nonces from the
sequence number, and does AES-128-GCM encrypt/decrypt in place.

Certificates are not parsed: `certs/embed_cert.sh` embeds `cert.der` verbatim
plus the raw 32-byte private scalar. There is no X.509 parser in the server.

## Crypto (`src/crypto/`)

| Module | Notes |
|---|---|
| `sha256/` | ARMv8 SHA-256 extension; streaming `init`/`update`/`final` |
| `hmac.S`, `hkdf/` | RFC 4231 / RFC 5869, plus RFC 8446 §7.1 `hkdf_expand_label` |
| `aes128/`, `gcm/` | ARMv8 Crypto Extensions AESE/AESMC; GHASH via PMULL, 4 blocks per reduction |
| `x25519/` | 51-bit limbs, Montgomery ladder |
| `p256/` | Field arithmetic mod *p*; Solinas folding reduction, unrolled 4×4 product |
| `p256_scalar/` | Arithmetic mod *n*; Montgomery multiply, addition-chain inversion |
| `p256_point/` | Jacobian add/double, generic ladder, and a fixed-base comb for `k*G` |
| `p256_ecdsa/` | Sign, verify, DER encoding |
| `random.S` | `getentropy(2)` on macOS, `getrandom(2)` on Linux |

The arithmetic here is derived and proved by the Python generators in `scripts/`
before it is written as assembly — see [SCRIPTS.md](SCRIPTS.md) and
[HISTORY.md](HISTORY.md). Do not hand-derive changes to these files.

## HTTP/2 (`src/h2/`, `src/hpack/`)

- `h2_connection_loop`: verify the 24-byte preface, send SETTINGS, then loop —
  read a 9-byte frame header → `h2_parse_frame_header` → `h2_validate_frame` →
  read the payload → `h2_dispatch_frame`. Connection errors → GOAWAY; stream
  errors → RST_STREAM; timeout or EOF closes. State lives in `h2_conn` (`H2C_*`).
- Handlers for SETTINGS (+ACK), PING (ACK echoes the 8 octets), GOAWAY, HEADERS,
  DATA, RST_STREAM, PRIORITY, WINDOW_UPDATE.
- Stream engine: fixed 32-entry table (`H2_MAX_STREAMS`), RFC 9113 §5.1 states,
  per-stream flow-control windows (§5.2).
- `h2_build_request` fills the same `request` struct from the decoded HEADERS
  block; `h2_process_request` then resolves and encodes exactly like HTTP/1.
- `h2_write_headers` is the whole response-side HPACK encoder — it builds
  `:status`, content-type/length/range/encoding in literal-with-indexed-name
  form directly into the frame buffer, stamps the frame header, one `write_all`.
- `h2_write_body` chunks DATA to the connection and stream windows; when credit
  runs out it reads and dispatches frames until a WINDOW_UPDATE arrives.
- HPACK decode covers the RFC 7541 static table, Appendix B Huffman
  (`src/h2_huffman_table.S`, generated) and a real bounded dynamic table with
  FIFO eviction; SETTINGS advertises the default 4096-byte table size.

## Request path and safety

`parse_path` → `decode_url` → `check_path_safety` → `check_path_traversal`:

1. `parse_path` scans the first 16 bytes for ` /` or ` *`, copies the path into
   `filename_buf` prefixed with `DOCROOT`, collapses repeated slashes, splits the
   query off at `?`. An empty path becomes `DEFAULT_FILE` for GET/HEAD.
2. `decode_url` does in-place `%XX` decoding and rejects `%00` and truncated
   escapes. It runs **before** the traversal check, so `%2e%2e%2f` is caught.
3. `check_path_safety` requires printable ASCII (0x20–0x7E).
4. `check_path_traversal` rejects a path segment that is exactly `..`.
   `foo..txt` and `...` are fine — dots are only special as a whole segment.

Then `lookup_embedded(path, len)` — a linear scan of the embedded table,
measured at ~7 ns and deliberately left linear (see [HISTORY.md](HISTORY.md)).
A miss is a 404. **There is no filesystem access at request time at all**, which
is the security model's foundation: no symlinks, no `open`, nothing to traverse.

Also enforced: 4096-byte path cap (414), buffer-full-without-terminator (431),
`RECV_TIMEOUT` receive timeout (408).

## Response encoding

`create_response` fills the `response` struct from the embedded entry (content
type from the table, else `get_filetype` on the extension). Then:

- **HTTP/1** — `http1_write_response` builds the header in `header_buf`
  (`RESPONSE_HEADER_SIZE`; overflow → 500): status line from `find_http_code`,
  `Content-Length`, `Content-Range` for 206, `Content-Type`,
  `Content-Encoding: gzip` and `ETag` when the embedded entry has them, then a
  fixed tail (`Connection: close`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `Allow`, `Accept-Ranges`, `Server`). Header and body go out as **one `writev`**.
- **HTTP/2** — `h2_write_headers` + `h2_write_body` as above.
- **Errors** — `reply_status(code, ret)` assembles `ERR_DIR + code + ".html"` and
  looks it up in the embedded table; found → serve that page, otherwise
  header-only.

## The embedded asset model

`embed_www.sh` walks `www/`, picks a MIME type by extension, gzips text-like
files when that makes them smaller (cached in `www_gz/`), computes a SHA-256
`ETag` over the served bytes, and emits `src/embedded.S`: `.incbin` payloads plus
an 80-byte-per-entry table (path ptr/len, content ptr/size, content-type ptr/len,
gzip flag, ETag ptr/len). `make assets` regenerates it whenever `www/` changes.

## Known dead weight

Honest inventory, so nobody spends an afternoon on it:

- `handle_fs_error` (`src/http1/`) has no callers — pre-embedded era.
- `find_http_code`'s table still holds 201/409/411/413/502/503/507 from the
  removed PUT/CGI features; no handler produces them.
- `MAX_PROCS` and `ALLOW_DIR_LISTING` in `config.S` are read by nothing.
- `defs.S` defines syscalls that are never used (`SYS_proc_info`,
  `SYS_getdirentries64`, …) — but *not* `SYS_fork`/`SYS_clone`, which run on
  every connection.
- The `transport_mode` reset at `Lmain_tls_close` (`main.S`) is dead on the
  forked path — the child `_exit`s immediately afterwards — and only does
  anything under `no_fork`. It predates the fork.
