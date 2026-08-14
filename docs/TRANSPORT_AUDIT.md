# HTTP/2 Transport Boundary Audit

Status: **done** (PLAN.MD §1.1 audit; §1.2 transport seam + §1.3 transport
mode implemented — see the addendum at the bottom)
Date: 2026-08-15
`make test`: **passes** (all suites green)

This document records exactly where the HTTP/2 engine reads from and
writes to the client socket, as of the current tree. It is the input
for PLAN.MD §1.2 (transport abstraction): everything below that is a
socket syscall is the boundary that must eventually route through TLS.

## Files inspected

| File | Role |
| --- | --- |
| `src/ymawky/main.S` | accept loop; produces `clientfd` |
| `src/ymawky/child.S` | connection handler; protocol detection; entry into HTTP/2 |
| `src/h2/h2_connection_loop.S` | per-connection HTTP/2 frame loop (read + dispatch) |
| `src/h2/h2_read_exact.S` | the HTTP/2 read primitive (raw `SYS_read`) |
| `src/h2/h2_write_headers.S` | HEADERS response encoder (uses `write_all`) |
| `src/h2/h2_write_body.S` | DATA response encoder (uses `write_all`); credit-wait read loop |
| `src/util/write_all.S` | the HTTP/2 write primitive (raw `SYS_write`) |
| `src/defs.S` | syscall numbers, `SCWINUM`/`SCWISVC`/`SCERR` macros, H2 structs/constants |
| `src/h2/h2_send_settings.S`, `h2_send_goaway.S`, `h2_send_rst_stream.S`, `h2_handle_ping.S`, `h2_handle_goaway.S`, `h2_process_request.S`, `h2_reply_status.S`, `h2_probe.S`, `h2_verify_preface.S` | frame writers / dispatch sites (supporting) |

Note: PLAN.MD §1.1 originally listed `src/ymawky.S`; that file does not
exist (it was the pre-split monolithic server file). The plan now lists
the real entry point `src/ymawky/main.S` and connection handler
`src/ymawky/child.S` — those are the files audited here.

## Where the file descriptor comes from

- `main.S:loop` calls `accept`/`accept4` and stores the result in the
  global `clientfd` (`src/data.S`), then branches to `child` (no fork —
  one connection-per-loop iteration).
- `child` reads the first bytes, probes for the HTTP/2 preface, and
  hands the fd (as `x0`), the buffer, and the buffered byte count to
  `h2_connection_loop`.
- Inside the HTTP/2 engine the fd is threaded explicitly through `x0`/
  `x19` and stored once per connection in `h2_conn` at offset
  `H2C_FD` (used only by the PING-ACK and GOAWAY reply writers that
  fire from `h2_dispatch_frame`, where the fd isn't otherwise in hand).

## Read path (client → server)

```text
main.S:loop  accept() ──> clientfd
    │
    ▼
child.S      setsockopt(SO_RCVTIMEO)            [raw SYS_setsockopt]
    │        raw SYS_read loop into buf[0..x7]   [raw SYS_read — HTTP/1 path,
    │                                             HTTP/2 inherits the bytes]
    │        h2_probe(buf, x7)  — preface prefix? ──no──► HTTP/1 flow
    │
    ▼ (yes)
h2_connection_loop(fd=x0, buf=x1, buffered=x2)
    │
    ├─ preface incomplete?  h2_read_exact(fd, buf+off, 24−buffered)
    ├─ frame header needed? h2_read_exact(fd, buf+off, 9−buffered)
    ├─ payload needed?      h2_read_exact(fd, buf+off, len−buffered)
    ├─ h2_dispatch_frame(header, payload, h2_conn)   (no socket I/O itself)
    └─ stream request complete → h2_process_request(stream_id, fd)
            │
            └─ (response write path — see below)
```

**Read sites — all go through `h2_read_exact`:**

1. `h2_connection_loop.S:93` — finish the 24-byte connection preface
   when the initial probe read came up short.
2. `h2_connection_loop.S:145` — top of the frame loop: guarantee a full
   9-byte frame header is buffered (compact + read).
3. `h2_connection_loop.S:175` — guarantee the full frame payload is
   buffered after the header is parsed.
4. `h2_write_body.S:141` and `:155` — the flow-control credit-wait
   loop: when the send windows are exhausted mid-body, the writer reads
   and dispatches frames (expecting `WINDOW_UPDATE`) until credit
   reopens. Uses the same `h2_read_exact`.

**The read primitive — `h2_read_exact` (`src/h2/h2_read_exact.S`):**
loops raw `SYS_read` (via the `SCWINUM`/`SCWISVC`/`SCERR` macros from
`defs.S`) until exactly `len` bytes arrive; retries `EINTR`; returns
with carry set and `x0 = 0` on EOF or `x0 = errno` on error. There is
**no other read syscall inside the HTTP/2 engine**.

## Write path (server → client)

```text
h2_connection_loop ──► h2_send_settings(fd)            ──► write_all(fd, h2_settings_frame, 21)
                     │
                     ├─► h2_process_request(stream_id, fd)  ──► h2_write_headers(fd, resp, sid, flags)
                     │                                             │       └──► write_all(fd, h2_frame_buf, 9+block)
                     │                                             └──► h2_write_body(fd, resp, sid)
                     │                                                       └──► write_all(fd, h2_frame_buf, 9+chunk)
                     │                                                        (per DATA frame)
                     ├─► h2_send_goaway(fd, code, h2_conn)   ──► write_all(fd, sp, 17)
                     └─► h2_send_rst_stream(fd, sid, code)   ──► write_all(fd, sp, 13)

h2_dispatch_frame (from the loop or the credit-wait loop)
    ├─► h2_handle_ping   — PING ACK ──► write_all(fd=H2C_FD, sp, 17)
    └─► h2_handle_goaway — GOAWAY reply ──► h2_send_goaway ──► write_all
```

**Write sites — all go through `write_all`:**

1. `h2_send_settings.S:54` — the server's opening SETTINGS frame, a
   static 21-byte frame in `.data`; tail-branches into `write_all`.
2. `h2_write_headers.S:232` — one HEADERS frame per write: the 9-byte
   header + HPACK block are assembled into `h2_frame_buf` and written
   in a single `write_all` so a partial write can't split the frame.
   Called from `h2_process_request.S:196` and `h2_reply_status.S:50`.
3. `h2_write_body.S:112` — one DATA frame per write (header + chunk in
   `h2_frame_buf`); called from `h2_process_request.S:203`.
4. `h2_send_goaway.S:62` — 17 bytes built on the stack; write failures
   are ignored (the connection is closing anyway). Called from
   `h2_connection_loop.S:223/:239` and `h2_handle_goaway.S:63` (fd from
   `H2C_FD`).
5. `h2_send_rst_stream.S:55` — 13 bytes on the stack. Called from
   `h2_connection_loop.S:231` and `h2_write_body.S:179`.
6. `h2_handle_ping.S:68` — PING ACK, 17 bytes on the stack; fd comes
   from `H2C_FD`.

**The write primitive — `write_all` (`src/util/write_all.S`):** loops
raw `SYS_write` until all bytes are written; retries `EINTR`; treats
`EPIPE` as a clean exit (carry clear); returns with carry set and
`x0 = errno` on other errors. **There is no other write syscall inside
the HTTP/2 engine.**

## Buffers and state the boundary touches

| Symbol | Location | Purpose |
| --- | --- | --- |
| `buf` (`BUF_SIZE` 16384) | `src/data.S` | shared request/read buffer; `child` fills it, the frame loop reads from it, the credit-wait loop reads into it |
| `h2_frame_header` | `src/h2/data.S` | 16-byte parsed frame header (`H2F_*`) |
| `h2_frame_buf` (`9 + 16384`) | `src/h2/data.S` | outgoing HEADERS/DATA frames (header + payload) |
| `h2_cr_buf` | `src/h2/h2_write_headers.S` | scratch for the content-range header value |
| `h2_conn` (`H2C_*`, 112 bytes) | `src/h2/data.S` | connection state incl. `H2C_FD` |
| `clientfd` | `src/data.S` | global fd — HTTP/1 entry; HTTP/2 receives it by value |

## Findings relevant to §1.2 (transport abstraction)

1. **There are exactly two socket choke points in HTTP/2:** every read
   goes through `h2_read_exact` and every write through `write_all`.
   No HTTP/2 frame code issues `SYS_read`/`SYS_write` directly. The
   abstraction in §1.2 can therefore be as thin as routing those two
   functions (or their call sites) behind `transport_read` /
   `transport_write` without touching any frame logic.
2. **The fd crosses the boundary as a value** (`x0`/`x19`), with one
   copy parked in `H2C_FD` for the dispatch-time reply writers. A TLS
   transport will need per-connection TLS state keyed off the fd (or a
   transport handle in place of the raw fd) — the `H2C_*` struct is the
   natural home.
3. **Stragglers outside the two choke points** (none are in the frame
   engine, but they matter for a complete picture):
   - `child.S:74` issues a raw `SYS_read` to gather the first bytes —
     pre-protocol-detection, shared with HTTP/1. TLS reads will have to
     start here, before the probe.
   - `h2_verify_preface.S` issues its own raw `SYS_read` loop but has
     **no callers** — dead code; the preface check was inlined into
     `h2_connection_loop` via `h2_read_exact`. Left untouched per
     §1.1 ("do not modify behaviour").
   - HTTP/1's writers (`http1_write_response.S` via `writev`,
     `reply_status.S` via raw `SYS_write`) are outside the HTTP/2
     boundary but share `clientfd`; they are out of scope for §1.2.
4. **Buffers are shared with HTTP/1** (`buf`) — a TLS layer will
   decrypt into the same buffer before the frame loop consumes it.
5. `write_all`'s `EPIPE`-as-success and `h2_read_exact`'s
   EOF-carry-set conventions must survive the abstraction — the frame
   loop and credit-wait loop branch on the carry flag after every
   call.

---

## Addendum — PLAN.MD §1.2-§1.3 (transport seam + mode)

Both follow-ups are now in place:

- **§1.2 (transport abstraction)** — `src/transport/transport_read.S`
  and `src/transport/transport_write.S` hold the two choke points; the
  HTTP/2 engine reaches them via `h2_read_exact` (tail-call) and
  `write_all` (tail-call). Finding #1 of this audit is implemented as
  intended — no frame logic changed.
- **§1.3 (TLS-disabled transport mode)** — the seam now dispatches on
  the runtime global `transport_mode` (`src/transport/data.S`),
  initialised from the `TRANSPORT_MODE` compile-time default in
  `config.S` (`TRANSPORT_PLAIN`):
  - `TRANSPORT_PLAIN` — the raw socket path, byte-for-byte the
    behaviour this audit documents.
  - `TRANSPORT_TLS` — a fail-closed stub returning `ENOTSUP` (carry
    set) from both primitives, so a TLS-mode connection can never
    exchange plaintext until the TLS phases land. Nothing sets the
    mode to TLS yet.
  - Covered by `tests/unit/test_transport.c` (default-mode, PLAIN
    roundtrip, and TLS fail-closed suites).
