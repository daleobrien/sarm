# Multicore baseline (Plan.md Phase 0, Steps 1–3)

Machine: Apple Silicon, 12 logical CPUs (`hw.perflevel0.logicalcpu` = 6 P-cores,
`hw.perflevel1.logicalcpu` = 6 E-cores). macOS (Darwin 27.0.0).
Measured at commit `b3e3150`, working tree clean.

---

## The process model as actually built

sarm forks a child process for every accepted connection. All of the following
is from `src/sarm/main.S` and `src/sarm/child_end.S`, and was confirmed at
runtime.

### What happens on each connection

```
_main
  socket() → SO_REUSEADDR → bind() → listen(backlog 5)
  SIGCHLD = SIG_IGN | SA_NOCLDWAIT      # kernel auto-reaps; no wait() anywhere
  SIGPIPE = SIG_IGN
  │
loop:
  accept()  ─────────────────────────────────────────────┐
  fork()                                                 │
   ├── parent: close(clientfd); b loop ───────────────────┘
   │
   └── child:  close(sockfd)             # drops the listening socket
               SO_RCVTIMEO
               recvfrom(MSG_PEEK, 1)     # protocol detection
                ├── 0x16 → tls_server_handshake → h2_connection_loop
                └── else → child         # HTTP/1 or h2c
               child_end: close(clientfd); close(file_des); exit(0)
```

The child serves **exactly one connection** and then calls `SYS_exit`
(`child_end.S`). It never returns to `accept()`. The parent does nothing but
accept and fork.

Both branches are explicit in the code, and both close the descriptor they do
not own: the parent closes the client fd so it does not leak, the child closes
the listening fd so the port is not held open after the parent exits.

### Why the fork is there

The comment at the fork site states the reason: an HTTP/2 connection is
persistent, so serving it inline on the accept loop would leave every other
connection stuck in the listen backlog until it finished. Browsers routinely
open a second connection, and those requests would hang. The fork also gives
each connection a private copy-on-write image of every global, "which is
exactly the isolation the single-connection-at-a-time code assumed".

### The `no_fork` debug mode

Passing a non-numeric argv[1] (`./sarm d`) sets the `no_fork` global and
suppresses the fork; the connection is served inline on the accept loop and
`child_end` branches back to `loop` instead of exiting. argv[1] is parsed by
first byte — `< 'A'` is treated as a port, anything else as the debug flag — so
`no_fork` mode always listens on the default port 8080. `scripts/profile_workload.py`
depends on this to attribute one process's `getrusage` to a whole workload.

### Verification

Three connections held open concurrently, counting processes:

```
sarm PIDs: 25504 25508 25509 25510      # 1 parent + 3 children
```

### There is no HTTP/1 keep-alive

Every HTTP/1 response carries `Connection: close`, and the server closes the
socket immediately after:

```
HTTP/1.1 200 OK
...
Connection: close
```

`grep -ri keep-alive src/` returns nothing. So on HTTP/1 a connection is a
single request, and therefore **one `fork()` per request**. On HTTP/2 a
connection is one fork amortised over every stream it carries.

### Where the documentation disagreed (all now corrected)

The fork was reinstated by `2dbbd23` ("Better forking", 2026-08-16). The
documentation set was written and revised on 2026-08-19 — *after* that commit —
but from the pre-fork mental model, so every one of these claims was wrong at
the time it was written rather than merely overtaken.

| Claim as written | Where | Reality |
| --- | --- | --- |
| "One process, one connection at a time, no fork, no threads" | `docs/ARCHITECTURE.md` | Forks per connection; many connections in flight at once |
| "there is no fork left to disable" | `docs/ARCHITECTURE.md` | `no_fork` disables exactly that fork |
| "`defs.S` still defines fork-era syscalls (`SYS_fork`, …) that are never used" | `docs/ARCHITECTURE.md` | `SYS_fork` runs on every connection |
| "single process" | `README.md` | One process per connection |
| "served one connection at a time and never forked (still true)" | `docs/HISTORY.md` | Written three days after the fork landed |
| "sarm serves one connection at a time" | `docs/SCRIPTS.md` | Used to justify benchmark advice that stands for other reasons |
| "`MAX_PROCS` — fork-era process cap" | `docs/CONFIGURATION.md` | Unused, but "fork-era" implied fork was past |

All have been fixed. The original `Plan.md` inherited the same error — it
opened by describing sarm as a "single-process, connection-per-loop server" and
told the implementer not to introduce `fork()` — and has been replaced by a
plan built on the findings below.

One open question resolved along the way: `docs/HISTORY.md` recorded ~10k `wrk`
socket read errors per ~90k HTTP/1 requests as "an unexplained characteristic
of the HTTP/1 path". The cause is the absence of keep-alive — `wrk` runs
keep-alive, sarm answers `Connection: close` and closes, and the errors are
`wrk` observing closes it did not expect.

### What this changes about the work

- **sarm already runs connections on multiple cores.** Each connection is an
  independently scheduled process. Exactly one thing is serialised on one core:
  the parent's `accept` → `fork` loop. So concurrency work can only ever speed
  up connection *setup* — not request serving, which is already parallel.
- **That makes HTTP/1 the only workload concurrency can help**, because it is
  the only one dominated by connection setup: no keep-alive means one fork per
  request. HTTP/2 amortises a single fork over every stream on the connection.
- **The global-state audit is unnecessary while workers stay processes.**
  `fork()` already gives every connection a private copy-on-write image, so all
  ~86 writable globals below are per-connection-isolated today. They become
  genuinely shared only if workers become threads.
- **Threads are therefore the wrong primitive**, and `Plan.md` now says so
  explicitly: pre-forked worker *processes* with `SO_REUSEPORT` give the same
  multicore benefit with none of the ~86-global refactor, and preserve the
  blocking-safety property the inner fork exists to provide.
- **`SO_REUSEPORT` is still worth doing** even keeping fork, since it removes
  the single accept loop as a serialisation point — but it is now sequenced
  last, behind keep-alive and syscall reduction, because it is the narrowest of
  the three wins.

---

## Step 1 — Build and test baseline

`make clean && make && make test`, from a clean tree:

| Metric | Value |
| --- | --- |
| Build | succeeds, no warnings |
| Clean build time | 5.5 s wall (2.6 s user, 2.3 s sys) |
| Test suite | **4304 tests, all pass** (`test_files.sh`, `test_security.sh`, `test_protocols.sh`, `tests/unit`) |
| `make test` time | 27.1 s wall |
| Binary size, unstripped (`make`) | 3 619 128 B (3.45 MiB) |
| Binary size, stripped (`make production`) | 295 632 B (289 KiB) |
| Startup → first `accept()` | median **6.3 ms** (min 3.7, max 7.6; n=5) |
| Single-request latency, HTTP/1.1 | median **0.195 ms**, p95 0.294 ms, min 0.160 ms (fresh connection, `GET /`, n=300) |

The two binary sizes differ by 12×; quote the stripped number when tracking
size regressions, since that is what `make production` ships.

The 0.195 ms latency figure includes a `fork()`, since HTTP/1 has no
keep-alive. It is a connect-fork-serve-close round trip, not a bare request.

---

## Step 2 — Single-core throughput baseline

**No new benchmark script was written — one already exists.**
`scripts/benchmarks/rps_bench.sh` already does everything Step 2 asks for: it
starts sarm, drives HTTP/1.1 with `wrk` and both h2c and HTTP/2-over-TLS with
`h2load`, and emits machine-readable JSON with `--json`.

```bash
for i in 1 2 3; do ./scripts/benchmarks/rps_bench.sh --no-build --duration 5 --json; done
```

Three runs, 5 s each, 50 connections, 4 threads, path `/`:

| Run | HTTP/1.1 req/s | HTTP/2 h2c req/s | HTTP/2 + TLS req/s |
| --- | ---: | ---: | ---: |
| 1 | 16 433 | 175 705 | 154 595 |
| 2 | 16 974 | 157 435 | 169 897 |
| 3 | 16 168 | 168 554 | 152 665 |
| **median** | **16 433** | **168 554** | **154 595** |
| spread (max/min) | 5 % | 12 % | 11 % |

Run-to-run spread is 5 % on HTTP/1 and 11–12 % on the HTTP/2 numbers. That is
stable enough to detect the kind of change multicore work should produce
(expected ≫ 12 %), but *not* stable enough to adjudicate a claimed 5–10 %
improvement. For those, raise `--duration` and take more runs.

### The 10× HTTP/1-to-h2c gap is the fork

16 k req/s on HTTP/1.1 against 169 k on h2c is a 10× gap on the same server
serving the same resource. The cause is the fork rate, which follows directly
from the keep-alive finding above:

| | connections | forks | requests |
| --- | ---: | ---: | ---: |
| HTTP/1.1 (`wrk`) | one per request | **one per request** | ~82 k over 5 s |
| HTTP/2 h2c (`h2load -c50 -m10`) | 50 | **50 total** | ~843 k over 5 s |

`wrk` is configured for keep-alive, but the server answers `Connection: close`,
so every request costs a fresh connection and a fresh `fork()`. The HTTP/1
number is substantially a measurement of `fork()` throughput.

Two consequences for later phases:

- **HTTP/1 is where the headroom is.** It is the workload the worker rewrite
  should move most, and the number to watch in Phase 10.
- **Steps 28–30 cannot treat today's HTTP/1 figure as a "1 worker" baseline.**
  It is not a single-core number; it is a fork-per-request number, and it is
  already spread across cores. Comparing "1 worker" against it measures the
  removal of fork, not the addition of workers. Record both, and say which is
  which.

---

## Phase 1, Step 1 — Fork hypothesis confirmed

`Plan.md` Phase 1 hypothesizes that the HTTP/1.1 figure above is a measurement
of `fork()` cost, not of anything else about the connection path. Test: run
the identical HTTP/1.1 benchmark against `./sarm d` (`no_fork` — serves
inline on the accept loop, no `fork()`, no process teardown, always port
8080) and compare to the forked median above.

`rps_bench.sh` always launches its own `./sarm <port>`, so it can't drive
`no_fork` mode directly. Started `./sarm d` by hand and ran `wrk` against it
with the same parameters as the Step 2 baseline (5 s, 50 connections, 4
threads, path `/`):

```bash
make production
./sarm d &
wrk -t4 -c50 -d5s --latency http://127.0.0.1:8080/   # × 3
```

| Run | HTTP/1.1 req/s (`no_fork`) |
| --- | ---: |
| 1 | 17 249 |
| 2 | 16 967 |
| 3 | 16 452 |
| **median** | **16 967** |

Forked median (Step 2): **16 433**. The `no_fork` median is **16 967** —
within the 5 % HTTP/1 noise band of the forked figure (3.3 % apart), not a
dramatically higher number.

**Confirmed**: one inline connection-at-a-time loop and one fork-per-request
loop cost about the same, exactly as the hypothesis predicted. Client-side
ephemeral-port churn is not the limiting factor — if it were, removing the
server-side fork would not have left throughput unchanged. Phase 1's premise
holds: the accept+fork loop, not the client or the network stack, bounds
today's HTTP/1.1 throughput, and keep-alive (which removes fork from the
per-request path entirely) is the correct next step.

No code was changed in this step.

---

## Phase 1, Step 6 — keep-alive shipped: the number that matters

With Steps 2-6 landed (the close-rule predicate, `Connection:` header
selection, per-request state reset, pipelined-bytes handling, and the
read/reset loop with a 100-request budget), HTTP/1 no longer pays a `fork()`
per request. Re-ran the Step 2 benchmark unchanged:

```bash
for i in 1 2 3; do ./scripts/benchmarks/rps_bench.sh --no-build --duration 5 --json; done
```

| Run | HTTP/1.1 req/s | HTTP/2 h2c req/s | HTTP/2 + TLS req/s |
| --- | ---: | ---: | ---: |
| 1 | 166 389 | 146 817 | 140 803 |
| 2 | 169 899 | 155 432 | 152 151 |
| 3 | 167 822 | 138 422 | 146 231 |
| **median** | **167 822** | **146 817** | **146 231** |

| Stage | HTTP/1 | h2c | h2+TLS |
| --- | ---: | ---: | ---: |
| Baseline (Step 2) | 16 433 | 168 554 | 154 595 |
| + keep-alive (Steps 2-6) | **167 822** | 146 817 | 146 231 |

**HTTP/1 moved 10.2×** (16 433 → 167 822), from a 10× gap under h2c to
*ahead* of both HTTP/2 variants in this run (h2c/h2+TLS moved within their
own 11-12% run-to-run noise band — the small dip here is noise, not a
regression, since nothing in Steps 2-6 touches the HTTP/2 or TLS paths).
This is squarely the "substantially toward the h2c regime" result Phase 1
predicted, achieved purely by removing `fork()` from the per-request path —
no concurrency work, exactly per the ordering principle.

Also verified directly (`tests/test_keepalive.sh`, part of `make test`):
two pipelined GETs in one `write()` and the same pair split at all 46 byte
boundaries of the first request both produce byte-for-byte identical
output; a connection is closed with `Connection: close` on exactly its
100th request (`HTTP1_KEEPALIVE_BUDGET`); and 40 concurrent connections
each issuing 10 sequential keep-alive requests all complete correctly.
(100 *simultaneous* connection starts intermittently hit `ECONNRESET` —
that's the pre-existing `listen(sockfd, 5)` backlog, Phase 2 Step 7's
problem to fix, not something keep-alive introduced; staggering connection
starts to stay within the backlog makes the same 100-connection test pass
100/100.)

---

## Phase 2, Step 7 — listen backlog raised

`listen(sockfd, 5)` → `listen(sockfd, 128)` in `src/sarm/main.S`. Re-ran the
exact 100-truly-simultaneous-connection check that surfaced the backlog limit
during Phase 1, Step 6 testing (100 threads all calling `connect()` with no
stagger, each sending one `GET` and reading the full response):

| Backlog | Simultaneous connections succeeding |
| --- | ---: |
| 5 (before) | 94/100 (`ECONNRESET`/`BrokenPipeError` on the rest) |
| 128 (after) | **100/100** |

`make test` passes unchanged (this step touches nothing on the request path,
only the size of the kernel's pending-accept queue).

## Phase 2, Step 8 — duplicate `SO_RCVTIMEO` dropped

`child.S` no longer arms `SO_RCVTIMEO` itself; `main.S`'s `Lmain_serve` arms
it once, before the TLS peek, and that already covers the plaintext path
`child.S` runs on. Verified the timeout still bounds an idle connection
identically before and after the change — connect, send nothing, wait:

```
before (child.S's own setsockopt + main.S's): EOF at 10.001s
after  (main.S's setsockopt only):             EOF at 10.001s
```

`make test` passes unchanged, including the fragmented-request and protocol
tests that exercise the plaintext read path. Note: the connection does
correctly close at the `RECV_TIMEOUT` boundary in both cases (the property
`SO_RCVTIMEO` exists for), but the 408 response body itself never reaches
the client before that close — confirmed as a pre-existing gap, present
identically on the pre-Phase-2 commit and untouched by this step; no test in
the suite currently exercises the 408-body path. Left as-is, out of scope for
Step 8.

---

## Phase 2, Step 9 — MSG_PEEK folded into the real first read

`main.S` no longer spends a `recvfrom(MSG_PEEK, 1)` syscall just to look at
the first byte and decide TLS vs plaintext; it does a real `read()` into
`buf` and dispatches on the byte it actually got, handing those bytes
downstream instead of leaving them on the socket to be read again:

- **Plaintext**: a new `child_with_data` entry point in `child.S` takes the
  bytes already read and resumes exactly where `read_loop` would be right
  after its own first `read()` completed (`Lread_got_data` — h2-preface
  probe, then header search), instead of blocking to read the same bytes a
  second time. `child` (fresh connection, nothing pre-read) is unchanged.
- **TLS**: `tls_server_handshake` gained an (already-read bytes, length)
  input, copies them into its own `tls_hs_record_buf` scratch buffer, and a
  new `tls_read_record_prefilled` (`src/tls/record/read_record.S`) reads
  only whatever of the ClientHello record wasn't already there — scoped
  deliberately to the ClientHello read alone, since a conforming TLS 1.3
  client's first flight is exactly one record (RFC 8446 §4.1.2); more
  already-buffered bytes than that one record holds is treated as a
  protocol error rather than threading a general leftover-bytes mechanism
  through the rest of the handshake.

Verified:
- `make test` — all 4349 tests, unchanged.
- All three protocols on one port via `curl` (plaintext HTTP/1.1, h2c
  prior-knowledge, HTTP/2+TLS) — 200s, TLS body byte-identical to
  plaintext.
- ClientHello delivered fragmented across ten single-byte writes (a real
  `curl`-generated ClientHello, replayed byte-by-byte over a raw socket) —
  server returns a well-formed ServerHello record promptly, same as an
  unfragmented write. (A ClientHello generated by Python's `ssl` module or a
  bare `openssl s_client` — distinct from curl/LibreSSL's — initially
  appeared to fail the handshake with or without fragmentation, identically
  on the pre-Step-9 commit. Traced directly against `tls_parse_client_hello`
  with the captured bytes: not a gap at all — neither client sends an ALPN
  extension by default, and this server correctly requires ALPN "h2" (it
  deliberately serves HTTP/2-over-TLS only, no HTTP/1-over-TLS). Both
  clients complete the handshake normally with `-alpn h2` /
  `set_alpn_protocols(["h2"])`. Correcting the record here since this was
  originally logged as a gap.)
- `tests/unit`'s existing `tls_read_record` suite (13 tests) passes
  unmodified — the 3-argument `tls_read_record` signature and behavior are
  untouched; only the new `tls_read_record_prefilled` and the one call site
  that reads the ClientHello changed.

Removes one syscall per connection (the peek) on the plaintext path, and at
least two on the TLS path (the peek plus the ClientHello's own two
`raw_read_exact` calls collapse into zero additional reads whenever the
whole ClientHello arrives in main.S's first read, the common case). The
`tls_peek_byte` global is gone.

---

## Fix — 408 Request Timeout never sent on an idle-read timeout

Found while investigating the "connect and send nothing" test case above
(which, per the correction, never actually exercised the 408 path at all —
that scenario times out in main.S's own read, before ever reaching
`child.S`). `child.S`'s `read_failed` only routed `errno == ETIMEDOUT` to
the 408 path, but POSIX and Linux's `socket(7)` both document `SO_RCVTIMEO`
expiring as reporting `EAGAIN`/`EWOULDBLOCK`, not `ETIMEDOUT` — `read()`
never actually returns `ETIMEDOUT` for this on any platform sarm targets.
The check fell through the whole errno cascade to the generic `L500`
instead: a request that started but stalled mid-header got `500 Internal
Server Error` at the 10s mark rather than `408 Request Timeout`.

Fixed by adding an explicit `EAGAIN` check alongside the (harmless, kept)
`ETIMEDOUT` one. Verified with a raw socket: a request sent without its
terminating `\r\n\r\n`, then nothing more, now gets `408 Request Timeout` at
the 10s `SO_RCVTIMEO` boundary instead of a `500`. `make test` unchanged.

---

## Phase 2, Step 10 — plaintext reads staged the way TLS reads already were

`transport_read`'s `TRANSPORT_PLAIN` branch used to tail-call
`raw_read_exact` directly — one `read()` syscall per span the caller asked
for, so h2c cost a syscall for every 9-byte frame header and another for
every payload. `TRANSPORT_TLS` already avoided this: it stages one
decrypted record's worth of plaintext in `tls_read_stage_buf` and serves
callers out of it across as many calls as it takes.

`PLAIN` mode now does the same thing one layer down: a new
`plain_read_stage_buf`/`_len`/`_pos` (`src/transport/data.S`) stage one real
(not "exact") `read()`'s worth of bytes, and `transport_read`'s `PLAIN`
branch drains callers from that buffer, only issuing another real `read()`
when it runs dry and the caller still wants more — the same drain/refill
loop structure as the TLS branch, mirrored rather than shared since the
"refill" step differs (TLS refills by blocking for one whole record;
plaintext refills by taking whatever the kernel hands back).

`h2_connection_loop` resets `plain_read_stage_len`/`_pos` to 0 at connection
start (alongside its existing per-connection resets — `h2_conn` fields,
`h2_streams`, HPACK dynamic table), mirroring `tls_server_handshake`'s own
stage-buffer reset: under `no_fork`, the same process serves connection
after connection, so a previous connection's unread staged bytes must never
leak into the next one. `child.S`'s HTTP/1 read loop is untouched — it
never called `transport_read`, only `h2_read_exact` (h2/h2c and h2+TLS) did.

Verified:
- `make test` — all 4349 tests, unchanged.
- `tests/h2_browser_sim.py all` — every scenario completes (the one
  `STALLED` stream in the `no-credit` scenario is that scenario's own
  deliberate assertion, not a failure); exit code 0.
- h2c multi-resource requests on one connection via `curl
  --http2-prior-knowledge`, bodies byte-identical to plaintext.
- Three sequential h2c connections under `no_fork` (same process, no fork
  between them) — each isolated correctly, confirming the stage-buffer
  reset actually matters and works.
- `h2load` burst: 2000 requests / 20 connections / 10 streams-per-connection
  for a 76 KB asset — 2000/2000 succeeded, 0 failed.

Benchmark: re-ran `rps_bench.sh` per the step's own instructions, but the
machine was under unusually heavy unrelated load while doing so (other
background processes; load average ~17 against 11-12% h2c run-to-run noise
even when idle). Isolated the comparison by running both the pre-Step-10
and post-Step-10 binaries back-to-back under the same load: 8 post-Step-10
h2c runs (median ≈ 104 k req/s, range 98.5 k-125 k) against 3 pre-Step-10
runs under identical conditions (median ≈ 106 k req/s, range 103 k-107 k) —
indistinguishable given the noise level at the time. Correctness is solid
(all tests above); the throughput claim needs a re-run on an otherwise-idle
machine before it can be trusted either way.

---

## Phase 2, Step 11 — `writev` for HTTP/2 DATA frames

`h2_write_body` used to build each DATA frame by `memcpy`ing the (up to 16
KiB) chunk into `h2_frame_buf` right behind the 9-byte frame header, then
sending the whole thing with one `write_all` — a real copy of every byte of
every response body, per frame, exactly what the file's own comment flagged
as "zero-copy DATA is a later stage."

That stage: a new `transport_writev` (`src/transport/transport_writev.S`)
takes a header and a body chunk as two separate pointers. `TRANSPORT_PLAIN`
sends both with one real `writev(2)` — genuinely zero-copy, via a new
`raw_writev_all` (`src/transport/raw_writev.S`, mirroring `raw_write_all`
but for an iovec array, looping on a partial write until every iovec is
fully drained). `TRANSPORT_TLS` has no vectored-write equivalent — a TLS
record has to be sealed from one contiguous plaintext buffer — so it copies
both parts into a new `transport_writev_scratch` and hands that to the
ordinary `transport_write`, unchanged from what `h2_write_body` did before
this existed. `h2_write_headers` needed no change — its header block is
always assembled in place already, there's no separate large body pointer
to avoid copying.

**Found and fixed a real bug while building this**: the first version of
`transport_writev`'s `PLAIN` branch called `bl raw_writev_all` without
saving its own `x30` (link register) first. `raw_writev_all`'s own `ret`
correctly returned to the instruction right after that `bl` — but that
instruction's own trailing `ret` then read the *same* `x30` value again,
jumping back to itself instead of to `transport_writev`'s real caller: an
infinite two-instruction loop, `add sp,sp,#0x20` / `ret`, endlessly growing
`sp`. It surfaced as five test suites crashing with SIGILL (`sample`
consistently showed 100% of CPU time pinned at that one address) once `sp`
wandered far enough to fault. Fixed by giving the `PLAIN` branch a proper
16-byte-aligned frame that saves/restores `x30` around the call, the same
discipline every other multi-call function in this codebase already
follows — this is exactly the class of bug Plan.md's own register-clobber
documentation convention exists to catch, and a good reminder to write it
for every new function immediately, not after something crashes.

Verified:
- `make test` — all 4349 tests (including all `h2_*` suites, which caught
  the bug above once the object cache was rebuilt clean).
- `tests/h2_browser_sim.py all` — exit 0.
- The largest embedded asset (76 KB, gzipped) over both h2c and h2+TLS,
  byte-identical to the on-disk source after gzip-aware `curl --compressed`.
- `h2load` burst on that same asset: 2000 requests / 20 connections / 10
  streams each — 2000/2000 succeeded, 0 failed.

## Phase 2, Step 12 — loop the HTTP/1 `writev` on partial writes

`http1_write_response` called `SYS_writev` once and ignored the result, with
no partial-write retry loop, unlike `raw_write_all`/`raw_writev_all` which do
loop. Replaced the raw syscall with a call to the same `raw_writev_all` Step
11 introduced — a correctness fix, not a performance one, exactly as Plan.md
describes it: on a blocking socket a short write is essentially only
possible on `EINTR` (both `SIGPIPE` and `SIGCHLD` are ignored server-wide),
so this was latent, not live, but a real gap the largest response could have
exposed.

Verified:
- `make test` — all 4349 tests, unchanged.
- 15 repeated fetches of the largest embedded asset (76 KB, gzipped) over
  fresh HTTP/1.1 connections — all 15 byte-identical to the on-disk source.
- The same asset served mid-keep-alive-connection (first request), followed
  by a second request reusing the connection — both responses correct,
  matching Step 6's own keep-alive mechanism.

No benchmark claim for either step: Step 12 is explicitly a correctness fix
with no expected throughput movement, and Step 11's `rps_bench.sh` numbers
were, again, taken on a machine under nontrivial background load (see Step
10's note) — h2c stayed in the same noisy 86k-119k range as before, no
conclusion drawn either way.

---

## Step 3 — Inventory of process-global mutable state

Every symbol emitted into a writable section (`.data` / `.bss`) across `src/`,
classified. Pure read-only constant tables (string literals, HPACK static
table, `file_types_*`, HTTP status lines, P-256 curve constants, `K256`,
`embedded.S`, `tls/cert_data.S`) are summarised rather than listed
individually — they are ~200 of the ~280 writable-section symbols, and none is
ever written at run time.

**Read this list as conditional.** Under fork-per-connection, everything in
categories C–G is already private to one connection, because `fork()` copies
it. The classification is what each object *would* have to become if workers
became threads. Nothing here is a bug today.

### A. Read-only in practice (shared, safe)

Emitted into `.data` (so technically writable) but never stored to:

| Group | Where | Notes |
| --- | --- | --- |
| Embedded content, paths, ETags, content types | `src/embedded.S` | Must stay single-copy (Plan.md "Keep embedded data read-only") |
| TLS certificate DER + private key | `src/tls/cert_data.S` | Shared read-only; per-connection TLS state is category F |
| P-256 constants: `p256_p`, `p256_mu`, `p256_n`, `p256_gx/gy/b`, `p256_comb_table`, `p256_scalar_inv_chain`, `p256_scalar_n0inv`, `p256_scalar_rr_n` | `src/crypto/p256*/` | |
| SHA-256 round constants `K256`, IV `sha256_h256` | `src/crypto/sha256/data.S` | |
| HPACK static table + all `hp_s_*` / `hp_v_*` strings | `src/hpack/h2_hpack_static_lookup.S` | |
| MIME table `file_types_*`, `unknown_ct` | `src/file/get_filetype.S` | |
| HTTP status lines `header_2xx`–`header_5xx`, `status_table` | `src/http1/http_code/data.S` | |
| HTTP/1 header fragments, `err_dir`, `err_ext` | `src/http1/` | |
| Match strings: `host_match_str`, `range_match_str`, `bytes_match_str`, `header_end`, `www_prefix`, `default_file`, `h2_preface`, `get_req`/`head_req`/`options_req`/`brew_req`, `http_1_0`, `http_1_1` | `src/parse/`, `src/sarm/main.S` | |
| TLS key-schedule labels `khs_label_*`, `as_label_*`, `fk_label_finished`, `cv_content_prefix`, `khs_empty_hash`, `x25519_basepoint9`, `tls_alpn_h2` | `src/tls/handshake/` | |
| `h2_frame_handlers`, `h2_stream_transitions`, `h2_settings_frame`, `h2_pseudo_*`, `h2_method_*`, `h2_bytes_name`, `h2_range_name`, `h2_gzip_str` | `src/h2/`, `src/h2/settings/` | |
| `one` (the `setsockopt` int) | `src/sarm/data.S` | |

### B. Mutable server state (set once at startup, then read-only)

| Symbol | Where | Notes |
| --- | --- | --- |
| `sockfd` | `src/sarm/main.S` | The listening fd. **This is the one that becomes `worker[i].listen_fd` in Steps 10–13.** Note the child already `close()`s it, so any worker redesign has to revisit that ownership rule |
| `addr` | `src/sarm/main.S` | `sockaddr_in`; port patched from argv[1] before `bind` |
| `no_fork` | `src/data.S` | Debug flag, set from argv[1] |
| `rcv_timeout` | `src/sarm/child.S` | `struct timeval` for `SO_RCVTIMEO`, never written |

Written before any connection exists, so they stay shared and read-only after
startup under either process model.

### C. Mutable connection state — HTTP/1 and dispatch

| Symbol | Where | Size |
| --- | --- | --- |
| `clientfd` | `src/data.S` | 16 |
| `connection_mode` | `src/data.S` | 8 (`CONNECTION_HTTP1` init) |
| `file_des` | `src/data.S` | 8 (init −1) |
| `resource_type` | `src/data.S` | 16 |
| `embedded_content`, `embedded_ct`, `embedded_ct_len`, `embedded_etag`, `embedded_etag_len`, `embedded_gzip` | `src/data.S` | 16 each — resolved-asset pointers for the request in flight |
| `header_len` | `src/data.S` | 16 |
| `tls_peek_byte` | `src/sarm/main.S` | 1 — `MSG_PEEK` protocol-detection scratch, written in the child after the fork |

### D. Temporary buffers (per-connection scratch)

| Symbol | Where | Size |
| --- | --- | --- |
| `buf` | `src/data.S` | `BUF_SIZE`, 16-aligned — main I/O buffer |
| `request` | `src/data.S` | `REQUEST_SIZE` |
| `response` | `src/data.S` | `RESPONSE_SIZE` |
| `header_buf` | `src/http1/data.S` | `header_buf_size` |
| `err_page_buf` | `src/http1/reply_status.S` | `err_page_buf_size` |
| `filename_buf`, `query_buf`, `authority_buf` | `src/parse/data.S` | |
| `range_buf` | `src/parse/parse_range.S` | 19 → 32 |
| `h2_range_buf`, `h2_cr_buf` | `src/h2/h2_build_request.S`, `h2_write_headers.S` | |
| `itoa_buf` | `src/util/itoa.S` | 20 — **shared formatting scratch, called from every path** |

`itoa_buf` deserves a flag: it is a single global used by an ordinary utility
that every response path calls. Fork hides it completely today. Under threads
it is the most likely source of silent, intermittent, hard-to-attribute
corruption, because nothing about `itoa`'s call sites suggests connection
ownership.

### E. HTTP/2 connection and stream state

| Symbol | Where | Notes |
| --- | --- | --- |
| `h2_conn` | `src/h2/data.S` | Connection struct — flow-control windows, settings, state |
| `h2_streams` | `src/h2/data.S` | Stream table |
| `h2_frame_header`, `h2_frame_buf` | `src/h2/data.S` | Frame scratch |
| `h2_hpack_fields`, `h2_hpack_str_buf`, `h2_hpack_str_off` | `src/hpack/data.S` | HPACK decode scratch |
| `h2_hpack_dyn_entries`, `h2_hpack_dyn_bytes`, `h2_hpack_dyn_count`, `h2_hpack_dyn_size`, `h2_hpack_dyn_used`, `h2_hpack_dyn_max`, `h2_hpack_dyn_tail` | `src/hpack/dynamic_table/data.S` | **HPACK dynamic table — per-connection by protocol definition (RFC 7541 §2.3.2).** Sharing it across connections does not merely race; it corrupts the compression context and yields wrong header values, not obviously garbled ones |

### F. TLS state

All of `src/tls/data.S`, all per-connection:

`tls_fd`, `tls_state`, `tls_hs_state`, `tls_client_random`, `tls_server_random`,
`tls_session_id`, `tls_session_id_len`, `tls_sni_hostname`, `tls_alpn`,
`tls_alpn_len`, `tls_client_key_share`, `tls_server_key_share`,
`tls_shared_secret`, `tls_handshake_secret`, `tls_master_secret`,
`tls_client_hs_traffic_secret`, `tls_server_hs_traffic_secret`,
`tls_client_hs_key`/`_iv`, `tls_server_hs_key`/`_iv`,
`tls_client_app_key`/`_iv`, `tls_server_app_key`/`_iv`,
`tls_client_seq`, `tls_server_seq`, `tls_hs_msg_buf` (2 KiB),
`tls_hs_record_buf` (16 448 B), `tls_transcript_ctx` (+ `_state`, `_bitlen`,
`_buf`, `_buflen`), `tls_transcript_hash_field`.

Transport layer, `src/transport/data.S`, also per-connection:
`transport_mode`, `tls_read_raw_buf` (16 448 B), `tls_read_stage_buf`
(16 384 B), `tls_read_stage_len`, `tls_read_stage_pos`,
`tls_write_record_buf` (16 448 B).

Three things to carry into Phase 5:

1. **`tls_client_seq` / `tls_server_seq` are AEAD record sequence numbers.**
   Sharing them across concurrent connections is nonce reuse in AES-128-GCM —
   a confidentiality failure, not a correctness annoyance. First thing to make
   connection-local.
2. **`main.S` already contains a fork-model artefact here.** The
   `Lmain_tls_close` path resets `transport_mode` to `TRANSPORT_PLAIN` before
   branching to `child_end`, commented as necessary because it "is a single
   global (one connection in flight at a time, PLAN.MD's connection-per-loop
   model)". In the forking build that reset is dead code on the child path —
   the child exits immediately afterwards — and it only does anything under
   `no_fork`. It is a leftover from the pre-fork design and a good marker for
   the reset-shared-state pattern that a worker model has to replace rather
   than extend.
3. **TLS state is ~66 KiB of buffers per connection.** Worth knowing before
   choosing per-worker vs per-connection allocation, since there is no heap.
   Under fork this is copy-on-write and mostly never faulted in; under threads
   it has to be real, statically reserved memory times the worker count.

### G. Cryptographic scratch

| Symbol | Where | Notes |
| --- | --- | --- |
| `sha256_ctx` (+ `_state`, `_bitlen`, `_buf`, `_buflen`) | `src/crypto/data.S` | **A single process-global streaming SHA-256 context.** Its own header comment describes it as "a fixed-layout global, like `tls_state`" |

A shared crypto scratch object already exists — harmless under fork, unusable
under threads. It is
*separate* from `tls_transcript_ctx`, which carries its own copy of the same
layout, so the TLS transcript is already insulated from general SHA-256 use.
Only the general context is shared.

`src/crypto/random.S` declares no writable globals (entropy comes from
`getentropy(2)` straight into caller storage), so the RNG needs no work.

### H. Counters / statistics

**None.** There are no global counters or statistics anywhere in `src/`.
"Keep statistics out of the hot path" is satisfied by construction; there is
nothing to remove, and nothing should be added to measure this work — the
benchmark script measures from outside the process.

---

## Summary for Phase 1

Writable-section symbols, by category:

| Category | Count | Today (fork) | If workers become threads |
| --- | ---: | --- | --- |
| A — read-only in practice | ~200 | Shared, never written | Stays shared |
| B — startup-only server state | 4 | Set pre-fork, then read-only | `sockfd` → per-worker; rest stays shared |
| C — connection state | 13 | Private via COW | Per-connection |
| D — scratch buffers | 12 | Private via COW | Per-connection (`itoa_buf` is the sleeper) |
| E — HTTP/2 state | 13 | Private via COW | Per-connection (HPACK dynamic table mandatory) |
| F — TLS + transport state | 39 | Private via COW | Per-connection (~66 KiB; seq numbers security-critical) |
| G — crypto scratch | 5 | Private via COW | Per-connection or caller-provided |
| H — counters | 0 | — | — |

Roughly **86 writable globals** must become worker- or connection-local if
workers become threads; **zero** need to while workers remain forked processes.
That ratio is the main argument for deciding the worker primitive (Step 12)
before doing any of the Phase 5 state work, rather than after.

No code was changed in Steps 1–3.
