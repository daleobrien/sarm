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

> **Superseded.** These are Phase 0 figures and neither the HTTP/1 number
> nor its fork model still holds — see
> [2026-08-21 — re-measured at HEAD](#2026-08-21--re-measured-at-head-de62b76)
> at the end of this document.

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


## Phase 3, Step 13 — `SO_REUSEPORT` does not distribute on macOS

Phase 3 as planned was N listening sockets on one port, one per worker,
each with `SO_REUSEPORT`, relying on the kernel to spread accepts across
them. Plan.md required that semantic to be proven before anything was built
on it, because BSD-derived kernels and Linux differ here. It does not hold.

Two throwaway probes, both with three `SO_REUSEPORT` sockets bound to one
port:

| Probe | Result |
| --- | --- |
| 300 sequential connections | all 300 to the **last socket bound** |
| 400 concurrent connections, 3 worker processes | all 400 to worker 2; killing worker 2 sent all 400 to worker 1 |

That is a deterministic "last bind wins" fallback chain — a failover order,
not load balancing. macOS also has no `SO_REUSEPORT_LB` (the FreeBSD option
that *does* balance). `SO_REUSEPORT` was therefore never added to `defs.S`:
nothing in sarm can use it.

### What shipped instead

**One shared listening socket, N workers blocked in `accept()` on it.** The
same probe harness, four workers, 500 connections:

| | Spread across workers | Throughput |
| --- | --- | --- |
| 1 worker (baseline) | — | 5,043 conn/s |
| 4 workers, shared socket | 128 / 124 / 124 / 124 | 15,449 conn/s (3.1×) |

No socket option, no userspace lock, and no per-worker descriptor
bookkeeping. Plan.md Step 13 rules out "a shared accept queue with locks",
and this is not that: the lock it rules out is one in userspace around a
descriptor. Here the kernel's own accept queue hands each connection to
exactly one blocked acceptor — which is the behaviour the per-socket queues
were being bought to imitate in the first place.

## Phase 3, Step 14 — `--workers`

`--workers N` / `--workers auto`, defaulting to **1** so an unflagged
`./sarm` is bit-identical to the pre-Phase-3 server. The existing argv[1] is
overloaded (numeric → port, letter → `no_fork`), so the count is a flag and
`_main` now walks all of argv instead of looking only at argv[1]; the
positional rules are untouched.

`auto` is `sysctlbyname("hw.logicalcpu")` via the raw syscall (`SYS_sysctlbyname`,
274) — 12 on this machine. Linux has no equivalent single call, so `auto`
there reports 1 rather than guessing; an explicit `--workers N` behaves
identically on both. The count is clamped to `[1, MAX_WORKERS]` at parse
time, so every later reader can trust it.

`MAX_WORKERS` (64) replaces `config.S`'s `MAX_PROCS` (256), which was
vestigial: nothing read it, and its comment described a `proc_info()` buffer
in a `sarm.S` that no longer exists. Two similarly-named constants would
have been worse than either.

Verified against a live binary: `4`, `auto`, and `999` (clamped) all serve
200s; `0`, `abc`, and a missing value all exit 1.

## Phase 3, Step 15 — pre-forked accept workers

The socket setup is unchanged. Immediately after `listen`, and after the
signal handlers are installed, the process forks `worker_count - 1` children
and then becomes the last worker itself rather than supervising idly — which
is why `--workers 1` forks nothing at all. `no_fork` debug mode stays
single-process by definition. Each forked pid is recorded in `worker_pids`
for Step 16; nothing `wait()`s on them (`SIGCHLD` is still `SIG_IGN` with
`SA_NOCLDWAIT`).

The **per-connection** fork inside the accept loop is untouched, so the
property it exists for still holds: a persistent HTTP/2 connection is served
by a forked child, leaving its worker free to return to `accept()`. Workers
are processes, not threads, so none of the ~86 writable globals in the Step 3
inventory below needed to become worker-local — the entire old Phase 5/6/12
disappears.

Verified:
- `./sarm 8099 --workers 3` → 3 processes; 60 concurrently-held connections
  landed **23 / 19 / 20** across them, so every worker really does accept.
- `--workers 1` and a bare `./sarm` → one process, as before.
- `--workers auto` → 12 processes on this 12-CPU machine.
- `make test` (4349 assertions + files/security/protocols/keepalive) and
  `tests/h2_browser_sim.py all` against a 4-worker server — both pass.

## Phase 3, Step 16 — shutdown

Before this step, killing the forking process orphaned every worker:
`kill -TERM <parent>` on a 3-worker server left 2 processes alive still
holding the port.

`worker_shutdown` (in `main.S`) now handles `SIGTERM`/`SIGINT`: close the
listening socket, `kill(SIGTERM)` each recorded worker pid, `exit`. Three
raw syscalls, no shared state written — async-signal-safe by construction.

Two things make it simple:

- The handler is installed **only in the forking process, and only after the
  fork loop**. The workers therefore keep the default disposition and just
  die when signalled, and `--workers 1` installs no handler at all.
- The per-connection children are deliberately not signalled — they are not
  in `worker_pids`, so an in-flight response finishes.

macOS needed a signal trampoline of our own (`sig_tramp`, the `sa_tramp`
field of `struct __sigaction`): the Darwin kernel enters userspace at the
trampoline, not the handler, and nothing but libc normally makes the
`sigaction` syscall directly. arm64 Linux needs no equivalent — the kernel
supplies the return path and ignores `sa_restorer`.

Neither `worker_shutdown` nor `sig_tramp` ends in `ret`, so `abi.py` and
`validate_clobbers.py` cannot see where they stop and read on into the code
that follows. Their "x30 never saved" warning is that overrun, not a defect;
it is noted in both header comments.

Verified:
- 5 start/kill cycles alternating `SIGTERM` and `SIGINT` on a 4-worker
  server: zero processes left behind each time, and the port was rebindable
  immediately (each cycle rebound it 0.6 s later and served a 200).
- A keep-alive connection mid-session survived the shutdown and served its
  next request, confirming in-flight children are left alone.
- `tests/test_workers.sh` covers all of the above and runs in `make test`.


## Phase 4, Step 17 — concurrent multi-protocol correctness

`tests/test_multicore.sh` with `tests/multicore_checks.py`. Each iteration
takes its own reference bodies over HTTP/1, then N concurrent clients re-fetch
the same resources over six connection styles — HTTP/1 single, keep-alive,
pipelined, split-write, h2c, and h2-over-TLS — and every response is compared
byte for byte. A body that differs in length is truncation; a body of the right
length with the wrong bytes is reported as probable cross-connection leakage,
which is the failure mode the whole worker design has to be innocent of.

**50 iterations x 112 responses = 5,600 responses at `--workers 4`, no
intermittent failure.**

## Phase 4, Step 18 — randomised mixed workload, and the bug it found

The `stress` mode of the same harness: a randomised mixture over all three
protocols plus HEAD, range and missing-file requests, two slow clients
trickling their request headers eight bytes at a time, two long-lived HTTP/2
connections, and a probe thread timing a *fresh* connection twice a second
throughout.

**13,461 requests over 60 s: no crash, no malformed response, no hang, and the
worst fresh-connection time was 3 ms** — a busy worker does not block accepts.

### The regression it found first: macOS drops `SA_NOCLDWAIT` across `fork()`

The first run of this test took the machine's entire process table with it.

`_main` sets `SIGCHLD` to `SIG_IGN` with `SA_NOCLDWAIT` so the kernel reaps
per-connection children. On macOS the effect of that flag is a process flag
that **`fork()` does not copy to the child**. A worker forked in Step 15
therefore inherited `SIG_IGN` *without* the auto-reap, and every connection it
served left a zombie behind:

| | Result |
| --- | --- |
| 300 connections, 2 workers | 151 zombies, all parented to the forked worker |
| sustained connections, 3 workers | fork starts failing at ~2x the free process slots; the server then accepts connections and closes them unanswered |
| the same load at `--workers 1` | clean — no zombies, no failures |

`--workers 1` forks no workers, which is exactly why every Phase 3 test passed
and why this only appeared under sustained load. Fixed by extracting
`install_sigchld` and calling it in each forked worker; `tests/test_multicore.sh`
now asserts that no worker leaves an unreaped child, and that assertion was
checked against a deliberately-created zombie before being trusted.

### Why the stress client is paced

Unpaced, it is the *client* that breaks first: several thousand connections a
second exhausts the ephemeral port range (`EADDRNOTAVAIL`), and every port
burned sits in `TIME_WAIT` for 30 s, which then poisons the next run. This
script is a correctness test; `rps_bench.sh` is the benchmark.

## Phase 4, Step 19 — the whole sequence, measured

### Method

Each stage was rebuilt from its own commit in a git worktree (`make
production`, same certificates, and the *current* `rps_bench.sh` copied in so
the harness is identical across stages). `--workers` was added to
`rps_bench.sh` for this. Every figure below is the median of three 8-second
runs at `rps_bench.sh`'s default 50 connections / 4 threads, `±` the full
spread.

The machine was not quiet — background load moved during the sweep — so
anything that mattered was re-measured with the stages **interleaved and their
order alternated** between rounds. That controls for drift. It does **not**
control for the two effects described below, which is why the h2 columns of
this table do not mean what they appear to mean: **read the table together
with "The apparent HTTP/2 regression was the benchmark, not the code"**, and
treat the h2c and h2+TLS columns as measurements of a 12-core machine running
50 server processes, not of the server.

### The table

| Stage | HTTP/1 | h2c (saturated) | h2+TLS (saturated) | Binary |
| --- | ---: | ---: | ---: | ---: |
| Baseline (`b3e3150`) | 15,593 (±13%) | 146,087 (±6%) | 160,701 (±10%) | 295,624 |
| + keep-alive, Ph 1 (`91363dc`) | **164,150** (±3%) | 153,590 (±19%) | 141,921 (±18%) | 296,104 |
| + syscall work, Ph 2 (`467114c`) | 162,832 (±16%) | **85,086** (±10%) | 91,908 (±13%) | 329,592 |
| + 1 worker, Ph 3 (HEAD) | 161,690 (±8%) | 90,844 (±3%) | 101,514 (±1%) | 329,800 |
| + 2 workers | 161,650 (±2%) | 94,632 (±30%) | 101,539 (±12%) | 329,800 |
| + 4 workers | 161,931 (±2%) | 92,428 (±6%) | 101,480 (±1%) | 329,800 |
| + 8 workers | 161,584 (±1%) | 95,541 (±3%) | 107,174 (±16%) | 329,800 |

HTTP/1 mean latency: 2.25 ms at baseline, ~230 µs from keep-alive onwards,
unchanged by worker count.

**The observed noise band is wider than Plan.md assumed** (5% HTTP/1, 12%
HTTP/2): HTTP/1 spread reached ±16% and h2 ±30% on this machine. Nothing in the
worker rows is outside it, in either direction.

At a connection count the machine can actually run (`-c8`, eight interleaved
repeats), HEAD serves **255,491 req/s h2c and 207,668 req/s h2+TLS** — above
every h2 figure in the table above, including the baseline row. That is the
number to quote for the server; the column above is the number to quote for
50 concurrent processes on 12 cores.

### Keep-alive is the entire HTTP/1 gain

15,593 -> 164,150 req/s, a 10.5x move, and nothing after it changes HTTP/1 at
all. **Extra workers do not appear in this benchmark, and should not**: `wrk`
holds 50 keep-alive connections, so there is almost no connection setup left to
parallelise. Phase 3's gain is a *connection* rate — 5,043 -> 15,449 conn/s in
the Step 13 probe — and this benchmark deliberately does not exercise it. The
right reading is that workers cost nothing here, not that they do nothing.

### The apparent HTTP/2 regression was the benchmark, not the code

The first pass at this section reported that Phase 2 had cost ~30% of HTTP/2
throughput, bisected to `ffef67b`. **That was wrong, and it is worth recording
why**, because the mistake survived an order-alternating A/B whose ranges did
not overlap — the usual defence against exactly this class of error.

What actually happens:

**1. `-c50` on a 12-core machine measures oversubscription.** sarm runs one
process per connection, so 50 connections is 50 processes plus `h2load`'s own
four threads, all on 12 cores. Throughput falls off monotonically well before
that:

| connections | h2c req/s | median latency |
| ---: | ---: | ---: |
| 4 | 282,541 | 214 µs |
| 8 | 250,416 | 473 µs |
| 12 | 184,068 | 1.08 ms |
| 16 | 152,758 | 1.69 ms |
| 24 | 119,286 | 3.19 ms |
| 32 | 104,494 | 4.64 ms |
| 50 | 93,334 | 8.89 ms |

No code changes between those rows. `rps_bench.sh` has always defaulted to
`-c50`, so every h2 figure it has ever produced sits deep in this regime.

**2. Raising the listen backlog changed what `-c50` means.** Step 7's
`listen(5)` -> `listen(128)` is a correctness fix (5 dropped connections under
a burst: 94/100 succeeded before, 100/100 after). But with a backlog of 5, 50
simultaneous connections cannot all be established at once — the kernel drops
SYNs and the client's connections trickle in over TCP retries, so much of the
run has far fewer than 50 processes competing. The old, higher numbers were
measured at a lower *effective* concurrency. Two builds differing only in that
one constant, at `-c12`: 291k/284k (backlog 5) against 180k/184k (backlog 128).

**3. Past the core count the metric is bimodal.** This machine is 6 P-cores
and 6 E-cores, and which cluster the children land on decides the result. Same
three builds, same order, two rounds at `-c12`:

| | round 1 | round 3 |
| --- | ---: | ---: |
| keep-alive | 261,437 | 171,648 |
| `ffef67b` + backlog 5 | 173,077 | 284,129 |

Every build produces both modes. A single run — or a handful, however
carefully ordered — samples whichever mode it happens to land in, and an
order-alternating A/B does nothing about it because the modes are not a
function of order.

**Measured properly, there is no regression.** Eight repeats per build,
interleaved, at `-c8` (inside the core count, unimodal):

| Build | median h2c | runs |
| --- | ---: | --- |
| Baseline (`b3e3150`) | 252,301 | 239k 241k 244k 249k 256k 257k 281k 289k |
| + keep-alive (`91363dc`) | 264,804 | 222k 227k 242k 264k 266k 286k 286k 296k |
| HEAD | 251,308 | 235k 240k 241k 251k 252k 253k 255k 258k |

The distributions overlap almost completely, HEAD's medians are within 5% of
both others, and HEAD has the *tightest* spread of the three. At `-c8` HEAD
serves **255k h2c and 208k h2+TLS**, both comfortably above the 168k / 154k
this document has been quoting as the baseline all along — those baseline
figures were themselves taken at `-c50` and are not the server's ceiling.

### What changed as a result

`rps_bench.sh` gained `--repeat N` (median of N passes, reported with the full
spread) and prints an explicit warning when `--connections` exceeds the
machine's logical CPU count, naming the connection count to compare at
instead. The lesson is in the header comment: **connection count is part of
the result**, and for a process-per-connection server it is the single most
important part.

No server code was changed. The one real defect Phase 4 found is the
`SA_NOCLDWAIT` zombie bug above, which was fixed.

### CPU utilisation, and why the obvious measurement is useless

Sampling per-process CPU during an HTTP/1 load shows only ~4% of one core per
worker, which is the accept-and-fork loop and nothing else. The actual serving
work is invisible to it: with `HTTP1_KEEPALIVE_BUDGET` at 100 requests, a
connection is closed after 100 requests and `wrk` reconnects, so children turn
over constantly — **2,217 distinct connection children in 3 seconds of load**,
each living ~30 ms. `ps` cannot sample that, and the client shares the same 12
cores as the server, so an absolute utilisation figure would not be
attributable to either. The child-churn number is the useful one, and it is a
direct measure of what the keep-alive budget costs.

## Phase 4, Step 20 — in `make test`

Three stages, one per worker count (`--workers 1`, `2`, `4`), each running 2
correctness iterations plus a 5-second stress run. The soak lengths quoted
above are what the `--iterations` and `--stress-seconds` flags are for and are
run by hand. `tests/test_workers.sh` from Phase 3 runs there too.

---

## 2026-08-21 — re-measured at HEAD (`de62b76`)

Same knobs as the Step 2 baseline table (5 s, 4 threads, path `/`, median of 3,
1 worker), re-run on the current tree so the Phase 0 numbers have an up-to-date
counterpart. Machine unchanged: 12 logical CPUs, not quiet.

At the baseline's 50 connections:

| | req/s | spread | forks | limited by |
| --- | ---: | ---: | --- | --- |
| HTTP/1.1 | 165,479 | ±5.4% | 50 total (one per connection) | per-request syscalls and parsing |
| HTTP/2 h2c | 90,699 | ±20.3% | 50 total | oversubscription — 50 processes on 12 cores |
| HTTP/2 + TLS | 92,177 | ±35.3% | 50 total | oversubscription — 50 processes on 12 cores |

HTTP/1 mean latency 229.6 µs.

The h2 rows carry ±20–35% spread and are not usable for build-to-build
comparison — same effect as in Step 19. At a connection count the machine can
actually run, the spread collapses and the protocol ordering flips:

| (`-c6`) | req/s | spread | forks | limited by |
| --- | ---: | ---: | --- | --- |
| HTTP/1.1 | 102,714 | ±0.9% | 6 total | per-request syscalls and parsing (41.7 µs avg latency) |
| HTTP/2 h2c | 303,988 | ±0.8% | 6 total | per-request syscalls and parsing |
| HTTP/2 + TLS | 263,565 | ±2.1% | 6 total | per-request syscalls and parsing + record crypto |

**Two things in the Phase 0 table no longer hold.** HTTP/1.1's 16,433 req/s and
its "one fork per request" both predate keep-alive (Phase 1) and the pre-forked
accept workers (Phase 3): every protocol now forks once per *connection*, so
the forks column is 50 (or 6) across the board and HTTP/1 is ~10x its Phase 0
figure. And the Phase 0 h2 numbers (169 k / 155 k at `-c50`) are not
reproducible at that connection count on this machine any more; `-c6` is where
h2's real ~3x lead over HTTP/1 shows up.

Reproduce with:

```
./scripts/benchmarks/rps_bench.sh --duration 5 --connections 6 --threads 4 --path / --repeat 3
```

---

## 2026-08-21 — is the loopback the limit? No; syscall count is

Asked of the 303,988 req/s h2c figure above: how much loopback bandwidth is
that, and is the network path the wall? Measured rather than estimated.

### Bandwidth is not remotely the constraint

At 292,600 req/s (a repeat pass), h2load's own counters report **117.20 MB/s**
— 585.99 MB in 5 s, of which 503.68 MB body and 57.20 MB headers (HPACK saving
50.6%), serving the 681-byte `www/index.html`. Scaled to 303,988 req/s that is
~121.8 MB/s, **~0.97 Gbit/s**. HTTP/2+TLS was 97.66 MB/s at 243,808 req/s.

What loopback can do on this machine (C sender/receiver pair, 127.0.0.1,
2 GiB per run):

| write size | throughput | sends/s |
| ---: | ---: | ---: |
| 400 B | 66 MB/s (0.5 Gbit/s) | 164 k |
| 681 B | 112 MB/s (0.9 Gbit/s) | 165 k |
| 4 KiB | 639 MB/s (5.1 Gbit/s) | 156 k |
| 64 KiB | 5,997 MB/s (48.0 Gbit/s) | 92 k |
| 1 MiB | 7,510 MB/s (60.1 Gbit/s) | 7 k |

~0.97 Gbit/s against a ~60 Gbit/s ceiling is **1.6% of capacity**. Loopback has
no wire — it is a copy through the socket buffers — so bytes/s only binds at
megabyte-sized writes. Note the sends/s column is flat from 400 B to 4 KiB: a
10x change in payload with no change in message rate. Below ~4 KiB you pay per
*message*, and the MB/s column is just that fixed rate times the payload.

### The sends/s column is NOT a ceiling sarm is hitting

Two corrections to the obvious reading of that table, both of which matter:

1. **`TCP_NODELAY` inflated the cost.** The harness set it, forcing a wakeup
   and a segment per `send()`. sarm sets it nowhere (`grep -rn NODELAY src` is
   empty). Without it the 681 B row goes 165 k -> **243 k sends/s**.
2. **sarm issues two writes per h2 request, and still beats that number.**
   `h2_write_headers.S:232` (`bl write_all`, HEADERS frame) and
   `h2_write_body.S:123` (`bl transport_writev`, 9-byte DATA header + body as
   one iovec — 681 B is one chunk, well under the 16 KiB frame size). At the
   single-connection rate of **144,552 req/s** (`-c1`, median of 3) that is
   ~289 k write syscalls/s on one socket — above both harness figures.

So the harness was measuring how fast one receiver process gets woken, not a
send ceiling. sarm exceeds it because `h2load -m10` keeps 10 streams in flight:
writes coalesce in the socket buffer and the client drains many per wakeup.

Connection scaling for reference (5 s, median of 3, path `/`):

| connections | HTTP/1.1 req/s | h2c req/s |
| ---: | ---: | ---: |
| 1 | 31,905 (±2.4%) | 144,552 (±2.6%) |
| 2 | 57,373 (±0.2%) | 241,183 (±0.3%) |
| 4 | 101,758 (±2.4%) | 312,970 (±2.1%) |
| 6 | 101,534 (±0.3%) | 307,618 (±0.3%) |
| 8 | 143,758 (±5.3%) | 266,481 (±4.2%) |

### What is actually the limit: 82% of per-request CPU is kernel time

`python3 scripts/profile_workload.py request` — marginal **11.80 us/request**,
fixed 2.672 ms, R^2 0.9997 — with this user/sys split:

| workload size | user | sys | sys share |
| ---: | ---: | ---: | ---: |
| 1000 | 2.90 ms | 11.74 ms | 80% |
| 2000 | 4.75 ms | 21.28 ms | **82%** |

Four fifths of per-request CPU is the socket syscalls. Syscalls dominate as
*cost per call inside sarm's own CPU budget*, not as an external rate ceiling —
nothing outside the process is throttling it.

(That profile runs over TLS with sequential requests, not `-m10` pipelined h2c,
so its 11.80 us marginal is not directly comparable to the ~6.9 us/request
implied by 144,552 req/s on one connection. The sys/user *ratio* is the
transferable part.)

### The lever this points at

Not bandwidth, and not a higher sends/s ceiling — **fewer syscalls per
response**. The concrete one: HEADERS and DATA leave as two separate writes,
while the `transport_writev` at `h2_write_body.S:123` already takes a
two-part iovec. Folding the encoded HEADERS block in as a third part would take
per-request write syscalls from 2 to 1. Same class of change as Phase 2
Steps 11-12, and with an 82% sys share that is where the headroom is.

---

## 2026-08-21 — one write syscall per HTTP/2 response

Acting on the lever identified above: an HTTP/2 GET used to leave in two write
syscalls, a HEADERS frame from `h2_write_headers` and a DATA frame from
`h2_write_body`. It now leaves in one.

### The change

`h2_write_headers` gained a second entry point, `h2_stage_headers`, that runs
the same encoder but *leaves* the finished frame in `h2_frame_buf` and returns
its length instead of writing it. `h2_write_body` takes that length in x3 and
builds the first DATA frame header immediately behind the staged bytes, so its
existing `transport_writev` sends HEADERS + DATA header + body chunk in one
call. `h2_process_request` uses the staged path for GET; HEAD is unchanged
(END_STREAM rides on its HEADERS frame, and there is no body to fold into).

Three things bound it:

- **`H2_HEADERS_STAGE_MAX` (256 bytes, `defs.S`).** A response block is a few
  dozen bytes, but the cap is what lets `h2_frame_buf` hold both frames and
  keeps the TLS path's `transport_writev_scratch` sized. A frame above the cap
  is written on its own and 0 is returned, so the DATA write starts at
  `h2_frame_buf[0]` exactly as before.
- **The flow-control wait path flushes first.** `.Lh2wb_wait` dispatches client
  frames while waiting for WINDOW_UPDATE, and a nested `h2_process_request`
  re-encodes into the same buffer — staged bytes would be destroyed. They are
  written before the wait begins, so a credit-starved response degrades to the
  old two-syscall behaviour instead of corrupting the connection.
- **`transport_writev_scratch` grew** 16416 -> 16672 bytes, for the TLS path's
  contiguous copy of a 256-byte staged frame + 9-byte header + 16 KiB chunk.

### A latent hang found on the way in

`raw_writev_all` spun forever on a trailing zero-length iovec: `writev(2)` on
an all-empty array returns 0, which consumes nothing and decrements nothing, so
the drain loop never terminated. `h2_write_body`'s terminal empty DATA frame
passes exactly that shape (9-byte header, zero-length body), so **any
empty-body HTTP/2 response over plaintext already hung the connection process
at 100% CPU** — the fold only made the shape more common. `raw_writev_all` now
drops leading zero-length iovecs before issuing the syscall. Reproduced with a
3-second alarm around a direct call; the fix returns 9 and exits.

### Measured

Interleaved, order alternated between rounds, `--repeat 3` (median of 3, ± full
spread), 5 s, path `/`. HTTP/1.1 is the control — the change is HTTP/2-only.

Single connection (`-c1 -t1`), the cleanest signal:

| | before | after | change |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 36,342 / 36,350 | 36,344 / 36,382 | none (control) |
| HTTP/2 h2c | 138,163 / 137,893 | 222,335 / 223,348 | **+61%** |
| HTTP/2 + TLS | 121,200 / 120,859 | 176,521 / 176,487 | **+46%** |

Six connections (`-c6 -t4`):

| | before | after | change |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 109,909 / 112,162 | 109,877 / 112,308 | none (control) |
| HTTP/2 h2c | 306,206 / 308,182 | 459,227 / 465,394 | **+50%** |
| HTTP/2 + TLS | 255,311 / 258,111 | 414,023 / 422,916 | **+62%** |

Every spread was 0.0-3.2%, both orderings agree to within it, and HTTP/1.1 sits
still across all of it — so this is the change, not machine drift.

`profile_workload.py request` confirms the mechanism is the one intended:

| | before | after |
| --- | ---: | ---: |
| marginal cost | 11.80 us/request | **9.20 us/request** |
| sys (size 2000) | 21.28 ms | **16.01 ms** |
| user (size 2000) | 4.75 ms | 4.40 ms |
| sys share | 82% | 78% |

Kernel time fell 25% while user time barely moved, which is what removing one
syscall per request should look like. Syscalls still dominate at 78%.

### Tests

`make test` (4,349 unit assertions plus files/security/protocols/keepalive/
workers/multicore at 1, 2 and 4 workers) and `tests/h2_browser_sim.py all` all
pass. The browser simulator matters here specifically: its `no-credit` scenario
drives the wait-path flush, and its 76 KB asset drives the multi-chunk DATA
path where only the first chunk carries staged headers.

## 2026-08-21 — do the correctness fixes cost anything? No

The three fixes in `716ada9` touch two hot paths: `aes128_encrypt`'s round
keys moved out of `v8`-`v11` (every TLS record), and `h2_write_body`'s wait
loop moved off `buf` onto `h2_wait_buf` (every flow-controlled response). The
question is whether either shows up end to end.

Interleaved against `7ed82bb` (the commit before the fixes) in a worktree,
same certs, same harness, `make production` each. Six rounds, order alternated
between rounds, `--repeat 3` inside each, `-c6 -t4`, 5 s, path `/`.

| median of 6 rounds | before (`7ed82bb`) | after (`716ada9`) | change |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 109,422 | 109,542 | +0.1% |
| HTTP/2 h2c | 443,697 | 447,392 | +0.8% |
| HTTP/2 + TLS | 398,985 | 399,411 | +0.1% |

No change on any protocol. `aes128_encrypt` on its own agrees: interleaved,
eight rounds each, 1.296 -> 1.285 ns/block.

**The first two rounds looked like a 2-7% regression, and were not.** The
`after` binary had just been built, so its first two runs paid cold code pages
while the `before` binary had already been exercised:

| round | h2c before | h2c after |
| ---: | ---: | ---: |
| 1 | 444,359 | 425,697 |
| 2 | 440,595 | 412,672 |
| 3 | 441,376 | 448,394 |
| 4 | 447,424 | 449,083 |
| 5 | 446,313 | 448,171 |
| 6 | 443,035 | 446,613 |

Alternating the order did not catch it, because the effect follows the binary's
age rather than the position in the round — the same failure mode as the
"HTTP/2 regression" further down this file, in a new disguise. HTTP/1.1 showed
it too, at 2.2% with a 0.2% spread, which is what gave it away: nothing in
`716ada9` is on the HTTP/1 path at all. **Discard the first round or two after
a build, or run enough rounds that they cannot set the median.**

These figures are also ~4% below the `459,227` / `414,023` recorded in the
section above, measured on a different day. That is drift, not a change: both
binaries were measured here together and agree.

---

## Step 3 — Inventory of process-global mutable state

Every symbol emitted into a writable section (`.data` / `.bss`) across `src/`,
classified. Pure read-only constant tables (string literals, HPACK static
table, `file_types_*`, HTTP status lines, P-256 curve constants, `K256`,
`embedded.S`, `tls/cert_data.S`) are summarised rather than listed
individually — they are 241 of the 339 writable-section symbols, and none is
ever written at run time.

**Re-verified 2026-08-21**, by re-enumerating every label emitted while a
`.data`/`.bss` directive is in effect and diffing the result against the table
below. The original pass landed in `0c8eaea`, and six commits had invalidated
it since without touching this section:

| Commit | Effect on this inventory |
| --- | --- |
| `91363dc` — HTTP/1 keep-alive (Phase 1) | +4 category C (`request_header_len`, `request_total_len`, `request_budget`, `keep_alive_decision`), +6 category A match strings |
| `ffef67b` — fold `MSG_PEEK` into the real first read | −1 category C: `tls_peek_byte` deleted |
| `b7549c6` — stage plaintext reads (Step 10) | +3 category F (`plain_read_stage_buf`/`_len`/`_pos`) |
| `7ed82bb` — one write syscall per HTTP/2 response | +1 category F (`transport_writev_scratch`) |
| `14e65c5` — pre-forked workers (Phase 3) | +3 category B (`worker_count`, `worker_pids`, `worker_pid_count`), +3 category A option strings |
| `716ada9` — three correctness fixes | +1 category E (`h2_wait_buf`) |

Not one of those is a large change, and none of their authors was wrong not to
update a section three phases upstream — which is the point. **Redo the
enumeration rather than trusting this table** whenever a phase adds state; it
is a twenty-line script, and it is the only thing that keeps the table honest.
The counts below are that script's, not the original hand count's.

**Read this list as conditional.** Under fork-per-connection, everything in
categories C–G is already private to one connection, because `fork()` copies
it. The classification is what each object *would* have to become if workers
became threads. Nothing here is a bug today.

### A. Read-only in practice (shared, safe)

Emitted into `.data` (so technically writable) but never stored to.

> **Since 2026-08-23 (`docs/SECURITY.md` Step 13) this whole category is
> read-only in fact, not just in practice.** Everything listed below now uses
> the `rodata` macro in `src/defs.S` — `__DATA_CONST,__const` on Mach-O,
> `.rodata` on ELF — and is mapped `r--` in the running process. The counts
> below still say "writable-section symbols" because they were taken before
> that change; the classification they support (what would have to become
> thread-local) is unaffected, since nothing here is ever written. See
> [security/hardening.md](security/hardening.md).

| Group | Where | Notes |
| --- | --- | --- |
| Embedded content, paths, ETags, content types | `src/embedded.S` | Must stay single-copy (Plan.md "Keep embedded data read-only") |
| TLS certificate DER + private key | `src/tls/cert_data.S` | Shared read-only; per-connection TLS state is category F |
| P-256 constants: `p256_p`, `p256_mu`, `p256_p_minus_2`, `p256_n`, `p256_mu_n`, `p256_n_minus_2`, `p256_gx/gy/b`, `p256_comb_table`, `p256_scalar_inv_chain`, `p256_scalar_n0inv`, `p256_scalar_rr_n` | `src/crypto/p256*/` | |
| SHA-256 round constants `K256`, IV `sha256_h256` | `src/crypto/sha256/data.S` | |
| HPACK static table `h2_hpack_static_table`, `hp_empty` + all `hp_s_*` / `hp_v_*` strings | `src/hpack/h2_hpack_static_lookup.S` | |
| MIME table `file_types_*`, `unknown_ct` | `src/file/get_filetype.S` | |
| HTTP status lines `header_2xx`–`header_5xx`, `status_table` | `src/http1/http_code/data.S` | |
| HTTP/1 header fragments `header_content_length`/`_type`/`_range`/`_encoding`, `header_etag`, `header_tail_close`/`_keep`, `err_dir`, `err_ext` | `src/http1/` | |
| Keep-alive match strings `cl_match_str`, `te_match_str`, `conn_match_str`, `close_match_str`, `ka_match_str`, `http10_match_str` | `src/http1/keep_alive.S` | Added by Phase 1's keep-alive work |
| Match strings: `host_match_str`, `host_str`, `range_match_str`, `bytes_match_str`, `header_end`, `www_prefix`, `default_file`, `h2_preface`, `get_req`/`head_req`/`options_req`/`brew_req`, `http_`, `http_1_0`, `http_1_1` | `src/parse/`, `src/sarm/` | |
| CLI option strings `opt_workers` (`--workers`), `opt_auto` (`auto`), `hw_logicalcpu` (the sysctl name) | `src/sarm/main.S` | Added by `14e65c5`; parsed once at startup |
| TLS key-schedule labels `khs_label_*`, `as_label_*`, `fk_label_finished`, `cv_content_prefix`, `khs_empty_hash`, `x25519_basepoint9`, `tls_alpn_h2` | `src/tls/handshake/`, `src/tls/data.S` | `tls_alpn_h2` sits in `tls/data.S` with the mutable TLS state but is the literal `"h2"`, never written |
| `h2_frame_handlers`, `h2_stream_transitions`, `h2_settings_frame`, `h2_pseudo_*`, `h2_method_*`, `h2_bytes_name`, `h2_range_name`, `h2_gzip_str` | `src/h2/`, `src/h2/settings/` | |
| `one` (the `setsockopt` int) | `src/sarm/data.S` | |

### B. Mutable server state (set once at startup, then read-only)

| Symbol | Where | Notes |
| --- | --- | --- |
| `sockfd` | `src/sarm/main.S` | The listening fd. **Phase 3 (`14e65c5`) settled its ownership the opposite way to what this section originally predicted:** every pre-forked worker inherits and `accept()`s on *one shared* listening socket, rather than each worker getting its own `listen_fd`. It stays a single shared read-only global |
| `addr` | `src/sarm/main.S` | `sockaddr_in`; port patched from argv[1] before `bind` |
| `worker_count` | `src/data.S` | How many accept workers to run. Clamped to [1, `MAX_WORKERS`] at parse time and never written again, so workers read it without re-checking. In `.data` (default `1`) rather than `.bss` because its default is nonzero |
| `worker_pids` | `src/sarm/main.S` | `MAX_WORKERS * 8` = 512 B. **Parent-only**: written before the last fork, read only by the parent's shutdown path. A worker never touches it |
| `worker_pid_count` | `src/sarm/main.S` | How many entries of `worker_pids` are live. Parent-only, same as above |
| `no_fork` | `src/data.S` | Debug flag, set from argv[1] |
| `rcv_timeout` | `src/sarm/child.S` | `struct timeval` for `SO_RCVTIMEO`, never written |

Written before any connection exists, so they stay shared and read-only after
startup under either process model. `worker_pids`/`worker_pid_count` are the
one pair that is not merely read-only-after-startup but *parent-only*: a
threaded worker model would need them to stay the supervisor's, not become
per-worker.

### C. Mutable connection and request state — HTTP/1 and dispatch

| Symbol | Where | Size |
| --- | --- | --- |
| `clientfd` | `src/data.S` | 16 |
| `connection_mode` | `src/data.S` | 8 (`CONNECTION_HTTP1` init) |
| `file_des` | `src/data.S` | 8 (init −1) |
| `resource_type` | `src/data.S` | 16 |
| `embedded_content`, `embedded_ct`, `embedded_ct_len`, `embedded_etag`, `embedded_etag_len`, `embedded_gzip` | `src/data.S` | 16 each — resolved-asset pointers for the request in flight |
| `header_len` | `src/data.S` | 16 |
| `request_header_len` | `src/data.S` | 16 — length of the raw request header in `buf` (Phase 1, Step 3) |
| `request_total_len` | `src/data.S` | 16 — bytes in `buf` at header terminator; the excess is the next pipelined request (Phase 1, Step 5) |
| `request_budget` | `src/data.S` | 16 — requests left on this keep-alive connection (Phase 1, Step 6) |
| `keep_alive_decision` | `src/data.S` | 16 — the close/continue decision the encoder just made (Phase 1, Step 3) |

The last four are the keep-alive work's per-*request* state, and are the
reason `http1_reset_request` exists: within one connection they are already
reset between requests, by one routine, in one auditable place. That routine
is the model for what categories C–G would need at connection granularity
under a threaded worker.

`tls_peek_byte` used to be listed here. It is gone: `ffef67b` replaced the
`MSG_PEEK` protocol probe with a real read into `buf`, and deleted the byte of
scratch along with it.

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

**`itoa_buf` used to be the twelfth entry here, and it is now gone.** It was a
single 20-byte global that `itoa` formatted into and returned a pointer into,
called from every HTTP/1 and HTTP/2 response path — the one object whose call
sites gave no hint that it carried connection-owned data, and so the most
likely source of silent, intermittent, hard-to-attribute corruption under any
threaded worker model. `itoa` now takes the buffer as an argument
(`ITOA_BUF_SIZE` bytes, `x1`) and each of its ten call sites passes stack space
in a frame it already owns — one `add` per call and 32 bytes of frame, no extra
syscalls, no extra memory traffic, no new callee-saved register saved or
restored. **Throughput was not re-measured for it**; the static cost is small
enough to state from the instruction counts, and this file's own benchmark
sections are the standard for what a measured claim looks like. Removing it was
independent of the worker-primitive decision, and it is the one item from this
inventory worth doing before Step 12 rather than after.

The pattern generalises to categories D and G: shared *scratch* — as opposed to
shared connection *state* — is usually convertible to caller-provided storage
one function at a time, with no design commitment, because the caller always
has a frame and the lifetime is always "until the next thing overwrites it".

### E. HTTP/2 connection and stream state

| Symbol | Where | Notes |
| --- | --- | --- |
| `h2_conn` | `src/h2/data.S` | Connection struct — flow-control windows, settings, state |
| `h2_streams` | `src/h2/data.S` | Stream table |
| `h2_frame_header`, `h2_frame_buf` | `src/h2/data.S` | Frame scratch |
| `h2_wait_buf` | `src/h2/data.S` | One *incoming* frame, for `h2_write_body`'s flow-control wait loop. Separate from `h2_frame_buf` precisely because reusing that one destroyed an already-buffered request while a large body waited on window credit — a bug latent over TLS only because the unparsed bytes lived in the TLS stage buffer instead |
| `h2_hpack_fields`, `h2_hpack_str_buf`, `h2_hpack_str_off` | `src/hpack/data.S` | HPACK decode scratch |
| `h2_hpack_dyn_entries`, `h2_hpack_dyn_bytes`, `h2_hpack_dyn_count`, `h2_hpack_dyn_size`, `h2_hpack_dyn_used`, `h2_hpack_dyn_max`, `h2_hpack_dyn_tail` | `src/hpack/dynamic_table/data.S` | **HPACK dynamic table — per-connection by protocol definition (RFC 7541 §2.3.2).** Sharing it across connections does not merely race; it corrupts the compression context and yields wrong header values, not obviously garbled ones |

`h2_wait_buf` is worth reading as a warning about this whole category: the two
frame buffers had to be split because one connection's *own* two uses of the
shared buffer collided. Every entry here has that failure mode waiting at
connection granularity.

### F. TLS and transport state

All of `src/tls/data.S` except the `tls_alpn_h2` literal, all per-connection:

`tls_fd`, `tls_state`, `tls_hs_state`, `tls_client_random`, `tls_server_random`,
`tls_session_id`, `tls_session_id_len`, `tls_sni_hostname`, `tls_alpn`,
`tls_alpn_len`, `tls_client_key_share`, `tls_server_key_share`,
`tls_shared_secret`, `tls_handshake_secret`, `tls_master_secret`,
`tls_client_hs_traffic_secret`, `tls_server_hs_traffic_secret`,
`tls_client_hs_key`/`_iv`, `tls_server_hs_key`/`_iv`,
`tls_client_app_key`/`_iv`, `tls_server_app_key`/`_iv`,
`tls_client_seq`, `tls_server_seq`, `tls_hs_msg_buf` (2 KiB),
`tls_hs_record_buf` (16 448 B), `tls_transcript_ctx` (+ `_state`, `_bitlen`,
`_buf`, `_buflen`), `tls_transcript_hash_field` — 35 symbols, ~18.7 KiB.

Transport layer, `src/transport/data.S`, also per-connection — 10 symbols,
~80.4 KiB:
`transport_mode`, `tls_read_raw_buf` (16 448 B), `tls_read_stage_buf`
(16 384 B), `tls_read_stage_len`, `tls_read_stage_pos`,
`tls_write_record_buf` (16 448 B), `plain_read_stage_buf` (16 384 B),
`plain_read_stage_len`, `plain_read_stage_pos`, `transport_writev_scratch`
(16 672 B).

Four things to carry into Phase 5:

1. **`tls_client_seq` / `tls_server_seq` are AEAD record sequence numbers.**
   Sharing them across concurrent connections is nonce reuse in AES-128-GCM —
   a confidentiality failure, not a correctness annoyance. First thing to make
   connection-local.
2. **TLS + transport state is ~99 KiB of declared bytes per connection**, not
   the ~66 KiB this section first recorded. The difference is Phase 2's
   staging work: `plain_read_stage_buf` and `transport_writev_scratch` are 32
   KiB of buffers that did not exist when the first count was taken. Worth
   knowing before choosing per-worker vs per-connection allocation, since
   there is no heap. Under fork this is copy-on-write and mostly never faulted
   in; under threads it has to be real, statically reserved memory times the
   worker count — and it grew by 50% in one phase, so budget for it growing
   again.
3. **The `no_fork` resets are the shape of the work, and they are already
   scattered across three files.** `main.S`'s `Lmain_tls_close` resets
   `transport_mode`; `tls_server_handshake` resets `tls_client_seq`/
   `tls_server_seq` and the TLS stage buffer; `h2_connection_loop` resets
   `h2_conn`, `h2_streams`, the HPACK dynamic table and the plain stage
   buffer. Each is correct and each carries a comment explaining why. Note
   that `main.S`'s is *not* dead code, despite serving one connection per
   forked child: under `no_fork` the same process accepts again, and the next
   connection may well be plaintext. Taken together they are an unnamed
   `connection_reset` spread over three call sites — the routine a worker
   model has to make explicit, in the way `http1_reset_request` already is at
   request granularity.
4. **Every reset above was found by a bug, not by an audit.** `tls/server/
   README.md` records three handshake bugs — two of them exactly this
   category's failure mode, sequence numbers not reset at an epoch boundary
   and then not reset across connections — and records all three as found by
   driving the real handshake against Python's `ssl` and LibreSSL `curl`,
   after every underlying primitive already passed its unit tests. That is the
   evidence standard this category needs. The inventory is a map, not a
   proof.

### G. Cryptographic scratch

| Symbol | Where | Notes |
| --- | --- | --- |
| `sha256_ctx` (+ `_state`, `_bitlen`, `_buf`, `_buflen`) | `src/crypto/data.S` | **A single process-global streaming SHA-256 context.** Its own header comment describes it as "a fixed-layout global, like `tls_state`" |

A shared crypto scratch object already exists — harmless under fork, unusable
under threads. It is
*separate* from `tls_transcript_ctx`, which carries its own copy of the same
layout, so the TLS transcript is already insulated from general SHA-256 use.
Only the general context is shared. `tls_transcript_ctx` is also the proof that
the caller-provided-context form works here: converting `sha256_ctx` to it is
the same move `itoa` just made in category D, one size up.

`src/crypto/random.S` declares no writable globals (entropy comes from
`getentropy(2)` straight into caller storage), so the RNG needs no work.

### H. Counters / statistics

**No hot-path counters.** Nothing in the request, response, or handshake path
increments a global. "Keep statistics out of the hot path" is satisfied by
construction, and nothing should be added to measure this work — the benchmark
script measures from outside the process.

The one global that counts anything is `worker_pid_count` (category B), and it
counts forks at startup, in the parent, before any connection exists. It is not
a statistic and it is not on any path a connection touches.

---

## Summary for Phase 1

Writable-section symbols, by category (re-enumerated 2026-08-21):

| Category | Count | Today (fork) | If workers become threads |
| --- | ---: | --- | --- |
| A — read-only in practice | 241 | Shared, never written | Stays shared |
| B — startup-only server state | 7 | Set pre-fork, then read-only | Stays shared; `worker_pids`/`_count` stay the supervisor's |
| C — connection + request state | 15 | Private via COW | Per-connection |
| D — scratch buffers | 11 | Private via COW | Per-connection |
| E — HTTP/2 + HPACK state | 15 | Private via COW | Per-connection (HPACK dynamic table mandatory) |
| F — TLS + transport state | 45 | Private via COW | Per-connection (~99 KiB; seq numbers security-critical) |
| G — crypto scratch | 5 | Private via COW | Per-connection or caller-provided |
| H — counters | 0 | — | — |
| **total** | **339** | | **98 mutable** |

**98 writable globals** must become worker- or connection-local if workers
become threads; **zero** need to while workers remain forked processes. That
ratio is still the main argument for deciding the worker primitive before doing
the Phase 5 state work rather than after.

It also moves. The original pass put the figure at "roughly 86" — and its own
per-category counts did not quite add up to its own lists, which is what a hand
count gets you. Six commits across Phases 1-3 then added and removed symbols
without anyone revisiting this section. Treat 98 as today's machine-derived number, not a
fixed cost to plan against: it is a reason to decide the worker primitive
early, while the set is still small enough to enumerate in a script.

Steps 1 and 2 changed no code. Step 3 changed one thing: `itoa` no longer
formats into a process-global buffer (category D above). That was the only
item in this inventory whose fix was both free and independent of the
worker-primitive decision — everything else here waits on Step 12.
