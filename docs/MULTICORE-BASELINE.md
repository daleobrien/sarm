# Multicore and throughput — what was measured

The measurement record behind `Plan.md`. Machine throughout: Apple Silicon,
12 logical CPUs (6 P-cores, 6 E-cores), macOS 27.0, loopback. Numbers do not
transfer to other hardware, and several of them do not transfer between
*connection counts* on this one — which is the single most important thing in
this file (§4).

`docs/HISTORY.md` has the distilled version. This is where the tables live.

---

## 1. The process model

```
_main
  socket() → SO_REUSEADDR → bind() → listen(128)
  SIGCHLD = SIG_IGN | SA_NOCLDWAIT      # kernel auto-reaps; no wait() anywhere
  SIGPIPE = SIG_IGN
  fork() × (worker_count - 1); the parent becomes the last worker
  │
loop:                                   # one loop per worker, one shared socket
  accept()  ─────────────────────────────────────────────┐
  fork()                                                 │
   ├── parent: close(clientfd); b loop ───────────────────┘
   │
   └── child:  close(sockfd); SO_RCVTIMEO; setitimer(CONN_DEADLINE)
               read() → first byte decides the protocol
               child_end: close; exit(0)
```

A connection child serves **exactly one connection** and then `_exit`s. It
never returns to `accept()`. The per-connection fork is what stops a persistent
HTTP/2 connection from stranding every other connection in the listen backlog,
and it gives each connection a private copy-on-write image of every global —
which is exactly the isolation the single-connection-at-a-time code assumed.

`no_fork` debug mode (`./sarm d`) suppresses that fork and serves inline, so
one process's `getrusage` can be attributed to a whole workload.
`scripts/profile_workload.py` depends on it.

**sarm therefore already ran connections on multiple cores before any of this
work.** Exactly one thing was serialised: the parent's `accept` → `fork` loop.
Concurrency work can only speed up connection *setup*.

---

## 2. Phase 0 — the baseline, and what was wrong with the premise

| Metric | Value at `b3e3150` |
| --- | --- |
| Test suite | 4304 tests, all pass; `make test` 27.1 s |
| Binary, unstripped / stripped | 3,619,128 B / 295,632 B |
| Startup → first `accept()` | median 6.3 ms |
| Single-request latency, HTTP/1.1 | median 0.195 ms (includes a `fork()`) |

Throughput, three runs at `-c50 -t4`, 5 s, `GET /`:

| | HTTP/1.1 | h2c | h2+TLS |
| --- | ---: | ---: | ---: |
| median | 16,433 | 168,554 | 154,595 |
| spread | 5% | 12% | 11% |

**The 10× HTTP/1-to-h2c gap was the fork.** `grep -ri keep-alive src/`
returned nothing: every HTTP/1 response carried `Connection: close`, so `wrk`
(which runs keep-alive) paid a fresh connection and a fresh `fork()` per
request, while `h2load -c50 -m10` paid 50 forks for ~843 k requests.

That also explained a long-standing open item — ~10 k `wrk` socket read errors
per ~90 k HTTP/1 requests, recorded in `docs/HISTORY.md` as "an unexplained
characteristic of the HTTP/1 path". It was `wrk` observing closes it did not
expect.

**Confirmed before acting on it.** The same benchmark against `./sarm d`
(`no_fork`, no fork at all) gave a median of 16,967 req/s against the forked
16,433 — 3.3% apart, inside the 5% noise band. One inline connection-at-a-time
loop and one fork-per-request loop cost about the same, so client-side
ephemeral-port churn was not the limit and the accept+fork loop was.

**The documentation had it wrong, and so did the original plan.** The fork was
reinstated by `2dbbd23` (2026-08-16); the doc set was revised on 2026-08-19
*from the pre-fork mental model*, so `ARCHITECTURE.md` ("one process, one
connection at a time, no fork"), `README.md` ("single process"), `HISTORY.md`,
`SCRIPTS.md` and `CONFIGURATION.md` were each wrong at the time they were
written rather than merely overtaken. All corrected. The original `Plan.md`
inherited the same error — it opened by calling sarm a "single-process,
connection-per-loop server" and told the implementer not to introduce `fork()`.

Two consequences that set the whole plan's shape:

- **HTTP/1 was where the headroom was**, because it was the only workload
  dominated by connection setup.
- **Threads were the wrong primitive.** `fork()` already gives every connection
  a private image of all ~98 mutable globals (§6), so pre-forked worker
  *processes* buy the same multicore benefit with none of that refactor.

---

## 3. Phases 1–3 — what each step changed

**Phase 1, keep-alive (`91363dc`).** A close-rule predicate, `Connection:`
header selection, per-request state reset, pipelined-bytes handling, and a
read/reset loop with a 100-request budget.

| Stage | HTTP/1 | h2c | h2+TLS |
| --- | ---: | ---: | ---: |
| Baseline | 16,433 | 168,554 | 154,595 |
| + keep-alive | **167,822** | 146,817 | 146,231 |

HTTP/1 moved **10.2×**, purely by removing `fork()` from the per-request path.
The h2 columns moved within their own 11–12% noise band.

**Phase 2, syscall reduction.**

| Step | Change | Result |
| --- | --- | --- |
| 7 | `listen(5)` → `listen(128)` | 100 truly-simultaneous connections: 94/100 → **100/100** |
| 8 | Dropped `child.S`'s duplicate `SO_RCVTIMEO` | idle EOF at 10.001 s before and after |
| 9 | Folded the `recvfrom(MSG_PEEK, 1)` into the real first read | −1 syscall per connection on the plaintext path, −3 on the common TLS path |
| 10 | Staged plaintext reads the way TLS reads already were | h2c stops paying a syscall per 9-byte frame header |
| 11 | `writev` for HTTP/2 DATA frames | genuinely zero-copy on `TRANSPORT_PLAIN` |
| 12 | Looped the HTTP/1 `writev` on partial writes | correctness only; latent, not live |

Step 9 corrected two records in passing. A ClientHello from Python's `ssl` or
bare `openssl s_client` appeared to fail the handshake — traced to neither
client sending ALPN by default, which this server correctly requires. And
`child.S`'s `read_failed` routed only `ETIMEDOUT` to the 408 path, while
`SO_RCVTIMEO` expiry reports `EAGAIN` on every platform sarm targets, so a
stalled request got a 500 at the 10 s mark instead of a 408.

Step 11 found a real bug on the way in: `transport_writev`'s `PLAIN` branch
called `raw_writev_all` without saving `x30`, so the return read the same `x30`
again and jumped to itself — an infinite two-instruction loop growing `sp`
until it faulted, surfacing as five suites crashing with `SIGILL`.

**Phase 3, workers. `SO_REUSEPORT` does not distribute on macOS**, and the plan
required proving that before building on it:

| Probe | Result |
| --- | --- |
| 300 sequential connections across 3 `SO_REUSEPORT` sockets | all 300 to the **last socket bound** |
| 400 concurrent connections, 3 workers | all 400 to worker 2; killing it sent all 400 to worker 1 |

A deterministic "last bind wins" failover chain, not load balancing, and macOS
has no `SO_REUSEPORT_LB`. So `SO_REUSEPORT` was never added to `defs.S`.

**One shared listening socket with N workers blocked in `accept()` on it** does
work, with no socket option, no userspace lock and no per-worker descriptor
bookkeeping:

| | Spread across workers | Throughput |
| --- | --- | --- |
| 1 worker | — | 5,043 conn/s |
| 4 workers, shared socket | 128 / 124 / 124 / 124 | **15,449 conn/s (3.1×)** |

`--workers N|auto` defaults to 1, so an unflagged `./sarm` is bit-identical to
the pre-Phase-3 server; `auto` is `sysctlbyname("hw.logicalcpu")` and reports 1
on Linux rather than guessing. `worker_shutdown` handles `SIGTERM`/`SIGINT` in
the forking process only — three raw syscalls, async-signal-safe by
construction — and deliberately does not signal per-connection children, so an
in-flight response finishes. macOS needed its own signal trampoline
(`sig_tramp`), since the Darwin kernel enters userspace at `sa_tramp` rather
than at the handler.

---

## 4. The benchmark lessons

This is the part worth keeping. Three separate times, a measurement said
something about the machine and was read as something about the server.

### 4.1 Connection count is part of the result

sarm runs one process per connection, so `-c50` on a 12-core machine measures
oversubscription. With no code change at all:

| connections | h2c req/s | median latency |
| ---: | ---: | ---: |
| 4 | 282,541 | 214 µs |
| 8 | 250,416 | 473 µs |
| 12 | 184,068 | 1.08 ms |
| 24 | 119,286 | 3.19 ms |
| 50 | 93,334 | 8.89 ms |

`rps_bench.sh` had always defaulted to `-c50`, so **every h2 figure it ever
produced sat deep in this regime** — including the "baseline" this document
quoted for weeks.

### 4.2 The apparent 30% HTTP/2 regression was the benchmark

Phase 2 was reported as having cost ~30% of HTTP/2 throughput, bisected to a
specific commit. That was wrong, and the mistake survived an order-alternating
A/B whose ranges did not overlap — the usual defence against exactly this
error. Two effects produced it:

**Raising the listen backlog changed what `-c50` means.** With a backlog of 5,
50 simultaneous connections cannot all be established: the kernel drops SYNs
and connections trickle in over TCP retries, so much of the run has far fewer
than 50 processes competing. The old, higher numbers were measured at a lower
*effective* concurrency. Two builds differing only in that constant, at `-c12`:
291k/284k (backlog 5) against 180k/184k (backlog 128).

**Past the core count the metric is bimodal.** 6 P-cores and 6 E-cores, and
which cluster the children land on decides the result. Same three builds, same
order, two rounds at `-c12`:

| | round 1 | round 3 |
| --- | ---: | ---: |
| keep-alive | 261,437 | 171,648 |
| syscall work + backlog 5 | 173,077 | 284,129 |

Every build produces both modes, and order-alternation does nothing about it
because the modes are not a function of order.

Measured properly — eight interleaved repeats per build at `-c8`, inside the
core count — the distributions overlap almost completely and HEAD's medians are
within 5% of both other builds, with the *tightest* spread of the three. There
was no regression.

`rps_bench.sh` gained `--repeat N` and now warns when `--connections` exceeds
the machine's logical CPU count, naming the count to compare at instead.

### 4.3 A freshly built binary is slower than an old one

Six interleaved rounds comparing two commits looked like a 2–7% regression in
the first two rounds and nothing after. The `after` binary had just been built
and was paying cold code pages. Alternating the order did not catch it, because
the effect follows the *binary's age*, not its position in the round. What gave
it away was HTTP/1.1 showing the same 2.2% move with a 0.2% spread — and
nothing in the commit under test touches the HTTP/1 path at all.

> **Discard the first round or two after a build, or run enough rounds that
> they cannot set the median.**

### 4.4 The observed noise band is wider than the plan assumed

The plan assumed 5% on HTTP/1 and 12% on HTTP/2. Measured spread reached ±16%
on HTTP/1 and ±30% on h2 at `-c50`. At `-c6` it collapses to under 3%.

---

## 5. Where the throughput went

**Phase 4, Step 19 — the whole sequence.** Each stage rebuilt from its own
commit in a worktree, same certificates, the current `rps_bench.sh` copied in.
Median of three 8 s runs at `-c50 -t4`, ± full spread. **Read the h2 columns as
a measurement of 50 server processes on 12 cores, per §4.1 — not of the
server.**

| Stage | HTTP/1 | h2c | h2+TLS | Binary |
| --- | ---: | ---: | ---: | ---: |
| Baseline (`b3e3150`) | 15,593 (±13%) | 146,087 (±6%) | 160,701 (±10%) | 295,624 |
| + keep-alive (`91363dc`) | **164,150** (±3%) | 153,590 (±19%) | 141,921 (±18%) | 296,104 |
| + syscall work (`467114c`) | 162,832 (±16%) | 85,086 (±10%) | 91,908 (±13%) | 329,592 |
| + 1 worker | 161,690 (±8%) | 90,844 (±3%) | 101,514 (±1%) | 329,800 |
| + 2 workers | 161,650 (±2%) | 94,632 (±30%) | 101,539 (±12%) | 329,800 |
| + 4 workers | 161,931 (±2%) | 92,428 (±6%) | 101,480 (±1%) | 329,800 |
| + 8 workers | 161,584 (±1%) | 95,541 (±3%) | 107,174 (±16%) | 329,800 |

HTTP/1 mean latency: 2.25 ms at baseline, ~230 µs from keep-alive onwards,
unchanged by worker count.

**Keep-alive is the entire HTTP/1 gain** and nothing after it moves HTTP/1 at
all. **Workers do not appear here, and should not**: `wrk` holds 50 keep-alive
connections, so there is almost no connection setup left to parallelise.
Phase 3's gain is a connection *rate* — 5,043 → 15,449 conn/s — which this
benchmark deliberately does not exercise. Workers cost nothing here; that is
not the same as doing nothing.

### 5.1 Is the loopback the limit? No — syscall count is

At 292,600 req/s h2c, `h2load` reports **117.20 MB/s** (~0.97 Gbit/s) serving
the 681-byte `www/index.html`. Loopback on this machine, measured with a C
sender/receiver pair:

| write size | throughput | sends/s |
| ---: | ---: | ---: |
| 681 B | 112 MB/s | 165 k |
| 4 KiB | 639 MB/s | 156 k |
| 64 KiB | 5,997 MB/s | 92 k |
| 1 MiB | 7,510 MB/s | 7 k |

~1.6% of capacity. Note the sends/s column is flat from 400 B to 4 KiB: below
~4 KiB you pay per *message*, and the MB/s column is that fixed rate times the
payload. That harness figure is not a ceiling sarm hits, for two reasons — it
set `TCP_NODELAY` (which sarm sets nowhere; removing it takes the 681 B row to
243 k sends/s), and sarm issued two writes per h2 request at 144,552 req/s on
one connection, ~289 k write syscalls/s, above both harness figures. It was
measuring how fast one receiver gets woken.

`profile_workload.py request` found the real answer: marginal **11.80 µs per
request**, of which **82% is system time**. Four fifths of per-request CPU is
socket syscalls — as a cost inside sarm's own budget, not an external rate
ceiling.

### 5.2 One write syscall per HTTP/2 response (`7ed82bb`)

Acting on that. `h2_write_headers` gained `h2_stage_headers`, which runs the
same encoder but *leaves* the frame in `h2_frame_buf` and returns its length;
`h2_write_body` builds the DATA header immediately behind it, so one
`transport_writev` sends HEADERS + DATA header + body.

Three things bound it: `H2_HEADERS_STAGE_MAX` (256 B) keeps `h2_frame_buf`
able to hold both frames, and a frame above the cap is written on its own; the
flow-control wait path flushes staged bytes *before* waiting, because a nested
`h2_process_request` would re-encode into the same buffer; and
`transport_writev_scratch` grew to 16,672 B for the TLS path's contiguous copy.

**A latent hang found on the way in.** `raw_writev_all` spun forever on an
all-zero-length iovec array: `writev(2)` returns 0, which consumes nothing and
decrements nothing. `h2_write_body`'s terminal empty DATA frame passes exactly
that shape, so **any empty-body HTTP/2 response over plaintext already hung the
connection process at 100% CPU**. It now drops leading zero-length iovecs.

Interleaved, order alternated, `--repeat 3`, 5 s. HTTP/1.1 is the control:

| `-c6 -t4` | before | after | change |
| --- | ---: | ---: | ---: |
| HTTP/1.1 | 109,909 | 109,877 | none (control) |
| HTTP/2 h2c | 306,206 | **459,227** | +50% |
| HTTP/2 + TLS | 255,311 | **414,023** | +62% |

At `-c1 -t1`: h2c +61%, h2+TLS +46%. Every spread 0.0–3.2%, both orderings
agreeing within it.

The profiler confirms the mechanism rather than just the outcome: marginal cost
11.80 → **9.20 µs/request**, system time 21.28 → **16.01 ms** over the sample,
user time barely moving (4.75 → 4.40 ms). Kernel time fell 25% for one fewer
syscall. Syscalls still dominate, at 78%.

### 5.3 Current figures

At `-c6 -t4`, 5 s, median of 3 — a connection count this machine can actually
run:

| | req/s | spread |
| --- | ---: | ---: |
| HTTP/1.1 | 102,714 | ±0.9% |
| HTTP/2 h2c | 303,988 | ±0.8% |
| HTTP/2 + TLS | 263,565 | ±2.1% |

```bash
./scripts/benchmarks/rps_bench.sh --duration 5 --connections 6 --threads 4 --repeat 3
```

The three correctness fixes in `716ada9` — including `aes128_encrypt`'s round
keys leaving `v8`-`v11`, on every TLS record — cost nothing end to end: +0.1%,
+0.8%, +0.1% across the three protocols over six interleaved rounds, and
`aes128_encrypt` alone went 1.296 → 1.285 ns/block.

---

## 6. Process-global mutable state

Every symbol emitted into a writable section across `src/`, machine-enumerated
rather than hand-counted (the original hand pass said "roughly 86" and its own
per-category counts did not add up to its own lists).

| Category | Count | Today (fork) | If workers became threads |
| --- | ---: | --- | --- |
| A — read-only in practice | 241 | Shared, never written | Stays shared |
| B — startup-only server state | 7 | Set pre-fork, then read-only | Stays shared |
| C — connection + request state | 15 | Private via COW | Per-connection |
| D — scratch buffers | 11 | Private via COW | Per-connection |
| E — HTTP/2 + HPACK state | 15 | Private via COW | Per-connection (HPACK dynamic table mandatory) |
| F — TLS + transport state | 45 | Private via COW | Per-connection (~99 KiB; sequence numbers security-critical) |
| G — crypto scratch | 5 | Private via COW | Per-connection or caller-provided |
| H — counters | 0 | — | — |
| **total** | **339** | | **98 mutable** |

**98 writable globals would have to become worker- or connection-local if
workers became threads; zero need to while workers remain forked processes.**
That ratio is the argument for deciding the worker primitive before doing any
state work rather than after.

Category A is no longer merely read-only *in practice*: since the hardening
work it uses the `rodata` macro and is mapped `r--` in the running process
(`docs/SECURITY.md` §13.1).

**No hot-path counters.** Nothing in the request, response or handshake path
increments a global, and nothing should be added to measure this work — the
benchmark measures from outside the process.

**Redo the enumeration rather than trusting the table.** Six commits across
Phases 1–3 added and removed symbols without anyone revisiting it. It is a
twenty-line script, and it is the only thing that keeps the counts honest.

---

## 7. Correctness under concurrency

**`tests/test_multicore.sh`** takes reference bodies over HTTP/1, then has N
concurrent clients re-fetch the same resources over six connection styles —
HTTP/1 single, keep-alive, pipelined, split-write, h2c, and h2-over-TLS — and
compares every response byte for byte. A body of the right length with the
wrong bytes is reported as probable cross-connection leakage, which is the
failure mode the whole worker design has to be innocent of. **50 iterations ×
112 responses = 5,600 responses at `--workers 4`, no intermittent failure.**

Its `stress` mode adds a randomised mixture over all three protocols plus HEAD,
range and missing-file requests, two slow clients trickling headers eight bytes
at a time, two long-lived HTTP/2 connections, and a probe thread timing a fresh
connection twice a second. **13,461 requests over 60 s: no crash, no malformed
response, no hang, and the worst fresh-connection time was 3 ms** — a busy
worker does not block accepts.

The stress client is paced deliberately. Unpaced, the *client* breaks first:
several thousand connections a second exhausts the ephemeral port range, and
every burned port sits in `TIME_WAIT` for 30 s, poisoning the next run.

### The bug it found: macOS drops `SA_NOCLDWAIT` across `fork()`

The first run took the machine's entire process table with it.

`_main` sets `SIGCHLD` to `SIG_IGN` with `SA_NOCLDWAIT` so the kernel reaps
per-connection children. On macOS that flag's effect is a process flag
**`fork()` does not copy to the child**. A pre-forked worker therefore
inherited `SIG_IGN` *without* the auto-reap, and every connection it served
left a zombie.

| | Result |
| --- | --- |
| 300 connections, 2 workers | 151 zombies, all parented to the forked worker |
| sustained load, 3 workers | `fork` starts failing at ~2× the free process slots; the server then accepts connections and closes them unanswered |
| the same load at `--workers 1` | clean |

`--workers 1` forks no workers, which is exactly why every Phase 3 test passed
and why this only appeared under sustained load. Fixed by extracting
`install_sigchld` and calling it in each worker; the harness now asserts no
worker leaves an unreaped child, and that assertion was checked against a
deliberately-created zombie before being trusted.

### Why per-process CPU sampling is useless here

Sampling shows ~4% of one core per worker under HTTP/1 load, which is the
accept-and-fork loop and nothing else. The serving work is invisible to it:
with `HTTP1_KEEPALIVE_BUDGET` at 100, `wrk` reconnects constantly — **2,217
distinct connection children in 3 seconds** — each living ~30 ms. `ps` cannot
sample that, and the client shares the same 12 cores. The child-churn number is
the useful one, and it is a direct measure of what the keep-alive budget costs.
