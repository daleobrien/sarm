# sarm — resource limits under attack

Step 12 of the programme in [docs/SECURITY.md](../SECURITY.md), whose whole
text is four words and a sentence:

> **Attack:** connections, handshake state, buffers, CPU.
> **Test:** resource use remains bounded.

Steps 6–9 asked what the parsers *do* with hostile bytes. This one asks what
they *cost*. The two questions come apart: a server can answer every malformed
input exactly right and still fall over, because answering was the expensive
part, or because the client never stopped asking.

The harness is [`tests/test_limits.sh`](../../tests/test_limits.sh) and
[`tests/limit_checks.py`](../../tests/limit_checks.py), 49 checks in about 25
seconds, run by `make test`. Unlike Steps 2–9 it does not live in
`tests/security/` — like the secret-leak probe (Step 10) and the syscall
allowlist (Step 11), what it measures is a property of a *running process*
rather than of a function, so it sits in `tests/` with the other live-server
harnesses. See [leak-and-containment.md](leak-and-containment.md) for the same
argument made about those two.

This step is not purely a test. It found the two things
[threat-model.md](threat-model.md) §8 had already named as unbounded and
deferred here — no cap on total handshake duration, no cap on how long a slow
client may hold a process — and closed both with one mechanism. §3 is that
change; §§4–7 are the campaigns; §8 is the sabotage table; §9 is what is still
not bounded, and why that is a decision rather than an oversight.

---

## 1. What "bounded" has to mean here

`sarm` forks one process per connection. That is the structural mitigation the
threat model leans on hardest — a corrupted parsing buffer or key schedule
cannot be observed by another connection, and a crash costs one connection
rather than the server — and it is also what sets the shape of every resource
question. The unit of resource use is not a buffer or an allocation. It is a
process:

```
one connection = one process = one fd + one page table + one resident image
                                     + one slot in the OS process table
```

So the four attacks in the step text land on the same three numbers:

| The attack | What it tries to grow | The number that has to be bounded |
|---|---|---|
| connections | how many processes exist at once | processes × their resident size |
| handshake state | how long one process lives | seconds one client may hold one |
| buffers | how big one process is | resident KB per process |
| CPU | how much work one packet buys | CPU seconds per connection |

Every check in the harness is a measurement of one of those four, compared
against a ceiling named as a constant at the top of `limit_checks.py`. Raising
one of those constants to make a test pass is a change to the threat model, and
this document is where it would have to be argued.

---

## 2. Every check states its own non-vacuity

The failure mode a resource test is most prone to is passing by measuring
nothing. "The connection was closed in time" passes trivially if the connection
was never opened; "the malformed handshake was cheap" passes trivially if the
well-formed one was cheap too; "resident size did not grow" passes trivially if
the sampler never saw a process.

So each campaign carries a check whose job is to fail when the attack stops
reaching its target:

| Campaign | The claim | The check that keeps it honest |
|---|---|---|
| connections | idle clients are reclaimed | *each held connection costs exactly one child* — there were N children to reclaim |
| deadline | the drip is stopped at `CONN_DEADLINE` | *the drip outlived `RECV_TIMEOUT` on the way there* — the receive timeout did not do it |
| deadline (TLS) | the handshake is bounded | *the handshake really started* — the server sent its flight |
| buffers | resident size does not grow | *the sampler saw the server's children* — with a sample count |
| cpu | rejection is cheaper than a handshake | *a well-formed handshake completes*, *the truncated key_share is rejected*, and *a complete handshake is measurably expensive* |

`limit_checks.py --self-test` runs before any of them and checks the
instruments themselves: that `children_of` finds a known child and reads a
non-zero RSS, that it finds *no* children of a pid that has none, that
`cpu_seconds` advances for a busy process, and that a ClientHello can be
captured and corrupted at the byte the campaign means to corrupt.

---

## 3. The change this step made: `CONN_DEADLINE`

### 3.1 What was unbounded

Before this step the only time limit in the server was `RECV_TIMEOUT` = 10 s,
set as `SO_RCVTIMEO` on the connected socket. It bounds **one `read()`**.
Nothing bounded how many times a client could restart it. Measured on the tree
as it stood, with one byte sent every 4 seconds:

```
t=  4.0s byte=0 children=1
t=  8.1s byte=1 children=1
...
t= 32.3s byte=7 children=1     ← still holding, indefinitely
```

The same attack has three shapes, one per protocol the server speaks, and the
third one the protocol actively invites:

* **HTTP/1** — a request header delivered a byte at a time. The header is never
  complete, so the read loop never leaves.
* **h2c** — the preface, then a frame header delivered a byte at a time.
* **TLS** — a real ClientHello, then `change_cipher_spec` records forever. RFC
  8446 Appendix D.4 requires a server to tolerate these for middlebox
  compatibility and sets no limit on how many, so this is not a malformed
  input: it is the protocol asking the server to wait. Measured at 30 s and
  still holding, with 10 six-byte records sent. Recorded as observation 14 in
  the threat model, and deferred to here.

Each held connection is a process. 160 KB resident, one descriptor, one process
slot, for as long as the attacker cares to dribble.

### 3.2 The bound

One syscall, in one place:

```asm
Lmain_child:
    // (the listening socket is closed here — it belongs to the parent)

    SCWINUM SYS_setitimer
    mov x0, #ITIMER_REAL
    adr_l x1, conn_deadline
    mov x2, #0                  // no interest in the previous value
    SCWISVC
```

`conn_deadline` is a static `struct itimerval` with a zero interval and
`it_value.tv_sec = CONN_DEADLINE` (`src/config.S`, default 120 s), so the timer
is one-shot. `SIGALRM` keeps its default disposition — no handler is installed
— which means expiry terminates the process, and terminates it *without a core
dump*. That last part matters: a core dump of this process is a complete
memory disclosure including the private scalar (`docs/SECURITY.md` §10), so
"terminate" and "terminate quietly" are not the same requirement. The harness
checks for cores at the end of every run.

Three properties follow from where it is armed rather than from what it does:

* **In `Lmain_child`, not `Lmain_serve`.** `Lmain_serve` is also how `no_fork`
  debug mode serves a connection inline, and an alarm there would kill the
  server rather than a connection. In `Lmain_child` one process is one
  connection, so an expiry costs exactly the connection that earned it.
* **After the `fork`, so workers never carry it.** An accept worker sits in
  `accept()` indefinitely by design.
* **Nothing branches on the result.** A `setitimer` that failed would leave the
  connection served without its ceiling, which is strictly better than
  refusing to serve it.

The cost is one syscall per connection and no per-read work at all — the kernel
does the counting.

Verified on both platforms, because the syscall number is not the same one:
`setitimer` is 83 on macOS and 103 on Linux/arm64, and `struct itimerval` is
two `struct timeval`s whose `tv_usec` is 32-bit on macOS and 64-bit on Linux —
16 bytes either way, which is why the `.quad` pairs lay out identically and why
`rcv_timeout` already used the same trick. A short-deadline Linux build in the
project's Alpine container drops a drip-fed HTTP/1 connection at 6.3 s against
a `CONN_DEADLINE` of 6.

### 3.3 What it is not

It is a **ceiling**, not a policy. `RECV_TIMEOUT` still does the ordinary work
of dropping idle clients after 10 s with a 408, and the keep-alive budget
(`HTTP1_KEEPALIVE_BUDGET` = 100 requests) still bounds a well-behaved
connection's reuse. `CONN_DEADLINE` only decides the case those two do not
cover: a client that is neither idle nor finished. At 120 s it is far outside
anything a browser fetching static assets does, and nginx's `keepalive_time`
is the same idea with a longer default.

It also does not distinguish a slow attacker from a slow network. A client on a
very bad link, mid-transfer at 120 s, loses the connection. For a static file
server whose largest embedded asset is measured in kilobytes, that trade is
easy; for a server streaming large bodies it would not be, and the constant is
in `config.S` for that reason.

### 3.4 The syscall allowlist changed with it

`setitimer` is the first timer in the tree and had to be added to
`tests/syscall_allowlist.txt`. Step 11's audit caught it before the test did:

```
✗ source: SYS_setitimer is called from src/sarm/main.S:799
          but is not on the allowlist
✗ binary: syscall setitimer (83) at 0000000100009a54 is not on the allowlist
```

Both halves — the `SCWINUM` site in the source and the `svc` in the linked
binary — which is what that audit is for. Adding the line is a change to
[threat-model.md](threat-model.md) §6, and it is made there too.

---

## 4. Campaign `connections`

N clients (48 by default) connect, send one byte, and go quiet. Each costs a
forked child.

```
✓ all 48 concurrent connections were accepted
✓ each held connection costs exactly one child (48 children for 48 connections)
✓ no child exceeds 1024 KB resident (peak 160 KB)
✓ every child costs the same (160-160 KB, spread 0 KB)
✓ a real request is still served while 48 connections are held
✓ every idle connection is reclaimed within RECV_TIMEOUT+8s (0 children left)
```

The interesting rows are the last three. *Every child costs the same* is the
measurable form of "no runtime allocation": with a heap, the spread would carry
whatever each connection had asked for. *A real request is still served* is the
availability question the whole campaign exists for — a bound nobody can reach
while the server is unusable is not a bound. And *every idle connection is
reclaimed* is what makes the flood transient rather than cumulative.

Run against the short-deadline variant (§7), so the reclaim wait is seconds.

---

## 5. Campaign `deadline`

The three drip shapes from §3.1, run concurrently — they are three independent
clients, and running them one after another would cost three deadlines of wall
clock.

```
✓ [http1-drip]     ended at CONN_DEADLINE (held 6.0s, deadline 6s)
✓ [http1-drip]     outlived RECV_TIMEOUT on the way there (6.0s > 2s, 6 chunks)
✓ [h2c-drip]       ended at CONN_DEADLINE (held 6.0s, deadline 6s)
✓ [h2c-drip]       outlived RECV_TIMEOUT on the way there (6.0s > 2s, 6 chunks)
✓ [tls-ccs-flood]  the handshake really started (828 bytes of server flight)
✓ [tls-ccs-flood]  ended at CONN_DEADLINE (held 6.0s, deadline 6s)
✓ [tls-ccs-flood]  outlived RECV_TIMEOUT on the way there (6.0s > 2s, 6 chunks)
✓ the server still serves after every deadline expiry
```

The ClientHello the TLS shape sends is not hand-written: it is captured from
the standard library's own handshake over a `socketpair`, so the bytes the
server sees are the bytes a real client sends. Hand-writing one would mean this
file owning a second, worse TLS implementation.

The last row is the one that would catch the mechanism being armed in the wrong
process: an alarm inherited by a worker, or armed before the fork, would take
the server down with the connection.

---

## 6. Campaigns `buffers` and `cpu`

### 6.1 buffers

Two sampled phases, and the comparison between them is the check.

Phase 1 is **plain traffic over all three protocols** — HTTP/1 GETs, an h2c
connection, and a TLS 1.3 + h2 connection. All three, deliberately: an h2 child
touches the frame and stream buffers an HTTP/1 child never faults in, and a TLS
child touches the record buffers and the key schedule on top of that. A
baseline taken over GETs alone would attribute those pages to the attack and
fail on the server working normally. Measured peak: 336 KB.

Phase 2 is the hostile corpus — a header past `BUF_SIZE`, a path past its cap,
600 header lines, a `Content-Length` past 2⁶⁴, TLS records at and past the
maximum, an h2c frame past `SETTINGS_MAX_FRAME_SIZE`, 64 concurrent h2c streams
against an advertised limit of 32, and an HPACK dynamic table stuffed toward
its 4096-byte cap. Measured peak: 240 KB.

```
✓ no child exceeds 1024 KB resident under the hostile corpus (peak 240 KB)
✓ peak resident size does not grow with the input
                        (plain 336 KB, hostile 240 KB, limit +64 KB)
```

Because `sarm` allocates nothing at runtime — every buffer is a fixed-size
`.bss`/`.data` global — the honest bound on that second row is zero growth; the
64 KB of slack is for page-accounting noise, not for the server. The cases that
name an expected status (`431`, `414`) additionally check that the bound is
still *enforced*, not merely survived: resident size would not move if a cap
were widened by 16 KB, but the status would.

### 6.2 cpu

`docs/SECURITY.md` §8 asks for one specific ordering:

> A malformed packet should generally be rejected **before expensive crypto**
> wherever protocol ordering permits.

That is a statement about cost, so it is measured as one. The campaign runs
against `./sarm` in `no_fork` mode, because per-connection CPU is only
measurable where one process serves the connections and survives them — a
forked child's accounting dies with it, and `SIGCHLD` is `SIG_IGN` with
`SA_NOCLDWAIT`, so nothing `wait()`s to collect it.

```
✓ [http1]             0.025 ms of CPU per connection (ceiling 2.0 ms, 1200 conns)
✓ [tls-junk]          0.017 ms of CPU per connection
✓ [tls-bad-key-share] 0.008 ms of CPU per connection
✓ [tls-handshake]     0.150 ms of CPU per connection (600 conns)
✓ a complete handshake is measurably expensive (0.150 ms)
✓ [tls-junk] is rejected before the key exchange (9.0x cheaper, floor 4.0x)
✓ [tls-bad-key-share] is rejected before the key exchange (18.0x cheaper)
```

`tls-bad-key-share` is the real ClientHello with the `key_share` extension's
`key_exchange` length cut to 31 octets — an X25519 share one byte short. The
point is *where* it is rejected, not that it is: 31 is caught by the
ClientHello parser's bounds walk, before any scalar multiplication happens. At
18× cheaper than a completed handshake, that ordering is visible in the
measurement, and a future refactor that moved validation after the ECDH would
collapse the ratio and fail the check.

The absolute ceiling (2 ms) is the cruder companion bound: it is what would
catch a parser that had become superlinear in some field's length, which no
ratio between two campaigns would notice.

---

## 7. Testing seconds instead of minutes

The shipped `CONN_DEADLINE` is 120 s and `RECV_TIMEOUT` is 10 s. Asserting them
directly would cost `make test` several minutes, and skipping the assertion
would leave the mechanism untested — the usual bad trade for a timeout.

Both constants are therefore `#ifndef`-guarded in `config.S`, and the Makefile
grew a `variant` target that builds the same sources, out of tree, with extra
`-D` flags and a binary somewhere other than `./sarm`:

```bash
make variant BIN=/tmp/sarm-short \
     VARIANT_CFLAGS='-DCONN_DEADLINE_SECONDS=6 -DRECV_TIMEOUT_SECONDS=2'
```

The `connections` and `deadline` campaigns run against that binary; `buffers`
and `cpu` run against the real one, because the numbers they measure are
properties of the shipped build. What the variant leaves untested is that the
shipped constants are the documented ones, so the harness reads them back out
of `src/config.S` and says so:

```
✓ src/config.S ships CONN_DEADLINE_SECONDS = 120
✓ src/config.S ships RECV_TIMEOUT_SECONDS = 10
```

### A flake worth recording

The harness was flaky on its first assembly, and the cause was not in the
server. Every harness in `tests/` picks its port as `BASE + ($$ % N)`. When a
stale server from an earlier run is still listening on the port that lands on,
the readiness probe succeeds — against the *stale* server — while the campaign's
own server has already exited on a failed `bind()`. Every measurement after
that reads a process that is not there, and the run fails with
`the sampler saw the server's children (0 samples)`.

`test_limits.sh` now binds a four-port range itself before using it, and checks
that its own server is alive *before* believing a successful `curl`. Worth
recording because the symptom pointed squarely at the server, and the server
was fine.

---

## 8. Verified by sabotage

A resource bound that is not there looks exactly like a resource bound that is,
until something is slow. Each row below is a break that was applied and a run
that caught it.

| Break | Result |
|---|---|
| `CONN_DEADLINE = 0` — `it_value` of zero disarms `setitimer`, i.e. exactly the pre-Step-12 server | `deadline`: all three drips *held 15.1s, deadline 0s* — the harness gave up before the server did |
| `CONN_DEADLINE = 1`, below `RECV_TIMEOUT` — a deadline that fires before the attack has begun | `deadline`: *the drip outlived RECV_TIMEOUT on the way there (1.0s > 2s)* — the non-vacuity check, not the bound |
| `RECV_TIMEOUT = 0` and `CONN_DEADLINE = 0` — nothing reaps anything | `connections`: *every idle connection is reclaimed … (48 children left)*, plus all three deadline shapes |
| `BUF_SIZE` widened 16384 → 262144, so a 64 KB header is accepted | `buffers`: *[header past BUF_SIZE] answered HTTP/1.1 431 (got 'HTTP/1.1 200 OK')* |
| the same, attacked with a 250 KB header so the buffer is actually touched | `buffers`: *peak resident size does not grow with the input (plain 336 KB, hostile 416 KB)* |
| `truncated_key_share` returns the ClientHello unmodified, so the cheap case and the expensive case are the same connection | `cpu`: *the ClientHello's key_share was found and corrupted* **and** *the truncated key_share is rejected, not served (127 bytes back)* — the ratio cannot degenerate into comparing a handshake with itself |

Six breaks, six catches, across four mechanisms: a wall-clock hold, a
non-vacuity lower bound, a status code, and a resident-size comparison.

The fourth and fifth rows are the same sabotage caught two different ways, and
the pair is the point: widening a buffer's *bound* is caught by the status
check, because resident size does not move until something writes the extra
pages; widening the buffer and then *filling* it is caught by the resident-size
check, because the status is 200. Neither check subsumes the other.

---

## 9. Still not bounded, on purpose

**The number of concurrent connections.** One `fork` per accepted connection,
no cap, so the ceiling is the OS process and descriptor limit. This was the
other half of threat-model observation 7 and it is *not* closed here. A cap
would mean the parent tracking how many children are live, which means
reaping them, which means giving up `SIGCHLD = SIG_IGN` with `SA_NOCLDWAIT` and
introducing an explicit `wait4` loop into the accept path — a change to the
process model, not a change to a limit, and one that touches the multicore
worker design the whole Phase 3 work rests on.

What Step 12 changes is the shape of the exposure rather than the number:

```
before:  live processes  ≈  connection rate × (attacker's patience)
after:   live processes  ≤  connection rate × CONN_DEADLINE
```

With no lifetime bound, a slow-connection flood accumulates without limit and
the server never recovers on its own. With one, the process count reaches a
steady state set by the arrival rate, and every connection in it is guaranteed
to leave. That does not make the server immune to a flood fast enough to
exhaust the process table — nothing at this layer would — but it does mean the
failure is transient and self-clearing, and that `fork` failing is already
handled by dropping the connection rather than serving it on the accept loop
(`Lmain_fork_failed`). A concurrency cap belongs with that code, and belongs to
whatever step revisits the process model. Recorded, not closed.

**Total bytes read per connection.** Bounded indirectly, and only indirectly:
by the keep-alive budget for HTTP/1, by the frame size and stream caps for h2,
and now by `CONN_DEADLINE` in wall-clock terms for everything. There is no
counter of bytes-per-connection anywhere in the tree. Under a 120-second
ceiling on a loopback link that is a large number, and nothing in the current
design cares — no input is accumulated across reads except the request header,
which has its own cap — but it is the assumption to revisit first if a body-
reading path is ever added.

---

## 10. What Step 12 delivers

`tests/test_limits.sh` + `tests/limit_checks.py`: 49 checks in ~25 seconds,
folded into `make test`, over four campaigns and four differently-shaped
servers. A new bound, `CONN_DEADLINE`, that closes the two holds threat-model
§8 had named as unbounded, at a cost of one syscall per connection. One new
line on the syscall allowlist, caught by Step 11's audit before this step's own
test ran. A `make variant` target so that timeouts can be tested in seconds
without shipping seconds. And the sabotage table in §8, which is the only
reason to believe any of the above.
