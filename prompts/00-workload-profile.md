# 00 — Establish where the time actually goes

**Run this first. Do not optimize anything until it is done.**

## Context

`sarm` is a freestanding AArch64 HTTP/2 server that serves a small, fixed set
of static files embedded in the binary and pre-compressed at build time. There
is no filesystem I/O and no runtime compression.

`docs/REGISTER-PRESSURE.MD` contains a completed static analysis of register
usage across all 165 assembly functions. It ranks functions by register
save/restore overhead. **That ranking is static, not empirical** — it says
nothing about how often each function runs. For this workload the two are very
different, and optimizing the static ranking would be optimizing the wrong
thing.

## Objective

Produce an empirical cost model of a real connection: a ranked breakdown of
where CPU time goes, per connection and per request, with enough resolution to
decide which of prompts 03–08 is worth doing and in what order.

## Method

### 1. Build an end-to-end harness

Write a benchmark driver that exercises the server the way a browser does:
TLS 1.3 handshake, HTTP/2 preface and SETTINGS, one or more GET requests for
the embedded assets, response read, connection close.

`tests/h2_browser_sim.py` already performs a full browser-like session and is
the natural starting point — extend or reuse it rather than writing a new
client. Drive enough iterations that per-connection cost is measurable above
process and network noise. Use loopback, pin to a single core if possible, and
report median of ≥5 rounds.

Measure at least these scenarios separately:

- **Handshake-dominated**: connect, handshake, one small request, close.
- **Transfer-dominated**: one handshake, then repeated requests for the
  largest embedded asset on the same connection.
- **Request-dominated**: one handshake, then many requests for the smallest
  asset on the same connection.

The three isolate per-connection, per-byte and per-request cost respectively.

### 2. Attribute cost to functions

There is no `perf` on this machine. Use these instead, in order of preference:

1. **`xctrace`** (`/usr/bin/xctrace`, present) — sampled time profile. This is
   the closest thing to a real profiler available; try
   `xctrace record --template 'Time Profiler'` against the server process
   under load, then export and attribute samples to symbols. Build with
   `make` (not `make production`) so local symbols survive.
2. **Targeted instrumentation** — a build-time-only counter or a
   `mach_absolute_time()` bracket around candidate regions (handshake, record
   encrypt, HPACK decode). Must be removable and must not ship; the committed
   binary logs nothing.
3. **Analytic estimate** — instruction counts from `objdump` times measured
   call counts. Weakest, but a valid cross-check.

Cross-check at least two methods. If they disagree by more than ~2×, resolve
the disagreement before proceeding.

### 3. Count call frequency

For each candidate function, determine how many times it is called per
connection and per request. `p256_point_mul` runs a 256-iteration loop calling
`p256_point_add`/`p256_point_dbl`; `aes128_encrypt` is called once per 16-byte
block of every record. Frequency, not size, is what makes a function hot.

## Deliverables

Write `docs/PROFILE.MD` containing:

1. **Scenario results** — wall-clock for each of the three scenarios, with
   round-to-round variance stated.
2. **Cost breakdown** — percentage of connection time in: handshake asymmetric
   crypto, transcript/key schedule, record encryption, HPACK/H2 framing,
   transport/syscalls, everything else.
3. **Ranked function table** — function, estimated share of total time, calls
   per connection, calls per request, measurement method, confidence.
4. **Method and its limits** — what you measured, how, and what the numbers
   cannot support. Be explicit about noise floor.
5. **Recommended order for prompts 03–08**, justified by the data, including
   any prompt the data says is not worth running.

## Acceptance criteria

- Two independent methods agree on the top three cost centres.
- The noise floor is stated as a number, so later prompts know what
  improvement is too small to claim.
- The recommendation explicitly addresses whether the register-pressure work
  (prompts 05–07) is justified for this workload, given that it targets roughly
  160 instructions repo-wide.

## Constraints

- **Do not modify any `.S` file.** This prompt is measurement only.
- Any instrumentation added must be clearly temporary and must not be
  committed to the shipped binary. The project deliberately logs nothing —
  see commit `8830940`.
- Report what you measured, including results that contradict
  `docs/REGISTER-PRESSURE.MD`. Contradicting it is a useful outcome.
