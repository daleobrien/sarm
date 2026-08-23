# tests/security

The per-function half of the security programme. What each harness *is* and how
to drive it; why it exists, what it found, and every sabotage table is in
[docs/SECURITY.md](../../docs/SECURITY.md).

```bash
make test-security          # from the repo root
make -C tests/security      # the same thing
make -C tests/security build
make -C tests/security clean
```

`make test` runs this suite after `tests/unit`.

These tests link no part of the server's build constraints: test code may use
libc freely — standalone and no-libc is a property of `sarm`, not of the things
that measure it.

Not to be confused with `tests/test_security.sh`, the end-to-end probe suite
(path traversal, `%00`, non-printables) run against a live binary with `curl`.
That one tests the server; this one tests it from underneath, one function at a
time.

**Three steps of the programme are deliberately not here**, because they are
properties of a running process rather than of a function: the secret-leak probe
(`tests/test_leak.sh`), the syscall allowlist (`tests/test_syscalls.sh`,
`scripts/syscall_audit.py`) and the resource-limit harness
(`tests/test_limits.sh`). All three live in `tests/` with the other live-server
harnesses, and all three run in `make test`. Binary hardening
(`tests/test_hardening.sh`) is there too.

---

## guard_pages.h — guarded buffers

`sarm` allocates nothing at runtime, so there is no allocator to notice a
routine writing one byte past `filename_buf` — the byte after it is just
another global. ASan cannot instrument hand-written `.S` either. A guarded
buffer restores the missing detector in hardware:

```
[ PROT_NONE ][ ...slack... | payload ][ PROT_NONE ]
                           ^data      ^data + size = first guard byte
```

```c
struct guarded_buffer out;
guard_alloc(&out, 32);           // out.data[32] now traps
guard_fill(&out, 0xA5);          // poison, so uninitialised reads look wrong
sha256_something(out.data, in.data, in.size);
guard_free(&out);
```

A page boundary can only be exact on one side at a time, so the flush end is
the caller's choice: `GUARD_OVERRUN` (default, `data[size]` traps) or
`GUARD_UNDERRUN` (`data[-1]` traps). Test both to cover both.

`guard_alloc_shifted(gb, size, side, shift)` inserts accessible slack between
payload and guard — for alignment sweeps (under `GUARD_OVERRUN` the payload's
start alignment is fixed by its size, so offering a routine a 1/2/4/…/64-byte
aligned pointer means shifting it), and for routines *documented* to read a
bounded distance past their length. Detection is then exact to within `shift`
bytes, which is why it defaults to 0.

`size == 0` is legal and useful: under `GUARD_OVERRUN` the payload pointer
lands on the first guard byte — a valid non-NULL pointer that traps on any
dereference, which is the right probe for a zero-length call.

`guard_probe(fn, ctx)` runs a function expected to trap, in a forked child that
installs `SIGSEGV`/`SIGBUS` handlers **and its own `alarm`**, so three outcomes
are distinguishable: returned, trapped, or never returned
(`GUARD_PROBE_TIMEOUT`). The third is not hypothetical — the first run of the
bounds suite hung the whole binary on `x25519_fe_sqr_times(out, a, 0)`.
`guard_probe_status` additionally reports the child's exit code, which is how
the bounds suites answer both of their questions in one run.

**The helper has its own self-test** (`test_guard_pages.c`): four deliberately
broken functions — read/write before/after — plus in-bounds controls. A guard
page that is silently not there would make every later test pass by doing
nothing. Both ways it can silently vanish were confirmed caught: `mprotect`ing
the whole mapping RW fails 21 of 62 assertions; hard-coding the page size to
4096 on a 16 KiB machine fails 33. **If you change `guard_pages.c`, repeat
that.**

---

## The suites

| Suite | Step | Covers |
|---|---|---|
| `test_guard_pages` | 2 | the helper itself |
| `test_bounds_sha256` | 3 | `sha256`, `sha256_init/update/final`, `crypto_random_bytes` |
| `test_bounds_hmac_hkdf` | 3 | `hmac_sha256`, `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` |
| `test_bounds_gcm` | 3 | `aes128_key_expand`, `aes128_encrypt`, `gf_mult_128`, `ghash`, `aes_gcm_encrypt/decrypt` |
| `test_bounds_ecc` | 3 | X25519 + field ops, `p256_fe_*`, `p256_reduce`, `p256_bn_mul`, `p256_scalar_*`, `p256_point_*`, `p256_ecdsa_*` |
| `test_diff_hash` | 4 | SHA-256 compression, one-shot and streaming, HMAC, HKDF |
| `test_diff_gcm` | 4 | the GCM set, including random-bit forgery attempts |
| `test_diff_ecc` | 4 | X25519 and P-256 field, scalar, point and ECDSA operations |
| `test_overflow_hpack` | 5 | RFC 7541 §5.1 integers at every prefix width, string lengths leaving the block, dynamic-table inserts and size updates, every truncation of a valid block |
| `test_overflow_crypto` | 5 | `hkdf_expand`'s info/output limits, `hkdf_expand_label`'s label/context limits, `x25519_fe_sqr_times` at zero |
| `test_fuzz_tls_record` | 6, 7 | 7 campaigns against the record layer |
| `test_fuzz_tls_handshake` | 7 | 3 campaigns against the handshake |
| `test_fuzz_http` | 8 | 7 campaigns against HTTP/1 request parsing |
| `test_frag_socket`, `test_frag_http` | 9 | 7 campaigns delivering the same bytes whole and in pieces |

### Bounds (Step 3)

```
0, 1, block-1, block, block+1, large, maximum supported
        -> no crash, and reference output matches
```

Every pointer gets a guarded buffer sized to **exactly** what the routine's
header comment declares, and the call runs inside `guard_probe_status`:

| outcome | reported as |
|---|---|
| touched memory outside a declared buffer | `OUT OF BOUNDS` |
| never returned | `DID NOT TERMINATE` |
| output disagreed with the C reference | `output differs from the reference` |

The fork per case is what makes the suite both survivable and diagnostic: one
run reports every failing case, which is the difference between "GHASH is
broken somewhere" and "GHASH is broken at 17, 33 and 49 — one past each block".

**`crypto_ref.h` is the second implementation**, written for obviousness: byte
at a time, block at a time, a bitwise GF(2^128) multiply, no SIMD, no
vectorised tails. That is the point — the bug class being hunted is "the fast
path handles a partial tail differently from the slow path", and a reference
sharing the trick shares the bug. Each suite runs `ref_selfcheck_*` **first**,
pinning the reference to FIPS 180-4, FIPS 197, RFC 4231, RFC 5869 and
SP 800-38D before it judges anything.

The fixed-size routines (X25519, P-256) have no length argument, so their
boundary question is "does it stay inside the size its header declares?", which
a guarded buffer of exactly that size answers. Correctness there is by
algebraic identity — `a - a == 0`, `a * a⁻¹ == 1`, `P + P == 2P`, comb against
ladder, sign-then-verify, tamper-then-reject.

**Two sweeps stop where the routine's header says its contract does**, and both
stopped there *after* the suite ran past the line and found out what happens:
`hkdf_expand`'s info length at 607, and `x25519_fe_sqr_times`'s count at 1. If
you widen either, expect the failure and read `docs/SECURITY.md` §9 obs. 9
first.

### Differential (Step 4)

```bash
make -C tests/security                       # ~5 s, ~430k vectors
SARM_DIFF_ITERS=100 make -C tests/security   # 100x, for a soak
SARM_DIFF_SEED=0x1234 ./_obj/test_diff_gcm   # replay a specific run
```

Every vector comes from one 64-bit seed, so a failure is replayable rather than
a ghost: the suite prints its seed, each routine draws from its own stream (so
adding a case to one does not renumber another's vectors), and a failure names
the iteration, the per-vector seed and the first byte that differed. The
default seed is fixed rather than taken from the clock — a suite that tests
different vectors every run fails on someone else's machine and passes on
yours.

**Not guarded, deliberately.** Step 3 already proved each routine stays inside
its declared buffers with a forked probe per case; forking a million times to
re-prove it would cost exactly the vector count that is the point. Instead every
output buffer carries a 32-byte poison tail that must come back untouched.

**`refbn.h` and `refcurve.h`** are references for the curves, where identities
alone are too narrow (a field multiplier reducing modulo the wrong prime still
satisfies `a * a⁻¹ == 1` — in the wrong field). `refbn.h` is 32-bit limbs,
schoolbook multiplication, reduction by shift-and-subtract one bit at a time:
every trick the assembly uses, absent on purpose. `refcurve.h` is P-256 in
**homogeneous projective** coordinates against assembly working in **Jacobian**
— different denominators, different intermediates, different special cases —
and comparing across the two needs no inversion at all, since Jacobian
`(X, Y, Z)` denotes affine `(x, y)` iff `X == x·Z²` and `Y == y·Z³`. There is no
published projective vector to pin it to, so `refcurve_selfcheck()` pins it
structurally: G is on the curve, `n*G` is infinity, `(a+b)*G == a*G + b*G`. A
mistyped doubling formula does not survive `n*G == O`.

Counts per routine are deliberately uneven — the reference reduces one bit at a
time, so a scalar multiplication costs thousands of those, and the field
operations, where the carry bugs live, get the vectors.

### Overflow corpus (Step 5)

Every input is copied into a buffer flush against `PROT_NONE`, so `end` is a
hardware boundary rather than a number the parser is *hoped* to be comparing
against. Each case therefore asserts two things: the routine returns its error,
and it does so **without reading a byte outside the input it was given**. A
parser that reads past the end and complains afterwards is `OUT OF BOUNDS`
whatever it would have returned — which matters, because three of the four
Step 5 findings were exactly that shape.

Every rejection case is paired with the largest value that must still be
**accepted**. A check that rejects 608 and also rejects 607 has not made the
routine safer, and only the second half of the pair notices.

### Fuzzing (Steps 6–8)

```bash
./tests/security/_obj/test_fuzz_tls_record                     # ~1.16M cases, ~1.4 s
SARM_FUZZ_MULT=100 ./tests/security/_obj/test_fuzz_tls_record  # 114M cases
SARM_FUZZ_STATS=1  ./tests/security/_obj/test_fuzz_tls_record  # outcome histogram
SARM_FUZZ_SEED=<s> SARM_FUZZ_CASE=<i> ./tests/security/_obj/test_fuzz_tls_record
```

The last replays a single case **in-process** — no fork, no handler — so a
fault lands on the faulting instruction under a debugger. Every failure the
suite reports ends with that exact command.

| suite | campaigns |
|---|---|
| `test_fuzz_tls_record` | `parse`, `decrypt`, `roundtrip`, `tamper`, `read_record`, `read_prefilled`, `inner_plaintext` |
| `test_fuzz_tls_handshake` | `client_hello`, `flight`, `finished` |
| `test_fuzz_http` | `header_end`, `header_field`, `front_door`, `path`, `filters`, `range`, `keepalive` |
| `test_frag_socket` | `record`, `prefilled`, `plain`, `tls` |
| `test_frag_http` | `header_end`, `probe`, `pipeline` |

Three campaigns are worth naming for what they do rather than what they target.
`inner_plaintext` seals RFC 8446 §5.4's `content || type || zeros` with
`aes_gcm_encrypt` **directly**, because `tls_record_encrypt` appends the type
octet last and so can never produce a plaintext ending in a zero — it is the
only way to reach `decrypt`'s padding scan. `finished` forks the server and
plays a **real client** — X25519, key schedule, decrypting the server's flight
— so it can send a correct client Finished or one of ten deviations and require
the server to connect on exactly the correct ones; without it, "invalid
transitions are rejected" is satisfied by a function that rejects everything.
`pipeline` transcribes `child.S`'s accumulate-scan-serve-shift loop and records
each served request as a length **and a hash of its bytes**, because a
length-only record calls a corrupted shift identical.

Three things every campaign checks that "no crash" does not: the routine's
whole **output contract** on every case; that a **rejected record leaked
nothing** (output buffers are poisoned before and verified after); and that the
corpus still **reaches** the paths it claims to — each campaign declares the
outcomes it must hit, and an empty one fails it as `VACUOUS`.

Two things the HTTP target needed that the TLS ones did not. **Its own
`reply_status`**: `parse_path`, `get_header_field` and `verify_http_version`
answer some inputs by tail-branching there rather than returning, so the suite
links the only `reply_status` in the binary, which records the status and
`longjmp`s back to the case loop — turning "which inputs escape, with which
code" into a counted outcome. And **poison canaries instead of a guard page on
the output side**, because `filename_buf`, `query_buf` and `authority_buf` are
the server's own globals: each is allocated larger than the bound its writer
enforces, and the slack is filled with 0xA5 and checked. The input side still
gets the guard page.

### Fragmentation (Step 9)

The property here is a relation between two runs, not an assertion about one:

```
        bytes ──┬── written whole ────▶ reader ──▶ result A
                └── written in pieces ─▶ reader ──▶ result B     A == B
```

So the corpus does not have to be *valid* — a record with a nonsense content
type must be rejected the same way from both deliveries — and "behaviour" means
every return value, every error code **and the whole destination buffer**,
poison included.

**A split is only real if the reader consumes piece k before piece k+1
arrives.** The naive `for (piece) write(fd, …)` lands them in the socket buffer
together, tests nothing, and *passes*. `frag_common.h` asks the kernel:
`FIONREAD` on the read end is what is still waiting, so the feeder spins until
it reads 0 — the reader has taken everything sent and is, or is about to be,
blocked in `read()` — and only then writes the next piece. Whether each
boundary was real is counted (`real split boundaries`, a required bucket), and
runs at 95–99%.

The delivery ends with `shutdown(wfd, SHUT_WR)`, and **on this kernel that
sometimes fails to wake a peer already asleep inside `read()`** — the state is
set, the wakeup is lost. So the feeder outlives its last write and prods the
reading thread with `SIGURG` (handler does nothing, installed without
`SA_RESTART`) every 2 ms until the reader confirms it has stopped. The prod
interrupts the sleep, the `EINTR` retry every read path already does re-enters
`read()`, and `read()` re-reads the state and returns the EOF that was there
all along. It is counted as `EOF wakeups lost (prodded)` so it stays visible. A
genuine hang in the code under test is still a hang. `docs/SECURITY.md` §14 D4.

The plan generator offers four shapes — one cut, byte at a time, up to 32
random cuts, and *on the seams* (a named offset, or one byte either side of it).
The **schedule** is deterministic, so `SARM_FUZZ_CASE` replays the same cuts;
the **interleaving** is not, and that asymmetry is the right way round, because
the invariant under test is precisely that the interleaving does not matter.

`test_frag_http` has no socket. `child.S` re-runs `h2_probe` and
`parse_header_end` over everything accumulated after every read, so the
question there is not "does the reader wait" but *whether the answer depends on
where the reads landed* — a sweep over every prefix, not a socket. The guard
page is what makes the sweep worth doing at every length: a scan that peeks one
byte past its length argument works perfectly on a full buffer and reads
whatever is there exactly when a read boundary lands on it.

---

## corpus/ and findings/ (Step 14)

A crash is never fixed without preserving the input that caused it, and the
preserving is automatic: every campaign hands its bytes to `fuzz_input()`,
which copies them into the shared report page, and a campaign that crashes,
hangs or breaks an invariant writes them out before it reports.

```
findings/<suite>-<campaign>-seed…-case…-crash.bin     what failed, unshrunk
       ↓  scripts/fuzz_minimize.py <binary> <campaign> <file> --keep <name>
corpus/<suite>/<campaign>/<name>.bin                  the regression test
```

`findings/` is scratch and is not committed. `corpus/` is, and every file in it
is replayed — from bytes, through the same invariants a generated case runs —
before its campaign starts, on every `make test`:

```
  ✓ flight — corpus: 5 preserved inputs replayed clean
  ✗ path — corpus REGRESSION: parse-path-overread-copy-loop.bin: SIGBUS …
```

Bytes rather than seeds, because a seed-based reproducer means whatever its
generator means *today*: replaying the seed and case of the five-byte
pre-auth crash now produces a 238-byte flight. What each entry guards is in
[corpus/MANIFEST.md](corpus/MANIFEST.md) — a corpus file nobody can explain is
a file nobody dares delete.

**A campaign gets a corpus by having a replay entry**, which means splitting its
case function into "generate the bytes" and "run the bytes and check
everything". Thirteen of 24 campaigns have one. The seven fragmentation
campaigns cannot, because a case there is bytes *plus cuts*, and the harness
exits **2** for those rather than answering wrongly — before that exit code
existed, the minimiser shrank a real hang to zero bytes and called it minimal.

Soak runs are `scripts/fuzz_soak.py` (`make fuzz-soak`), which runs the seeded
suites on random seeds while `make test` keeps its fixed one.

### Environment

| variable | what it does |
|---|---|
| `SARM_FUZZ_SEED` | campaign seed |
| `SARM_FUZZ_MULT` | scale every campaign's case count |
| `SARM_FUZZ_CASE` | replay one case in-process, no fork |
| `SARM_FUZZ_TARGET` | run only this campaign |
| `SARM_FUZZ_REPLAY` | run a file's bytes through the campaign's replay entry; the exit code is the oracle the minimiser bisects against |
| `SARM_FUZZ_DUMP` | with `SARM_FUZZ_CASE`, write that case's input bytes to a file |
| `SARM_FUZZ_CORPUS` | where the preserved corpus lives (default `corpus`) |
| `SARM_FUZZ_FINDINGS` | where a failing campaign writes its input (default `findings`) |
| `SARM_FUZZ_SECS` | per-campaign no-progress deadline |
| `SARM_FUZZ_STATS` | print the outcome histogram |
| `SARM_DIFF_ITERS` | scale the differential vector count |
| `SARM_DIFF_SEED` | replay a differential run |
