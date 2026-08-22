# tests/security

The security test suite from [docs/SECURITY.md](../../docs/SECURITY.md).
Its baseline inventory — entrypoints, wire-derived lengths, secrets, buffers,
syscalls, protocol states — is
[docs/security/threat-model.md](../../docs/security/threat-model.md) (Step 1).

```bash
make test-security          # from the repo root
make -C tests/security      # the same thing
make -C tests/security build
make -C tests/security clean
```

`make test` runs this suite after `tests/unit`.

These tests link no part of the server. Test code may use libc freely — the
standalone, no-libc constraint is a property of `sarm`, not of the things that
measure it.

Not to be confused with `tests/test_security.sh`, which is the end-to-end
probe suite (path traversal, `%00`, non-printables) run against a live binary
with `curl`. That one tests the server; this one tests it from underneath, one
function at a time.

## guard_pages — guarded buffers (Step 2)

`sarm` allocates nothing at runtime: every buffer is a fixed-size `.bss`/`.data`
global. That removes every heap bug class and, with it, every heap red zone —
there is no allocator to notice that a routine wrote one byte past the end of
`filename_buf`, because the byte after `filename_buf` is just another global.
ASan cannot instrument hand-written `.S` either.

A guarded buffer restores the missing detector in hardware. The payload is
placed flush against a `PROT_NONE` page, so the *first* out-of-bounds access
traps:

```
[ PROT_NONE ][ ...slack... | payload ][ PROT_NONE ]
                           ^data      ^data + size = first guard byte
```

```c
#include "guard_pages.h"

struct guarded_buffer out;
guard_alloc(&out, 32);           // out.data[32] now traps
guard_fill(&out, 0xA5);          // poison, so uninitialised reads look wrong

sha256_something(out.data, in.data, in.size);

guard_free(&out);
```

A page boundary can only be exact on one side at a time, so the flush end is
the caller's choice: `GUARD_OVERRUN` (default — `data[size]` traps) or
`GUARD_UNDERRUN` (`data[-1]` traps). Test both to cover both directions.

`guard_alloc_shifted(gb, size, side, shift)` inserts accessible slack between
the payload and its guard. Two uses: alignment sweeps (with `GUARD_OVERRUN` the
payload's start alignment is fixed by its size, so offering a routine a
1/2/4/…/64-byte-aligned pointer means shifting it), and routines *documented*
to read a bounded distance past their length. Detection is then exact to within
`shift` bytes rather than one byte — which is why `shift` defaults to 0.

`size == 0` is legal and useful: under `GUARD_OVERRUN` the payload pointer
lands on the first guard byte, so it is a valid non-NULL pointer that traps on
any dereference — exactly the right probe for a zero-length call.

`guard_probe(fn, ctx)` runs a function that is *expected* to trap in a forked
child and reports `GUARD_PROBE_OK` / `_FAULT` / `_ERROR`. The child installs
`SIGSEGV`/`SIGBUS` handlers that `_exit` immediately, so an expected fault costs
no macOS crash report and no core file, and the test binary survives to assert
about it.

### guard_probe and non-terminating code

`guard_probe(fn, ctx)` runs a function in a forked child that installs
`SIGSEGV`/`SIGBUS` handlers **and its own `alarm`**, so three outcomes are
distinguishable: the routine returned, it trapped on a guard page, or it never
returned at all (`GUARD_PROBE_TIMEOUT`). The third case is not hypothetical —
the first run of the Step 3 suite hung the whole binary and orphaned a child on
`x25519_fe_sqr_times(out, a, 0)`. A harness for hand-written assembly has to
survive the assembly not terminating.

`guard_probe_status(fn, ctx, &verdict)` additionally reports the child's exit
code, which is how the bounds suites answer both of Step 3's questions in one
run: the return value says whether the routine stayed in its buffers, the
verdict says whether its output matched the reference.

### Why the helper has its own self-test

`test_guard_pages.c` contains four deliberately broken functions — read before,
read after, write before, write after — plus in-bounds controls. A guard page
that is silently not there (wrong page size, payload not flush, `mprotect`
quietly failing) would make every later security test pass by doing nothing,
which is the worst failure mode a suite can have.

Both of those failure modes were confirmed to be caught, by sabotaging the
helper and re-running:

| Sabotage | Result |
|---|---|
| `mprotect` the whole mapping RW (no guards at all) | 21 of 62 assertions fail — every fault assertion, including all four required cases |
| hard-code the page size to 4096 (Apple silicon is 16 KiB) | 33 of 62 fail — the payload no longer ends on the guard |

If you change `guard_pages.c`, repeat that: a green suite is only evidence when
it can go red.

## test_bounds_* — every crypto primitive at its length boundaries (Step 3)

```
0, 1, block-1, block, block+1, large, maximum supported
        -> no crash, and reference output matches
```

Both halves are answered in one run. Every pointer the routine touches gets a
guarded buffer sized to *exactly* what its header comment declares, and the
call runs inside `guard_probe_status`:

| outcome | reported as |
|---|---|
| touched memory outside a declared buffer | `OUT OF BOUNDS` |
| never returned | `DID NOT TERMINATE` |
| output disagreed with the C reference | `output differs from the reference` |
| none of the above | pass |

The fork per case is what makes the suite survivable *and* diagnostic. An
out-of-bounds access in-process would take the binary down at the first bad
length and hide every case after it; here one run reports all of them, which is
the difference between "GHASH is broken somewhere" and "GHASH is broken at 17,
33 and 49 — one past each block".

| suite | covers |
|---|---|
| `test_bounds_sha256` | `sha256`, `sha256_init/update/final`, `crypto_random_bytes` |
| `test_bounds_hmac_hkdf` | `hmac_sha256`, `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label` |
| `test_bounds_gcm` | `aes128_key_expand`, `aes128_encrypt`, `gf_mult_128`, `ghash`, `aes_gcm_encrypt`, `aes_gcm_decrypt` |
| `test_bounds_ecc` | `x25519` + field ops, `p256_fe_*`, `p256_reduce`, `p256_bn_mul`, `p256_scalar_*`, `p256_point_*`, `p256_ecdsa_*` |

### crypto_ref.h — the second implementation

"Reference output matches" needs an implementation that is not the one under
test, or the assertion is that the assembly agrees with itself. `crypto_ref.h`
is that: SHA-256, HMAC, HKDF, HkdfLabel, AES-128, GHASH and AES-128-GCM, all
written for obviousness — byte at a time, block at a time, a bitwise GF(2^128)
multiply, no SIMD, no vectorised tails. That is the point. The bug class being
hunted is "the fast path handles a partial tail differently from the slow
path", and a reference sharing the same trick shares the same bug.

Each suite runs `ref_selfcheck_*` **first**, pinning the reference to published
vectors (FIPS 180-4, FIPS 197, RFC 4231, RFC 5869, SP 800-38D) before it is
used to judge anything.

The fixed-size routines (X25519, P-256) have no length argument, so their
boundary question is "does it stay inside the size its header declares?" — a
guarded buffer of exactly that size answers it. Correctness there is checked by
algebraic identity (`a - a == 0`, `a * a^-1 == 1`, `P + P == 2P`,
`k*G` by comb == `k*G` by ladder, sign-then-verify, tamper-then-reject) rather
than by a reference; the full random-vector comparison is Step 4's job.

### Sweeps stop at the documented contract

Two sweeps deliberately stop where the routine's header says its contract does,
and both stopped there *after* the suite ran past the line and found what
happens:

- `hkdf_expand` info length stops at 607 (`32 + infolen + 1 <= 640`, a stack
  buffer). Past it, the frame is silently overrun.
- `x25519_fe_sqr_times` count starts at 1. At 0 the do-while wraps to 2^64-1
  iterations and never returns.

Neither is reachable from the network today — every caller passes a
compile-time constant — and both are recorded in
[docs/security/threat-model.md](../../docs/security/threat-model.md) §9 as
unchecked preconditions rather than fixed here, because Step 3 is a test step.
If you widen either sweep, expect the failure, and read that section first.

## test_diff_* — random-vector differential testing (Step 4)

Step 3 asks whether the assembly survives the edges someone thought to name.
Step 4 asks whether it is *right everywhere*, by running each routine and its
reference over hundreds of thousands of random inputs at random lengths and
requiring the two to agree byte for byte.

```bash
make -C tests/security                       # ~5s, ~430k vectors
SARM_DIFF_ITERS=100 make -C tests/security   # 100x that, for a long soak
SARM_DIFF_SEED=0x1234 ./_obj/test_diff_gcm   # replay a specific run
```

| suite | covers |
|---|---|
| `test_diff_hash` | `sha256` compression, one-shot and streaming digests, `hmac_sha256`, `hkdf_extract/expand/expand_label` |
| `test_diff_gcm` | `aes128_key_expand`, `aes128_encrypt`, `gf_mult_128`, `ghash`, `aes_gcm_encrypt`, `aes_gcm_decrypt` incl. random-bit forgery attempts |
| `test_diff_ecc` | X25519 field ops + full scalar mult, `p256_fe_*`, `p256_reduce`, `p256_bn_mul`, `p256_scalar_*`, `p256_point_*`, `p256_ecdsa_sign_with_k` |

Every vector comes from one 64-bit seed, so a failure is replayable rather than
a ghost: the suite prints its seed on every run, each routine draws from its
own stream (adding a case to one does not renumber another's vectors), and a
failure report names the iteration, the per-vector seed and the first byte that
differed.

The default seed is fixed rather than taken from the clock. A suite that tests
different vectors every run is a suite that fails on someone else's machine and
passes on yours; sweeping the space is what `SARM_DIFF_ITERS` and Step 14's
continuous fuzzing are for.

### Not guarded, and why

These suites do not use `guard_pages.h`. Step 3 already proved each routine
stays inside its declared buffers with a forked probe per case, and forking a
million times to re-prove it would cost exactly the vector count that is the
point of this step. Instead every output buffer carries a 32-byte poison tail
that must come back untouched — a gross overwrite is still caught, without a
syscall per vector.

### refbn.h and refcurve.h — a reference for the curves

Step 3 checked the ECC routines by identity because identities need no second
implementation. They are also narrow: a field multiplier that reduces modulo
the wrong prime still satisfies `a * a^-1 == 1` in the wrong field. Step 4
needs the actual value, so it needs an actual reference:

- **`refbn.h`** — 32-bit limbs, schoolbook multiplication, reduction by
  shift-and-subtract long division one bit at a time. No Montgomery form, no
  Solinas fold, no lazy carries, no 64-bit limbs: every trick the assembly
  uses is absent on purpose.
- **`refcurve.h`** — P-256 in *homogeneous projective* coordinates
  (`x = X/Z`), against assembly that works in *Jacobian* (`x = X/Z^2`).
  Different denominators, different intermediates, different special cases.
  Comparing across the two needs no inversion at all: a Jacobian `(X, Y, Z)`
  denotes affine `(x, y)` iff `X == x*Z^2` and `Y == y*Z^3`, so the check
  multiplies up rather than dividing down.

There is no published projective-coordinate vector to pin `refcurve.h` to, so
`refcurve_selfcheck()` pins it structurally instead: G is on the curve,
`n*G` is the point at infinity, and `(a+b)*G == a*G + b*G`. A mistyped
doubling formula does not survive `n*G == O`.

The counts per routine are deliberately uneven. The reference reduces modulo a
256-bit prime one bit at a time, so a scalar multiplication costs thousands of
those — and the field operations, where the carry bugs actually live, are the
ones getting the vectors.

### Verified by sabotage

A green differential suite is the easiest thing in the world to fake, so each
comparison was checked by breaking the assembly and confirming the suite went
red:

| break | result |
|---|---|
| one SHA-256 round constant, `0xc67178f2` → `f3` | every sha256, hmac and hkdf sweep failed |
| `x25519_fe_mul` carry chain, `lsl #13` → `#12` | fe_mul, fe_recip and full x25519 failed |
| `p256_point_dbl`, one `fe_add` → `fe_sub` | point dbl/add, point mul and ECDSA failed |
| `ghash` length block, `lsl #3` → `#4` | the `ghash` sweep failed — **and nothing else did** |

That last row is a finding, not a pass. `aes_gcm_encrypt` and
`aes_gcm_decrypt` do not call the exported `ghash`: they share its absorb core
(`.Lgcm_ghash_run`, `src/crypto/gcm/data.S`) but assemble the final
`[len(A)] || [len(C)]` block themselves. Nothing outside `tests/` calls
`ghash` at all. See
[docs/security/threat-model.md](../../docs/security/threat-model.md) §9.

---

## test_overflow_* — the integer-overflow corpus (Step 5)

Step 5 audits every length calculation an attacker can influence and asks the
`adds`/`b.cs` question of each: *can this sum wrap, and does anything notice?*
The audit itself, site by site with a verdict for each, is
[docs/security/length-audit.md](../../docs/security/length-audit.md). These two
suites are its test half.

| suite | covers |
|---|---|
| `test_overflow_hpack.c` | RFC 7541 §5.1 integers at every prefix width, string lengths that leave the header block, dynamic-table inserts and size updates, and every truncation of a valid block |
| `test_overflow_crypto.c` | `hkdf_expand`'s info and output limits, `hkdf_expand_label`'s label and context limits, and `x25519_fe_sqr_times` with a zero count |

The suites run in about a second and need no environment variables.

### Rejected, not merely survived

Every input is copied into a buffer placed flush against a `PROT_NONE` page, so
`end` is a hardware boundary rather than a number the parser is hoped to be
comparing against. That makes each case assert two things at once:

* the routine returns its error rather than accepting the value or looping, and
* it does so **without reading a byte outside the input it was given**.

A parser that reads past the end and complains afterwards is reported as
`OUT OF BOUNDS` whatever it would eventually have returned. That distinction is
the point: three of the four Step 5 findings were exactly that shape — the
overrun was always detected, but only after `h2_huffman_decode` had expanded
2.5 KB of adjacent memory, or after `h2_hpack_dyn_insert` had copied it into
the dynamic table.

Each case runs in a forked child (`guard_probe_status`), so one run reports
every failing case instead of dying on the first, and a routine that hangs is
reported as `DID NOT TERMINATE` rather than taking the run with it.

Every rejection case is paired with the largest value that must still be
**accepted**. A check that rejects 608 and also rejects 607 has not made the
routine safer, and only the second half of the pair notices.

### Verified by sabotage

Each fix was reverted in turn and the corpus re-run:

| break | result |
|---|---|
| `lsr x3, x2, #32 / cbnz` → `tbnz x2, #32` | 8 failures — every value above bit 32 accepted |
| remove `decode_int`'s per-octet end check | 3 failures, all `OUT OF BOUNDS` |
| remove `decode_string`'s `ckrange` | 9 failures, 6 of them `OUT OF BOUNDS` |
| remove `hkdf_expand`'s infolen check | 10 failures, 8 of them `OUT OF BOUNDS` |
| remove `hkdf_expand_label`'s label check | 3 failures, 2 of them `OUT OF BOUNDS` |
| remove `x25519_fe_sqr_times`'s zero guard | 2 failures, both `DID NOT TERMINATE` |

The `OUT OF BOUNDS` rows are the MMU, not the test, confirming the
pre-Step-5 code really did read past the buffer it was given.

## test_fuzz_* — generated inputs (Steps 6 and 7)

Steps 3–5 test the inputs somebody thought of. Step 6 tests the others:
`test_fuzz_tls_record.c` runs seven campaigns against the TLS record layer —
the first code an unauthenticated peer reaches. Step 7 points the same harness
one layer up, at the handshake (`test_fuzz_tls_handshake.c`, below). The design, the invariants and the
evidence are in
[docs/security/fuzzing.md](../../docs/security/fuzzing.md); the summary is
here.

| campaign | target |
|---|---|
| `parse` | `tls_record_parse` over bytes ending flush against a guard page |
| `decrypt` | `tls_record_decrypt` on records that essentially never authenticate |
| `roundtrip` | `tls_record_encrypt` → `tls_record_decrypt` must return exactly what went in |
| `tamper` | seal a record, flip one bit anywhere in it, require the open to fail |
| `read_record` | `tls_read_record` against a real `socketpair` fed adversarial bytes |
| `read_prefilled` | `tls_read_record_prefilled`, whose shortfall arithmetic runs twice on wire-derived values |
| `inner_plaintext` | RFC 8446 §5.4's `content \|\| type \|\| zeros`, sealed with `aes_gcm_encrypt` directly — the only way to reach `decrypt`'s padding scan, since `tls_record_encrypt` appends the type octet last and never produces a plaintext ending in a zero (added in Step 7) |

Default run: ~1.16M cases in about 1.4 s, no environment needed.

```bash
SARM_FUZZ_MULT=100 ./tests/security/_obj/test_fuzz_tls_record   # 114M cases
SARM_FUZZ_STATS=1  ./tests/security/_obj/test_fuzz_tls_record   # outcome histogram
SARM_FUZZ_SEED=<s> SARM_FUZZ_CASE=<i> ./tests/security/_obj/test_fuzz_tls_record
```

The last one replays a single case **in-process** — no fork, no handler — so a
fault lands on the faulting instruction under a debugger. Every failure the
suite reports ends with that exact command.

### Three things it checks that "no crash" does not

**The output contract, on every case.** A parser can return success while
handing back a fragment pointer past the end of the buffer, and nothing crashes
until a later caller uses it. Each campaign checks carry, error-code range,
fragment placement and every length relation the module README publishes.

**That a rejected record leaked nothing.** The decrypt output buffer is filled
with poison before each case and verified byte-for-byte afterwards on every
failure. `decrypt.S` claims a bad tag leaves the output untouched; this is that
claim, tested, a few million times.

**That the corpus still reaches the interesting paths.** A generator that
drifts into producing only malformed input satisfies every invariant on the
accepting path vacuously, and stays green. So each campaign declares the
outcomes it must reach, and an empty one fails it:

```
✗ read_record — VACUOUS: 20000 cases and not one reached "past the buffer"
```

That fired on the first run, and it was right: `tls_read_record` structurally
cannot produce `BOUNDS`, because it hands `tls_record_parse` a buffer length
equal to the record length it just read. See `fuzzing.md` §4.

### Verified by sabotage

| break | result |
|---|---|
| `tls_record_parse` drops its fragment-past-the-buffer check | `parse`: *success with a record running past the end of the buffer* |
| `tls_record_parse` accepts content type 24 | `parse`, `read_record`, `read_prefilled`, all at the same case index |
| `tls_record_decrypt` drops its bounds check | `decrypt`, `tamper`: **CRASH: SIGBUS** — the guard page |
| `aes_gcm_decrypt` skips the tag comparison | `decrypt`: *wrote plaintext for a record it then rejected*; `roundtrip`: *accepted under the wrong sequence number*; `tamper`: *accepted a record with a flipped bit* |
| `raw_read_exact` drops its EOF check | `read_record`, `read_prefilled`: **HANG**, caught by the heartbeat within seconds |

Four distinct detection mechanisms — a returned-value invariant, a guard-page
fault, a leaked-plaintext check, and the progress deadline — and the MAC row
was caught by three of them independently.

## test_fuzz_tls_handshake — the handshake (Step 7)

Three campaigns, in `test_fuzz_tls_handshake.c`. The design and the evidence
are in [docs/security/fuzzing.md](../../docs/security/fuzzing.md) §§8–14.

| campaign | target |
|---|---|
| `client_hello` | `tls_parse_client_hello` over structured-then-mutated bodies ending flush against a guard page — the largest pre-auth parser in the tree |
| `flight` | `tls_server_handshake` against a generated flight in a `socketpair`: no such flight can complete a handshake, so every case must end at `TLS_HS_FAILED`, plaintext, with no application traffic keys installed |
| `finished` | the iff. The case forks the server and plays a **real client** — X25519, key schedule, decrypting the server's flight — so it can send either a correct client Finished or one of ten generated deviations, and require the server to connect on exactly the correct ones |

```bash
./tests/security/_obj/test_fuzz_tls_handshake                    # ~2.0M cases, ~1.2 s
SARM_FUZZ_MULT=200 ./tests/security/_obj/test_fuzz_tls_handshake # 401M cases
SARM_FUZZ_STATS=1  ./tests/security/_obj/test_fuzz_tls_handshake # outcome histogram
```

This is the suite that found the one production defect the fuzzing steps have
turned up: a handshake record whose fragment is shorter than the 4-byte
handshake header made `tls_server_handshake` hash 2^64-4 bytes and crash,
before authentication, on five bytes from any peer. `fuzzing.md` §9 has the
input, the instruction, and the fix.

### Two detection mechanisms the record suite did not need

**An invariant on global state after the call.** `tls_server_handshake` returns
one bit; what matters as much is what it left behind. Every `flight` case
checks `tls_hs_state`, `transport_mode`, and the four application traffic
key/IV fields, which are filled with poison before the call — a handshake that
fails *after* installing application keys would leave a live key schedule no
peer ever authenticated.

**An invariant on a second process's verdict.** The `finished` campaign's
server runs in a forked child so it has its own `tls_state`; the child's exit
code carries "connected" or "rejected", and the case compares it against what
it knows it sent. That comparison is an iff in both directions: a correct
Finished that is refused fails the campaign exactly as loudly as an incorrect
one that is accepted.

### Verified by sabotage

| break | result |
|---|---|
| the fragment-length check from `fuzzing.md` §9 removed | `flight`: **CRASH: SIGSEGV**, case 83 — the original defect |
| `tls_server_handshake` skips the `verify_data` comparison | `finished`: *accepted an invalid client Finished* |
| `tls_server_handshake` accepts any inner type on the client's Finished | `finished`: same, at case 0 |
| the application traffic secrets derived before the client's Finished is read | `flight`: *failed after installing application traffic keys* |
| `TLS_HS_FAILED` computed but not stored | `flight`: *failed without leaving tls_hs_state at TLS_HS_FAILED* |
| `tls_parse_client_hello` drops its `cipher_suites` bounds check | `client_hello`: **CRASH: SIGBUS** at case 79 of 2,000,000 — the guard page |
| `tls_record_decrypt` accepts inner type 24 | `inner_plaintext`: *accepted an inner plaintext with no valid content type* — and **none** of the six Step 6 campaigns notice |
