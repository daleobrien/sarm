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
