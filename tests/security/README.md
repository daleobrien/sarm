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
