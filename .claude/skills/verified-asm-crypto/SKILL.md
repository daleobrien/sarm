---
name: verified-asm-crypto
description: How to implement or modify hand-written ARM64 assembly cryptographic/bignum arithmetic in this repo (ymawky) correctly — via Python-prototype-then-cross-check-then-port, not by hand-deriving formulas from memory and reasoning about correctness abstractly. Use this whenever touching src/crypto/*.S or writing new field/scalar/point/bignum arithmetic in assembly, whenever implementing a new PLAN.MD crypto phase (e.g. CertificateVerify, Finished, HMAC-based key derivation, or any future ECDSA/X25519/AES/SHA work), and whenever a crypto assembly test is failing and the instinct is to just patch the .S file. Also apply this whenever asked to "implement Phase N" where N touches src/crypto/ or src/tls/handshake/ crypto plumbing.
---

# Verified ARM64 crypto implementation

Hand-deriving cryptographic formulas (modular reduction, point arithmetic,
signature equations) from memory and translating them straight into assembly
is how subtle, hard-to-spot bugs get shipped. In this repo's Phase 16 work
(P-256 field/scalar/point arithmetic and ECDSA sign/verify), this exact
workflow caught two real bugs that pure code review — reading the assembly
and reasoning about it — missed entirely:

1. **A Barrett-reduction truncation bug.** The final "make the result
   canonical" step truncated to 4 limbs *before* applying the correction
   subtraction, silently dropping a high bit on the (rare, but real) inputs
   that needed a genuine correction. The formula looked right on paper.
2. **A stack-frame size miscalculation** in a scalar-multiplication routine
   (declared 336 bytes, actually needed 352), which overflowed 16 bytes into
   the caller's stack — a classic nondeterministic-corruption bug that
   happened to not trigger in one test binary but did in another calling it
   from a deeper stack.

Neither of these would have been caught by staring at the code harder. They
were caught because the workflow below forces every claim about correctness
to be checked against something outside your own derivation.

## The workflow

Do these in order. Don't skip ahead to writing assembly because the math
"seems obviously right" — that's exactly the failure mode this guards
against.

### 1. Prototype the algorithm in Python first

Before writing a single line of `.S`, write the algorithm in plain Python
using arbitrary-precision integers. Python's native big-int arithmetic means
you can express "mod p" or "mod n" as literally `% p`, with no risk of the
representation bugs (limb splitting, carry chains, truncation) that plague
the assembly version. This gives you a clean, easy-to-eyeball reference
implementation to develop the *algorithm* separately from the *port*.

If the assembly is going to use a specific technique (Barrett reduction, a
particular point-addition formula, a square-and-multiply exponentiation
loop), write that exact technique in Python too — not just the mathematical
end result. The goal is a Python version that is structurally what you're
about to port, so that when you later compare against it, you're validating
the actual approach, not a different one that happens to agree on easy
inputs.

### 2. Cross-check the Python prototype against a real independent library

A formula you derived from memory, checked only against another formula you
also derived from memory, proves nothing — both could share the same
misconception. Before trusting the Python prototype, validate it against a
real, independently-implemented, audited library. In this repo that's meant
Python's `cryptography` package (which wraps OpenSSL):

- For point operations: derive a private key with a known scalar `d` via
  `cryptography`, read off its public key, and confirm your prototype's
  `d * G` matches — this validates point addition/doubling/scalar-mult all
  at once, for free, with real curve parameters.
- For signing: sign with your prototype, then verify the signature with
  `cryptography`'s own `verify()`. If it verifies, your signing math is
  provably correct against a real implementation, independent of whether you
  can control `cryptography`'s own nonce.
- For verification: have `cryptography` produce real signatures, decode
  them, and feed them into your prototype's verify function — including
  deliberately tampered signatures, which must be rejected.

Run this against dozens to thousands of random cases where practical (it's
cheap in Python) — a formula being correct on one hand-picked example proves
much less than an edge case only shows up at 1-in-20000 odds, as it did for
the Barrett-reduction bug above. Do not proceed to porting until this
cross-check passes.

### 3. Only now port the validated algorithm to assembly

With a Python reference that's independently verified, write the ARM64
assembly. Follow this repo's existing conventions in `src/crypto/*.S`:
4-limb little-endian field element representation, `adr_l`/`ldr_l` for
position-independent data access, generous stack frames with named slot
offsets for scratch field elements, and doc-comment blocks over each
function describing arguments, clobbered registers, and stack usage.

When double-checking a new stack frame's size, add up every named region
explicitly (saved register pairs + each scratch slot) rather than trusting
a round number — the 336-vs-352 bug above was exactly this kind of
arithmetic slip, and it's easy to make and easy to miss by inspection.

### 4. Generate test vectors from the Python reference, don't hand-transcribe them

Write a script (inline Python, run via Bash) that uses the *same* validated
Python functions from step 2 to generate test vectors — inputs plus their
expected outputs — and emit them directly as C array literals. Never
hand-copy a hex value from a scratch calculation into a test file; that's
another place for a transcription slip to hide. Wire the generated vectors
into a new `tests/unit/test_<name>.c` file following the existing pattern in
that directory (see `tests/unit/test_p256*.c` for the shape: `extern`
declarations with `__asm__("symbol")` labels, `struct ... VECS[N] = {...}`
tables, `TEST_SUITE`/`ASSERT_EQ` from `test_harness.h`), and add the
corresponding `TEST_<NAME>` target to `tests/unit/Makefile` next to the
similar existing entries.

### 5. Build and run on real hardware — don't just reason about it

Compile and run the actual test binary (`make _obj/test_<name>` from
`tests/unit/`, then run it) on the real arm64 machine. A hand-written
assembly routine that "looks right" is not verified until it has actually
executed and produced the expected bytes. After a new test passes standalone,
run the full `make test` suite to catch regressions elsewhere, and do a
clean top-level `make` to confirm the server still builds and links.

### 6. When a test fails, re-verify the algorithm before patching the assembly

The instinct when a test fails is to stare at the assembly and find the
off-by-one. Resist that first — go back to the Python prototype and check
whether *it* actually produces the expected value via a clean, from-scratch
recomputation (not just re-running the same script that generated the
"expected" value, which would just confirm its own bug). If the algorithm
itself needs a bigger correction than expected (e.g. more Barrett correction
rounds than assumed), that's a real finding about the math, and the fix
belongs in the algorithm's design, not as a bigger hammer in the assembly. A
debugger (`lldb`, single-stepping registers) is the right tool once you're
confident the algorithm is correct and are hunting a translation bug — not a
substitute for that confidence.

## When this doesn't apply

Simple, mechanical translations — a wire-format serializer, byte-order
conversion, a struct-copy — don't need the Python-prototype step; there's no
algorithmic subtlety to get independently wrong. This workflow earns its
cost specifically for arithmetic where a formula can be *plausible but
wrong*: modular reduction, point/field arithmetic, signature equations,
anything with a correction/edge-case step that's easy to get almost right.
