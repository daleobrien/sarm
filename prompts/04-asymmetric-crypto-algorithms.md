# 04 — Replace the P-256 reduction bottleneck

**The largest measured P-256 opportunity.** The workload profile
(`docs/PROFILE.MD`) shows `p256_reduce` accounts for approximately 73% of
`p256_fe_mul`'s cost. This prompt replaces its algorithm; it does not attempt
fixed-base comb multiplication, which is deferred to a later re-profile (see
"Fixed-base comb" below).

## Context

`p256_reduce` (`src/crypto/p256/sqr_mul.S:37`, file-local, called from
`p256_fe_mul` at `sqr_mul.S:207`) currently performs **Barrett reduction** of
an 8-limb (512-bit) product down to a canonical 4-limb result: two calls into
`p256_bn_mul` (`src/crypto/p256/bn_mul.S:38`) to compute `q1*mu` and `q3*p`,
followed by a 9-limb subtraction and up to three branchless conditional
add/subtract-p correction rounds. See the header comment at
`sqr_mul.S:9-20` for the exact algorithm currently implemented.

Barrett reduction is a **general-purpose** technique — it works for any
modulus and needs no special structure. But P-256 does not have a general
modulus:

```text
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
```

This is a **Solinas prime**: a modulus built from a small number of powers of
two, chosen specifically so that reduction can be done by *folding* the
high limbs of the product back onto the low limbs with shifted
adds/subtracts — no multiplication instructions at all, as opposed to
Barrett's two schoolbook multiplies (`q1*mu`, `q3*p`) each touching multiple
limbs. This is the reduction method used by, e.g., NIST's own P-256
reference and most production P-256 implementations; it is available here
and unused.

## Objective

Investigate and implement a constant-time P-256 reduction specifically
optimized for the P-256 modulus's special form, replacing the current
Barrett implementation.

The primary target is `p256_reduce`. Its effect propagates to
`p256_fe_mul`, `p256_fe_sqr` (`sqr_mul.S:164`, a thin trampoline into
`p256_fe_mul`), `p256_point_mul`, ECDSA, ECDH, and complete TLS handshakes —
measure all of these, not just the microbenchmark.

## First establish the mathematics

**Before writing any assembly.** This follows the repo's `verified-asm-crypto`
skill's prototype-then-cross-check-then-port workflow, and it matters more
here than almost anywhere else in the codebase — the current Barrett
implementation's header comment already documents a subtle correctness trap
(`sqr_mul.S:95-101`: truncating to 4 limbs before the correction rounds
silently drops the 257th bit on exactly the inputs that need a real
correction). A folding reduction has its own version of this trap and it must
be found in Python, not in production.

1. Implement a reference reduction in Python using arbitrary-precision
   integers as the mathematical oracle.
2. Derive the exact folding sequence for `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`
   from the 512-bit product's limb structure. Standard treatments (e.g. the
   NIST FIPS 186 P-256 reduction algorithm) exist and can be used as a
   starting point, but the derivation must be redone against this repo's
   actual limb representation, not copied blind — confirm limb width, limb
   count, and endianness match `p256_reduce`'s 4×64-bit output convention
   before trusting any borrowed formula.
3. Determine the required intermediate limb widths and where carries/borrows
   can exceed a single 64-bit limb during folding.
4. Determine carry propagation requirements — Solinas folding for P-256 is
   known to need signed intermediate quantities (the fold can produce a
   negative partial result that a later fold corrects), which is a different
   failure mode than Barrett's "maybe off by one multiple of p".
5. Determine whether one or multiple folding passes are required to reach a
   result small enough for the existing conditional-subtract-p correction
   rounds to finish.
6. Prove the result is canonical (< p) in the representation the existing
   code expects (`out[0..3]`, 4×64-bit limbs, matching `p256_fe_mul`'s call
   convention at `sqr_mul.S:205-207`).
7. Cross-check millions of random inputs against both the current
   implementation and the Python arbitrary-precision oracle, including
   adversarial inputs: the maximum 512-bit product, zero, and products with
   many leading/trailing zero limbs.

Do not begin by rewriting the assembly. If the Python cross-check against the
current implementation does not match on every case, the derivation is wrong
and must be fixed before any `.S` file is touched.

## Assembly implementation

Only after the reference algorithm is validated over millions of cases:

1. Implement the reduction in assembly.
2. Preserve the existing field representation (4×64-bit limbs, same
   endianness and layout `p256_fe_mul`/`p256_bn_mul` already use).
3. Preserve the existing ABI: `x0` = out pointer, `x1` = T pointer (8 limbs),
   matching `p256_reduce`'s current signature so `p256_fe_mul` needs no
   change beyond the `bl p256_reduce` call itself.
4. Preserve constant-time behaviour.
5. Avoid secret-dependent branches — the reduction operates on field
   elements derived from secret scalars (private keys, ECDSA nonces), so
   even though `p` itself is public, correction-round branching must stay the
   branchless `csel`-based pattern the current code already uses.
6. Avoid secret-dependent memory addressing.
7. Avoid unnecessary stack use — Barrett's 192-byte frame held a 10-limb `q2`
   buffer and a 9-limb `q3p` buffer for two `p256_bn_mul` calls; a
   multiplication-free folding reduction may need substantially less
   scratch space. Do not carry over stack allocation sized for an algorithm
   this implementation no longer uses.
8. Minimize carry-propagation dependencies — a long, single dependent
   `adds`/`adcs`/`adcs`/... chain each has multi-cycle latency; where the
   fold produces limbs that don't depend on each other's carries, compute
   them independently.

Pay particular attention to:

- `ADDS` / `ADCS` / `SUBS` / `SBCS` carry chains
- instruction scheduling
- register pressure — use the prompt-01 tooling
  (`python3 scripts/regpressure.py --function p256_reduce`) to check, not
  guess. **The reduction may legitimately use more temporary registers than
  Barrett did.** That is acceptable if the additional register usage does not
  cause spills or another measurable regression — do not preemptively
  constrain the design to Barrett's register budget.

## Benchmark

Using the substrate from prompt 02, measure before and after:

```text
p256_reduce       (isolated)
p256_fe_mul       (isolated, and reduction-share vs multiplication-share)
p256_fe_sqr
p256_point_mul
ECDSA sign
ECDH
TLS handshake      (complete, end to end)
```

The critical measurement is whether replacing Barrett reduction materially
reduces complete handshake cost, not just the microbenchmark number —
`p256_reduce` being 73% of `p256_fe_mul` only matters if `p256_fe_mul` itself
is a meaningful share of handshake time; confirm that share from
`docs/PROFILE.MD` before over-claiming the end-to-end effect.

## Fixed-base comb

**Do not implement fixed-base comb multiplication in this prompt.** That was
the previous plan's proposal for `p256_point_mul` and is a different,
independent optimization (precomputed multiples of the generator to cut
double-and-add iterations) from the reduction work here.

After the new reduction is working and benchmarked, **re-profile P-256** with
the reduction change in place. Only proceed with a comb/windowing
optimization for `p256_point_mul` if that fresh profile shows scalar
multiplication remains a sufficiently large share of P-256/handshake cost to
justify the table size (a 4-bit comb over P-256 is roughly 64 KB) and the
added implementation and verification complexity. This decision belongs to
prompt 05's re-profiling process, not to an assumption carried over from
before the reduction change landed.

## Constraints

Non-negotiable:

- **Constant time.** No secret-dependent branches, no secret-dependent
  addressing, at every step of the fold and every correction round.
- **The field element is derived from secret material.** Private keys and
  ECDSA nonces flow through every `p256_fe_mul` call.
- **Verify against known-answer tests before trusting anything.** RFC 6979
  deterministic ECDSA vectors and the standard P-256 test vectors give exact
  expected outputs. Wrong crypto that passes a smoke test is the worst
  outcome here.
- **No heap, no dynamic allocation.**
- Preserve the existing ABI and field representation exactly — every caller
  of `p256_reduce`/`p256_fe_mul` must work unmodified.

## Testing

- `tests/unit/test_p256/`, `test_p256_point/`, `test_p256_ecdsa/` suites.
- **Differential against the current (Barrett) implementation** over millions
  of random 512-bit products, run first in the Python reference stage and
  then again against the compiled assembly: scalar 0, 1, n−1, the maximum
  512-bit product, and products with structural edge cases (many
  leading/trailing zero limbs).
- RFC 6979 known-answer vectors for ECDSA.
- End-to-end: `tests/h2_browser_sim.py` and `tests/test_protocols.sh` must
  complete a real handshake with a real client.

## Acceptance criteria

- Byte-exact agreement with the current implementation on every differential
  case and every known-answer vector.
- Measured reduction in `p256_reduce` and `p256_fe_mul` cost, and in complete
  handshake CPU time, beyond prompt 02's noise floor.
- Constant-time properties preserved — state explicitly what you checked and
  how.
- No increase in `p256_reduce`'s stack usage unless justified and quantified;
  a decrease is expected given the algorithm no longer needs Barrett's
  multiplication scratch buffers.
- Register pressure measured and reported; an increase is acceptable only if
  it does not cause spills.

## Deliverable

Implementation plus a report: the Python reference derivation and its
cross-check count, per-operation and per-handshake cost before and after,
register pressure and stack usage before and after, and — separately — the
re-profiled P-256 bottleneck table that determines whether fixed-base comb
multiplication is now justified.
