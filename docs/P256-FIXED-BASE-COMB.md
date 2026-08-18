# P-256 fixed-base comb — derivation, proofs, and measured effect

Completes the half of `prompts/04-asymmetric-crypto-algorithms.md` that was
deliberately deferred: the reduction rewrite landed as `b0a868e`, and prompt
04 said the comb should only follow if a *fresh* profile still showed scalar
multiplication dominating. `docs/PROFILE-POST.MD` §10 is that profile, and it
ranked `p256_point_mul` first at **45.4% of a page-load connection**, calling
the comb "the largest remaining opportunity in the codebase". This is that
work.

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback. Numbers do not
transfer to Cortex/Neoverse.

---

## The one-line answer

`k*G` is now a table lookup problem rather than a doubling problem:
**38.5 µs instead of 320.2 µs, 8.3x**, which takes ECDSA signing from
354.7 µs to 87.9 µs (**4.0x**) and a whole TLS handshake from 531.2 µs to
260.7 µs (**2.04x**) — measured baseline-and-candidate in the same session,
against a 3843-test suite that passes unchanged.

| | before | after | ratio |
|---|---:|---:|---:|
| `k*G` (`p256_point_mul` → `p256_point_mul_base`) | 320.2 µs | **38.5 µs** | **8.32x** |
| `p256_ecdsa_sign_with_k` | 354.7 µs | **87.9 µs** | **4.03x** |
| handshake connection (server CPU, marginal) | 531.2 µs | **260.7 µs** | **2.04x** |
| page-load connection (server CPU, marginal) | 696.9 µs | **410.4 µs** | **1.70x** |
| request on an established connection | 12.03 µs | 12.04 µs | 1.00x (untouched) |
| production binary (`make production`) | 229,176 B | 295,400 B | **+66,224 B** |

---

## 1. What changed, and why it is this much faster

The generic routine (`src/crypto/p256_point/mul.S`, unchanged and still used
for variable-base multiplication) walks all 256 bits of the scalar, doing one
`p256_point_dbl` and one `p256_point_add` per bit — 512 point operations, and
the addition is the *general* one, which internally computes a full
`p256_point_dbl` and twelve `p256_fe_cmov`s so it can handle coincident,
negated and infinity inputs. That is roughly 26 field multiplies per addition
and ~9,200 field multiplies for one scalar multiplication.

For a **fixed** base the doublings are all known in advance, so they can be
done once, at build time. `k*G` is decomposed over the scalar's 64
little-endian nibbles:

```
k*G = Σ (d_i · 2^(4i)) · G       i = 0..63,  d_i = nibble i of k
```

and each of the 64 terms is read out of `p256_comb_table`
(`src/crypto/p256_point/comb_table.S`, entry `[i][d_i]`) instead of being
built. The cost becomes **64 additions and zero doublings**, and because the
table is affine each addition can be the cheap mixed one:

| | field muls per op | ops per `k*G` | total |
|---|---:|---:|---:|
| generic: `p256_point_dbl` + `p256_point_add` | ~10 + ~26 | 256 + 256 | ~9,200 |
| comb: `p256_point_add_affine` | 11 | 64 | ~700 |

plus one shared `p256_point_to_affine` inversion (~270 field ops) at the end.
That ~10x drop in field work is what the measured 8.3x is; the gap is the
table scan and the inversion, both of which are now a visible fraction of a
much smaller number.

Three new files, no existing algorithm replaced:

- `src/crypto/p256_point/comb_table.S` — generated, 64 blocks × 15 affine
  points × 64 bytes = 61,440 bytes.
- `src/crypto/p256_point/add_affine.S` — `p256_point_add_affine`, the 8M+3S
  mixed addition. This is `add.S` with `Z2 = 1` substituted throughout, which
  is why `U1` collapses to `X1`, `S1` to `Y1`, and `Z3 = H·Z1` rather than
  `H·Z1·Z2`.
- `src/crypto/p256_point/mul_base.S` — `p256_point_mul_base`, the comb loop.

`p256_ecdsa_sign_with_k` (`k*G`) and `p256_ecdsa_verify` (its `u1*G` half,
the other half being variable-base and still generic) now call it.

---

## 2. The two things that had to be proved, not assumed

`p256_point_add_affine` is deliberately *not* a general-purpose addition. It
has no doubling fallback and no infinity handling, and it returns a wrong
point rather than an error if handed inputs it can't do. That is the entire
source of its speed, and it is only safe because the comb loop can never
present it with such inputs. Both facts are proved in
`scripts/p256_comb_derivation.py` (`prove`), against the actual curve order.

At the start of block `i+1` the accumulator holds `L·G`, where `L` is the
integer formed by nibbles `0..i` of `k`, so `0 ≤ L < 2^(4(i+1))`; the addend
is `M·G` with `M = d·2^(4(i+1))` and `1 ≤ d ≤ 15` (digit 0 is masked out and
never reaches the formula). The formula misbehaves exactly when the two share
an x-coordinate, i.e. `L ≡ ±M (mod n)`.

**`R == A` is impossible.** `L < 2^(4(i+1)) ≤ M`, so `M − L > 0`; and the
largest addend anywhere is `15·2^252`, which is *less than n*:

```
15·2^252 = 0xf000…000
n        = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
```

So `0 < M − L < n` and the two are never congruent.

**`R == −A` happens only for `k == n`.** `L + M` is exactly the integer formed
by nibbles `0..i+1` of `k`, so it is positive and `< 2^(4(i+2))`. For
`L + M ≡ 0 (mod n)` it must equal `n` itself, which needs `L + M ≥ n > 2^255`,
hence `4(i+2) > 255`, hence `i+2 = 64`: the final block, with `L + M = k = n`.
And `k == n` means `k·G` is genuinely the point at infinity. The comb returns
`(0, 0)` for it — bit-identical to what the generic `p256_point_mul` returns,
and rejected by `p256_ecdsa_sign_with_k`'s existing `r == 0` check.

Beyond the algebra, `prove` re-runs the whole comb loop with an instrumented
addition that flags every `H == 0` over 211 adversarial and random scalars
(including `n`, `n−1`, `2^256−1`, and the all-`0x0F`/all-`0xF0` nibble
patterns), and asserts that the only flagged case is `k == n`:

```
H != 0 confirmed on all 12050 contributing mixed additions over 211 scalars
```

**Scalars are not reduced first.** `p256_point_mul`'s contract treats `k` as a
raw 256-bit value, and `p256_ecdsa_sign_with_k` relies on that — it feeds the
nonce straight from `p256_fe_frombytes`. Both proofs above are therefore
stated over the full `[0, 2^256)` range, not `[0, n)`.

---

## 3. Verification

Following the repo's `verified-asm-crypto` workflow: Python prototype →
cross-check against an independent library → port → generated vectors → run
on hardware. `scripts/p256_comb_derivation.py` is the generator behind all
three new files and both new test files.

| Stage | What it checks | Result |
|---|---|---|
| `gen-table` / `verify_table` | all 960 table entries re-derived independently by textbook affine `aff_mul`, and each checked on-curve | 960/960 |
| `prove` | the two structural preconditions above | pass |
| `check 3000` | hardware-faithful comb vs. the affine oracle, over random + edge scalars (0, 1, n−1, n, n+1, 2^255, 2^256−1, nibble patterns, short scalars with many leading zero nibbles) | 3053/3053 |
| `interop 500` | the same reference vs. the `cryptography` package (OpenSSL) public keys | 505/505 |
| `tests/unit/test_p256_point/add_affine.c` (generated) | 24 mixed-addition vectors, P1 in **non-normalized** Jacobian form (random Z) so a Z==1-only bug can't hide, plus `out` aliasing `p1` | 25/25 |
| `tests/unit/test_p256_point/mul_base.c` (generated) | 28 scalars against the reference **and** against the generic `p256_point_mul` bit-for-bit | 112/112 |
| `make test` | full suite, incl. the pre-existing RFC 6979 ECDSA sign/verify vectors now running through the comb | 3843/3843 |
| `tests/h2_browser_sim.py` | real TLS 1.3 + HTTP/2 page load, 6 assets | all streams complete |

The mul_base test's second suite is the most valuable single check: the comb
and the untouched double-and-add must agree exactly on every scalar,
including `k = 0` and `k = n`, so the two independent algorithms cross-verify
each other on every run of `make test`.

The table itself is generated, never hand-transcribed, and
`comb_table.S`'s header carries the command to regenerate it.

---

## 4. Constant-time properties, and what was actually checked

Same threat model as the rest of the P-256 code: the scalar is a private key
or an ECDSA nonce, so nothing may branch on it or address memory with it.

- **Table selection scans the whole block, every time.** For each of the 64
  blocks, all 15 entries are read and masked with `csetm`/`and`/`orr`
  (`mul_base.S`, `.Lmb_sel`). Addresses depend only on the block index and the
  loop counter, both public, so the digit never selects a cache line.
- **Both digit-dependent decisions are `p256_fe_cmov`** (i.e. `csel`), not
  branches: "is this digit zero" and "is the accumulator still infinity".
- **The only branches in the whole routine are the two loop counters**
  (`j < 16`, `i < 64`), both public and both iterating a fixed number of times
  regardless of the scalar. `p256_point_add_affine` is fully straight-line.
- **The addend is never secret-dependently absent.** Digit 0 selects `(0, 0)`,
  the addition is performed anyway on that garbage, and its result is
  discarded by the cmov — the work is done unconditionally so the timing is
  identical for zero and nonzero digits.
- **The number of additions is exactly 64 for every scalar**, including
  `k = 0` and `k = 1`, unlike a leading-zero-skipping implementation.

Not checked, and worth stating: there is no dudect-style statistical timing
test in this repo, and no hardware counters are available on this machine
(`docs/PROFILE-POST.MD` §6), so the above is a structural argument about the
emitted instructions, not an empirical timing-distribution measurement.

The 61,440-byte table is a public constant; the whole of it is touched on
every call, so it does not introduce a secret-dependent cache footprint.

---

## 5. Cost measured, including the costs that went up

**Register pressure and stack** (`scripts/regpressure.py`):

| Function | peak live GPRs | callee-saved | unjustified | stack |
|---|---:|---|---|---:|
| `p256_point_mul_base` | 19 (in loops) | x19–x26 | none | 368 B |
| `p256_point_add_affine` | 9 (5 in loops) | x19–x21 | none | 496 B |
| `p256_point_mul` (for comparison, unchanged) | — | x19–x24 | 1 | 352 B |

`regpressure.py` rates `mul_base` MEDIUM ("loop carries 19 live registers") —
that is the eight accumulators of the constant-time table scan plus the
pointer/mask/counter set, it is inherent to scanning without branching, and
it does not spill. `add_affine` rates NONE. `scripts/validate_clobbers.py`
agrees with both headers.

**Binary size is the real cost: +66,224 bytes stripped (+28.9%)**, of which
61,440 is the table itself and the rest is code plus `__DATA` page alignment.
This is a deliberate trade — prompt 04 flagged the table size as the reason to
gate the comb behind a profile, and `docs/PROFILE-POST.MD` §10 accepted it at
an estimated 64 KB. For a server binary that already embeds ~200 KB of
pre-compressed assets, 60 KB to make every connection 1.7x cheaper is worth
it; for a size-constrained target it would not be, and a 3-bit comb (86
blocks × 7 entries = 38.5 KB, 86 additions) is the obvious dial.

**The transfer scenario** measured 84.6 µs/asset before and ~90 µs after. That
path contains no P-256 at all, the two sweeps after the change agreed with
each other (89.6, 90.8) and both sit inside the ±10.4% spread
`docs/PROFILE-POST.MD` §1 documents for this scenario specifically. It is
session noise, not a regression — which is why the baseline above was
re-measured in the same session rather than quoted from the prompt-05 doc.

---

## 6. What this exposes next

Signing is now 87.9 µs, of which the comb is 38.5 µs. The remaining ~49 µs is
the scalar-field chain, and it was measured rather than inferred:
**`p256_scalar_inv` is 43.3 µs of it** — the Fermat inversion `k^-1 mod n`,
which is ~430 iterations through the 100.0 ns `p256_scalar_mul`
(`docs/PROFILE-POST.MD` counted 427 `p256_scalar_mul` calls per connection,
essentially all of them from inversion). 38.5 + 43.3 = 81.8 µs accounts for
93% of the signature; everything else — three `p256_fe_frombytes`, two
`p256_scalar_reduce`, two `p256_scalar_mul`, two `p256_fe_tobytes` — is the
remaining ~4 µs. The inversion was 12% of a 355 µs signature; it is now **half
of an 88 µs one**.

By the same "smaller pie, bigger slice" logic that made `crypto_random_bytes`
visible last cycle, the ranking after this change is likely:

1. `p256_scalar_inv` — a constant-time binary/Bernstein-Yang inversion, or
   simply a shorter addition chain, against a measured 43.3 µs/connection.
2. `crypto_random_bytes` — still re-opening `/dev/urandom` three times per
   connection, ~25 µs/connection (`docs/PROFILE-POST.MD` finding 4), now a
   *larger* share of a smaller connection than when it was found.

Both are worth a fresh profile before either is started, on exactly the
grounds prompt 04 applied to this work.
