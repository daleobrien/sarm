# P-256 scalar inversion — Montgomery arithmetic, an addition chain, and measured effect

Picks up the item `docs/P256-FIXED-BASE-COMB.md` §6 identified as the next
bottleneck. Once the fixed-base comb had taken `k*G` out of first place,
`p256_scalar_inv` was **the single largest cost in an ECDSA signature** — 45.2 µs
of an 86.4 µs signature, more than the point multiplication it sits next to.
That measurement, not a guess, is what this change is aimed at.

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback. Numbers do not transfer
to Cortex/Neoverse.

---

## The one-line answer

`a^-1 mod n` was paying twice over — a modular multiply whose reduction cost
three times its multiplication, run 425 times by naive square-and-multiply.
Both halves are now different: **5.3 µs instead of 45.2 µs, 8.5x**, which takes
ECDSA signing from 86.4 µs to 45.8 µs (**1.89x**) and a TLS handshake
connection from 267.9 µs to 225.5 µs — measured baseline-and-candidate in the
same session, against a test suite that grows from 3843 to 4090 and passes.

| | before | after | ratio |
|---|---:|---:|---:|
| `p256_scalar_inv` | 45.2 µs | **5.3 µs** | **8.53x** |
| `p256_ecdsa_sign_with_k` | 86.4 µs | **45.8 µs** | **1.89x** |
| handshake connection (server CPU, marginal) | 267.9 µs | **225.5 µs** | **1.19x** |
| page-load connection (server CPU, marginal) | 409.0 µs | **363.4 µs** | **1.13x** |
| one modular multiply (`p256_scalar_mul` → `p256_scalar_mont_mul`) | 107 ns | **11.7 ns** | **9.1x** |
| `p256_point_mul_base` (untouched, control) | 40.6 µs | 40.5 µs | 1.00x |
| `p256_fe_mul` (untouched, control) | 33.0 ns | 33.4 ns | 1.01x |
| production binary (`make production`) | 295,400 B | 295,624 B | +224 B |

The request path on an established connection contains no P-256 at all and is
untouched; the profiler's marginal fit puts it at 11.92 µs/request.

---

## 1. What changed, and why it is this much faster

`p256_scalar_inv` computes `a^(n-2) mod n` by Fermat, and it did so before this
change too. The contract is also unchanged: `a` is taken as a raw 4-limb value
and the answer is `(a mod n)^(n-2)`, because `p256_ecdsa_sign_with_k` feeds its
nonce straight out of `p256_fe_frombytes` without reducing mod n first. What
changed is *both* factors of `cost = (number of multiplies) x (cost of one)`.

### 1a. The multiply: Barrett → Montgomery

`p256_scalar_mul` is a 4x4 product followed by a Barrett reduction, and the
Barrett step is two further `p256_bn_mul` calls — a 5x5 and a 5x4. That is **45
limb products to reduce a result that took only 16 limb products to compute**.
Montgomery reduction is four rounds of `m = T[i] * n0inv` followed by
`T += m*n << 64i`: 4 products for the multipliers and 16 for the modulus
additions, **20 instead of 45**. Being a dedicated 4-limb routine rather than a
composition, it also drops three function calls and `p256_bn_mul`'s generic
index-driven inner loop.

Measured, on the same operands: **107 ns → 11.7 ns, 9.1x.**

`p256_scalar_mul` itself is *not* touched. It keeps its plain-domain contract,
and outside the inversion it runs twice per signature and twice per
verification — about 210 ns — so converting it would trade real ABI churn for
nothing measurable.

### 1b. The schedule: bits of n-2 → an addition chain

`n-2` is a public curve constant, so the order of operations is free to be
anything. The old loop walked its 256 bits: one squaring each, plus a multiply
for each of the 169 set bits — **425 modular multiplications**.

Its binary form has structure worth using:

```
n-2 = ffffffff 00000000 ffffffffffffffff bce6faada7179e84f3b9cac2fc63254f
      └─ 32 ones ─┘└ 32 zeros ┘└─ 65 ones ─┘└──── 128 unstructured bits ────┘
```

So the chain is built around `x^(2^k - 1)` ("k ones") values:

- a ladder builds `ones2..ones6` a bit at a time, then `ones8`, `ones16`,
  `ones32` by doubling (`ones2k = ones_k^(2^k) * ones_k`);
- the accumulator *starts* at `ones32`, which covers the top run for free;
- the 65-run is covered by applying `ones32` twice and then `ones1` — two
  multiplies more than building an `ones65` would need, but 35 chain steps
  cheaper, because `ones65` would cost 33 squarings to construct and be used
  once;
- the low 128 bits have no structure at all, but every run of ones in them is
  6 bits or shorter, so the same ladder covers them: one instruction per run,
  33 of them.

**257 squarings + 43 multiplies = 300**, against 425 — 29.4% fewer.

The chain lives as a 44-instruction program in
`src/crypto/p256_scalar/inv_chain.S` (180 bytes) that `inv.S` interprets, not
as unrolled code (~5 KB). Four bytes per instruction — dst slot, src slot,
squaring count, multiply slot:

```
t = slot[src];  t = t^(2^nsq);  if mul != 0xFF: t *= slot[mul];  slot[dst] = t
```

`nsq` is always ≥ 1, which is why there is no slot-copy opcode: the first
squaring reads `src` and writes `dst`.

### 1c. Why 8.5x and not 9.1 x 1.42 = 12.9x

The two factors do not multiply cleanly, and the benchmark says so out loud: it
prints `mults_per_inv`, which comes out around **450–500, not 300**. The
difference is dependent-chain latency. In the microbenchmark, `mont_mul` runs
back-to-back on the same operands and the M3 pipelines it to an 11.7 ns
*throughput*; inside the chain each squaring consumes the previous one's
result, so what is paid is latency, plus the interpreter's per-step overhead
and `mont_mul`'s own prologue/epilogue. 5.3 µs / 300 ≈ 17.7 ns per step is the
honest per-multiply figure on this workload.

---

## 2. What had to be proved, not assumed

`scripts/p256_scalar_inv_derivation.py prove` establishes four things.

**The chain reconstructs exactly n-2.** Not "it produced the right answer on
some inputs" — the chain is replayed with *multiply replaced by integer
addition*, so each slot literally holds the exponent it stands for, and the
final accumulator is compared against `n-2` as an integer. The same replay
checks that every `ones_k` slot really holds `2^k - 1` and that no instruction
reads a slot before something has written it.

**The Montgomery bounds the assembly depends on.** The word-level Python model
is not `(a * b * pow(R,-1,N)) % N`; it is the exact carry sequence
`mont_mul.S` executes, so a carry bug is one the Python can also have — and
therefore one that testing can catch, rather than both being right for
different reasons. It asserts, on every call:

- the product's second carry chain never escapes `T[i+4]` — which holds
  because `T[i..i+3] < 2^256` and `a*b[i] <= (2^256-1)(2^64-1)`, so their sum
  is `< 2^320`. This is what licenses the assembly emitting *no* instruction
  for that carry;
- each reduction round really does zero its own limb (`T[i] + m*n[0] == 0 mod
  2^64`), which is the whole point of the choice of `m`;
- the 9th result word never exceeds 1;
- the output is `< 2n`, so **one** conditional subtraction is enough.

Driven over 5100 products: both operands at `n-1`, values above `2^255`, the
`R^2` constant, and randoms. 2031 of them needed the conditional subtract, so
that path is genuinely exercised rather than nominally present.

**The reduction of the input is load-bearing, not cosmetic.** `mont_mul`'s
operand bound is `< n` and `p256_scalar_inv`'s input is only bounded by
`2^256`, so the `p256_scalar_reduce` on the way in is required. The proof runs
`a = n`, `a = n+1` and `a = 2^256-1` through the full structure.

---

## 3. Verification

Following `.claude/skills/verified-asm-crypto`, in order:

| step | what |
|---|---|
| Python prototype | `scripts/p256_scalar_inv_derivation.py` — Montgomery at word-and-carry level, chain builder, and an inversion structured exactly as `inv.S` |
| independent cross-check | `interop` signs 150 messages with the `cryptography` package (OpenSSL), recovers each `k` from the real signature, and confirms the model's `k^-1` rebuilds the same `s`. `check` runs 3009 inversions against Python's own `pow(a, n-2, n)` |
| port | `mont_mul.S` (188 instructions, no calls, no branches), `inv.S` (60 instructions), `inv_chain.S` (generated) |
| generated vectors | `gen-test-mont` → 44 vectors, 176 assertions; `gen-test-inv` → 45 inputs, 88 assertions. Both emitted from the validated Python, never hand-transcribed |
| real hardware | 4090 unit tests pass (from 3843); clean top-level `make`; `tests/h2_browser_sim.py` completes a real TLS 1.3 + HTTP/2 page load over all six embedded assets |

Two things the generated tests deliberately do that a thinner suite would not:

- **`mont_mul` is tested for aliasing** — `out == a`, `out == b`, and
  `out == a == b` (the squaring case, which is 257 of the chain's 300 steps).
  Both operands reach registers before anything is stored, which is what makes
  this safe, and the test is what makes it checked.
- **`inv` is cross-checked through code it does not share.** Beyond the vector
  comparison, every input is verified by `a * a^-1 == 1 mod n` computed with
  `p256_scalar_mul` — which is Barrett and has no Montgomery step anywhere in
  it. The benchmark applies the same check before it times anything, because a
  fast wrong inversion would produce perfectly plausible numbers.

The `inv.c` test file is regenerated rather than extended, and now covers the
whole 4-limb input range — `0`, `n`, `n+1`, `2^256-1` — rather than only
`[1, n-1]`, because signing can reach all of them.

---

## 4. Constant-time properties, and what was actually checked

**Structurally:**

- `p256_scalar_mont_mul` is straight-line: no branches at all, no
  data-dependent addressing, and the single conditional subtraction is `CSEL`,
  not a branch. `validate_clobbers.py` agrees with its declared clobber set
  (140 agreements, no mismatches across the tree).
- `p256_scalar_inv`'s loop branches only on the chain program, which — like
  the exponent it encodes — is a public curve constant. This is the same
  reasoning the previous implementation used to branch on the bits of `n-2`,
  and that `p256_fe_inv` still uses. Nothing branches on `a`.
- Table addressing in the interpreter comes from program bytes, not from the
  secret, so no slot index is secret-dependent.

**What was not checked:** this is an argument from structure, not a
measurement. There is no `dudect`-style statistical timing test in the repo and
no PMU access on this machine, so "constant time" here means "no branch or
address depends on secret data by inspection and by the analysis tooling",
not "measured to leak nothing".

One property worth being explicit about: the number of Montgomery
multiplications is **fixed at 300 regardless of the input**, where the previous
implementation's was also input-independent (it walked a fixed exponent). Neither
version's *count* varied; what varied in neither is what matters.

---

## 5. Cost measured, including the costs that went up

**Binary size** (`make production`, stripped): 295,400 → 295,624 B, **+224 B**
on disk. The breakdown is `__text` +800 B (the unrolled `mont_mul`, minus the
old inversion loop it replaced) and `__data` +224 B (the 180-byte chain program
plus the `R^2` and `n0inv` constants). The on-disk figure is smaller than the
code growth because `__TEXT` had page slack; the honest number for "how much
code did this add" is the +800 B.

**Register pressure.** `regpressure.py` reports `p256_scalar_mont_mul` at 21
peak live GPRs against the 18 caller-saved available, so it must use
callee-saved registers and its `opportunity: HIGH — 6 callee-saved reg(s)
never hold a value across a call` is a leaf-function blind spot in the
heuristic, not slack. This was tested rather than asserted: a variant holding
eight scratch registers (all eight `mul`/`umulh` results live at once, an
80-byte frame) was A/B'd against the four-scratch version now in the tree
(48-byte frame) on the real chain, and the two were indistinguishable —
5485/5493/5720 ns against 5293/5518/5500 ns. The cheaper frame won on a tie.
`p256_scalar_inv` itself reports `opportunity: NONE`.

**A measurement trap worth recording.** The first inversion benchmark in a
freshly launched process reads ~8.4 µs against a steady-state ~5.3 µs, even
with a 20-iteration warm-up inside the program. That is CPU frequency ramp, not
the code; every figure in this document is the warm one, and the A/B was run
baseline-and-candidate in the same session for the same reason.

**What was deliberately not done:**

- **No dedicated Montgomery squaring.** 257 of the 300 chain steps are
  squarings, and squaring needs only 10 limb products in phase 1 instead of 16
  (the cross terms are computed once and doubled). Estimated ~10-15% off the
  inversion, i.e. ~0.7 µs, or ~1.5% of a signature — not worth a second
  hand-written carry chain to verify at this point in the ranking.
- **No exploiting n's limb structure.** `n[2] = 2^64-1` and `n[3] = 2^64-2^32`,
  so `m*n[2]` and `m*n[3]` are shifts and subtractions rather than
  multiplications; that would drop 8 of the 20 reduction products. Same
  reasoning — real, but it buys less than the next item on the list.

---

## 6. What this exposes next

With the inversion at 5.3 µs, a signature is 45.8 µs and
**`p256_point_mul_base` is 40.5 µs of it — back in first place.** Inside it,
`p256_fe_inv` (the field inversion in `p256_point_to_affine`) is 13.1 µs.

The interesting number is this one:

| | ns |
|---|---:|
| `p256_bn_mul` 4x4 (the product inside `p256_fe_mul`) | 27.9 |
| `p256_reduce` (Solinas, the reduction inside `p256_fe_mul`) | 11.1 |
| `p256_fe_mul` (both) | 33.0 |
| **`p256_scalar_mont_mul` (a 4x4 product *and* a full reduction)** | **11.7** |

A whole Montgomery multiply now costs less than half of what the *product
alone* costs on the field side, because `p256_fe_mul` still reaches
`p256_bn_mul`'s generic index-driven loop. The Solinas reduction that
`prompts/04` delivered is already fast (11.1 ns); it is the multiplication that
is now the slow half. Unrolling a dedicated 4x4 product for the field path is
the obvious next move, and it applies to every one of the ~700 field multiplies
a comb point-multiplication performs.

`p256_fe_inv` compounds it: it is still naive square-and-multiply over the bits
of `p-2` (256 squarings + 128 multiplies = 384 operations) where the same
addition-chain treatment applied here would bring it to roughly 270 — and it is
called once per point multiplication.

Both are estimates from measured components, not measurements. Per the
discipline `prompts/04` set and this change followed, neither should be started
without a fresh profile confirming the ranking first.

The other item `docs/P256-FIXED-BASE-COMB.md` §6 listed — `crypto_random_bytes`
re-opening `/dev/urandom` three times per connection, ~25 µs — is untouched and
now a *larger* share of a handshake connection than before, simply because
everything around it got smaller.
