# P-256 field multiplication — an unrolled 4x4 product, and measured effect

Picks up the item `docs/P256-SCALAR-INVERSION.md` §6 identified as the next
bottleneck, after re-confirming it with a fresh profile rather than trusting the
estimate. §6 predicted it from measured components; `scripts/profile_samples.py`
then put **`p256_bn_mul` at 9.05% of the handshake workload's busy samples — the
largest single compute cost in the server**, ahead of `crypto_random_bytes`
(8.74%) and every X25519 routine. That measurement, not the estimate, is what
this change is aimed at.

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback. Numbers do not transfer
to Cortex/Neoverse.

---

## The one-line answer

`p256_fe_mul` was reaching a *generic* schoolbook loop that works for any
`(na x nb)` shape, and paying a load, a store, two index computations and two
branches for each of the sixteen limb products. The algorithm is unchanged — it
is still schoolbook — but the loop is gone and the 512-bit product never touches
memory: **17.2 ns instead of 33.9 ns, 1.97x**, which takes a fixed-base point
multiplication from 39.4 µs to 26.4 µs and an ECDSA signature from 45.7 µs to
31.6 µs.

| | before | after | ratio |
|---|---:|---:|---:|
| `p256_fe_mul` | 33.9 ns | **17.2 ns** | **1.97x** |
| the 4x4 product alone (`fe_mul` − `reduce`) | ~26.7 ns | **~6.1 ns** | **~4.4x** |
| `p256_point_mul_base` | 39.4 µs | **26.4 µs** | **1.49x** |
| `p256_ecdsa_sign_with_k` | 45.7 µs | **31.6 µs** | **1.45x** |
| `p256_point_mul` (generic double-and-add) | 324.6 µs | **215.8 µs** | **1.50x** |
| handshake connection, **user** CPU (marginal) | 120.8 µs | **111.7 µs** | **1.08x** |
| `p256_reduce` (untouched, control) | 11.0 ns | 11.1 ns | 1.00x |
| `p256_bn_mul` 4x4 (untouched, control) | 26.7 ns | 27.9 ns | 1.00x |
| `p256_scalar_inv` (untouched, control) | 5.6 µs | 5.4 µs | 1.00x |
| `p256_scalar_mont_mul` (untouched, control) | 11.5 ns | 11.5 ns | 1.00x |

Baseline and candidate were built as two binaries up front and run back to back
in one session, alternating, for the reason recorded in
`docs/P256-SCALAR-INVERSION.md` §5: a freshly launched process reads high while
the CPU ramps, so figures taken on different days do not compare.

The four controls matter as much as the wins. `p256_scalar_inv` and
`p256_scalar_mont_mul` do not touch `p256_fe_mul` at all — they are arithmetic
mod *n*, not mod *p* — and they are flat, which is what says the improvement is
the field multiply and not the machine being in a better mood.

---

## 1. What changed

### 1a. The product stopped being a generic loop

`p256_bn_mul(out, a, na, b, nb)` is a general multi-precision multiply. It is
still there, and still correct, and `src/crypto/p256_scalar/mul.S` still calls
it for the 5x5 and 5x4 shapes its Barrett reduction needs. What changed is that
the field path stopped using it.

The inner loop body was, per limb product:

```
ldr   x11, [x3, x10, lsl #3]   // b[j]
mul   x12, x8, x11             // the actual work
umulh x13, x8, x11             // the actual work
add   x14, x7, x10             // index
ldr   x15, [x0, x14, lsl #3]   // read the accumulator back
adds  x15, x15, x12
cset  x16, cs
adds  x15, x15, x9
cset  x17, cs
str   x15, [x0, x14, lsl #3]   // write the accumulator back
add   x9, x13, x16
add   x9, x9, x17
add   x10, x10, #1
b     .Lbn_mul_inner
```

Two instructions of that are the multiply. The accumulator lives in memory
because the loop cannot know how many limbs there will be, so every partial sum
round-trips through the stack, and the carry is rebuilt out of two `cset`s
because it cannot be kept in NZCV across the loop back-edge.

Unrolled at a fixed 4x4, none of that is necessary. The accumulator is eight
registers, the carry stays in NZCV across a whole row, and a row is one `ldr`
plus eight multiplies plus eight adds. See `P256_FE_PRODROW` in
`src/crypto/p256/sqr_mul.S`.

### 1b. The product stopped touching memory at all

`p256_fe_mul` used to be:

```
sub sp, sp, #96          // frame + an 8-limb product buffer
bl  p256_bn_mul          // writes T[0..7] to the stack
bl  p256_reduce          // reads T[0..7] back off the stack
add sp, sp, #96
```

`p256_reduce` opens by loading those eight limbs into eight named registers.
The product now produces its result *directly in those eight registers*, in
that order, and control falls into `p256_reduce` at a label past its four
`ldp`s:

```
.Lreduce_regs:                 // T already in x14,x15,x16,x17,x2,x3,x4,x5
```

That removes the 8-limb stack buffer, eight stores, eight loads, two calls and
two returns. It also removes the stack frame entirely: with nothing called and
nothing spilled, `p256_fe_mul` is a leaf that touches no callee-saved register
and never writes x30, and the `ret` at the end of `p256_reduce` returns to
*`p256_fe_mul`'s* caller.

The whole product had to fit in x0–x17 for that to work, since using any of
x19+ would need a frame to save them and the fall-through leaves nowhere to
restore. It fits exactly: out, the b pointer, four `a` limbs, one `b` limb,
three scratch, eight accumulator — eighteen registers.

### 1c. Why 2x and not more

The product went from ~26.7 ns to ~6.1 ns, which is 4.4x, but `p256_fe_mul` only
halved — because the Solinas reduction `prompts/04` delivered was already fast
and is now the *larger* half of the function, 11.1 ns of 17.2 ns. Further work on
the field multiply means working on the reduction, not the product.

---

## 2. What had to be proved, not assumed

The algorithm did not change, so the algorithm is not the risk. The risk is the
hand-written carry chain, which is where this repo has shipped bugs before
(`.claude/skills/verified-asm-crypto` documents two). One property carries the
whole shape:

> Row *i* accumulates `a[0..3] * b[i]` into `T[i..i+4]` and must not carry out
> of `T[i+4]`.

If it could, the routine would need a propagation loop into the higher limbs and
the flat unrolled form would be wrong. It cannot, and that is forced rather than
observed: after row *i* the accumulator holds exactly

```
a * (b mod 2^(64*(i+1)))  <  2^256 * 2^(64*(i+1))  =  2^(64*(i+5))
```

so it fits in *i*+5 limbs with nothing left over. The bound is *tight* — the
maximum partial product is just under the capacity, not comfortably below it —
which is why it is worth stating rather than waving at:

```
row 0: max partial 2^320.000 < 2^320 capacity  OK
row 1: max partial 2^384.000 < 2^384 capacity  OK
row 2: max partial 2^448.000 < 2^448 capacity  OK
row 3: max partial 2^512.000 < 2^512 capacity  OK
```

Row 0 has a second, smaller obligation: it ends `adc x2, x2, xzr`, adding a
carry bit to a `umulh` result. `umulh` of two 64-bit words is at most 2^64−2,
attained only at (2^64−1)², so adding one cannot overflow a limb.

`scripts/p256_fe_mul_derivation.py prove` checks both arguments numerically at
their extremes and then replays the actual instruction sequence with the bounds
as assertions.

---

## 3. A bug this found — in the verification substrate, not the assembly

Sweeping edge-case operand pairs through the model turned up a product that made
`p256_reduce`'s Python reference assert. The reference is
`scripts/p256_reduce_derivation.py`, and its `ext == 0` guarantee is the thing
`p256_reduce`'s header cites as "proven over 2M+ random and adversarial cases".

The assembly was right. The reference was wrong.

`p256_reduce` finishes with two branchless conditional-subtract-p rounds over a
*five*-limb value: four limbs plus a signed `ext`. The assembly subtracts all
five —

```
subs x12, x2, x12
sbcs x13, x3, x13
sbcs x14, x4, x14
sbcs x15, x5, x15
sbcs x17, x6, xzr        // ext participates
cset x16, cs             // the carry out of *that*
```

— but the Python modelled the decision as `if borrow == 0` over the low four
limbs only, so whenever `ext == 1` and the low four borrowed, the model refused
a subtraction the hardware performs, and reported a non-canonical result.

It survived 200,000 random 512-bit inputs because a random `T` essentially never
leaves `ext == 1` after the second fold. The pair that finds it is
`(2^256−1) * 0xffffffffffffffff_0000000000000000_0000000000000000_ffffffffffffffff`,
and the real assembly reduces it correctly — checked by running `p256_reduce`
itself on that input, not by reasoning about it.

Two fixes, both in the reference: the correction round now models the five-limb
`sbcs`, and that `T` is now a permanent entry in `edge_cases()`. `p256_reduce`
itself is unchanged, because there was nothing wrong with it.

The lesson is narrow and worth keeping: **a reference implementation is only
evidence to the extent that it is faithful to the thing it models**, and the
places where it silently is not are exactly the places random testing does not
reach. This one had been load-bearing for two previous changes.

---

## 4. Verification

| check | what it establishes |
|---|---|
| `p256_fe_mul_derivation.py prove` | the row bound and the `umulh` headroom hold at their extremes, and the transcribed instruction sequence obeys them |
| `p256_fe_mul_derivation.py check 20000` | 20,000 products — 324 of them edge x edge pairs — match Python's arbitrary-precision `a*b`, and their reductions match `(a*b) % p` |
| `p256_fe_mul_derivation.py interop 25` | 25 public keys computed with **every** field multiply routed through the modelled carry chain (91,854 of them) agree with `cryptography`/OpenSSL |
| `tests/unit/test_p256/mul_carry.c` | 195 assertions on hardware: 45 generated vectors plus `out == a`, `out == b`, `out == a == b`, and `p256_fe_sqr` in place |
| `tests/unit/test_p256/mul.c`, `reduce.c`, `inv.c` | the pre-existing field tests, unchanged, still pass |
| `tests/unit/test_p256_point/*`, `test_p256_ecdsa/*` | point and signature tests, which reach `p256_fe_mul` some 700 times per case |
| `make test` | 4090 → 4304 tests, all passing |
| `scripts/validate_clobbers.py` | AGREE 139 → 140; the changed headers match what the binary actually clobbers |
| `tests/h2_browser_sim.py` | a real TLS 1.3 handshake and HTTP/2 page load against the built server |

The model is deliberately *not* `(a * b)`. It reproduces every 64-bit
truncation and every carry-out in the order the assembly performs them, so that
comparing it against Python's native multiply is a real cross-check rather than
a tautology.

---

## 5. Constant-time properties

Stronger than before, and for a structural reason: the new product is
**straight-line**. It has no branches at all — not even data-independent ones —
where `p256_bn_mul` had three nested loops. There is no data-dependent
addressing: `a` and `b` are read at fixed offsets, and the only memory written
is the caller's 4-limb output.

What was **not** done, stated plainly so it is not mistaken for a stronger
claim: no dudect-style timing test, no PMU cycle-count distribution over secret
inputs. The argument is structural — no branches, no data-dependent addresses,
and `mul`/`umulh` are fixed-latency on this core — not statistical.

---

## 6. Cost measured, including what did not move

**Code size.** `__text` grows 44,508 → 44,732 bytes (+224 B) for this change:
the unrolled rows cost more instructions than the loop, and the removed frame,
removed buffer and two removed call sequences give some of it back. The
stripped binary is unchanged at 295,624 bytes — the growth fits in page slack.
(With `docs/ENTROPY-SOURCE.md`'s change on top, which shrinks `__text`, the
batch nets out at 44,636 bytes.)

**End-to-end, this change alone.** Marginal server CPU per handshake connection
did **not** move outside noise. Its *user* component did — 120.8 → 111.7 µs,
1.08x — but the total did not, because roughly half of a connection's CPU is
kernel time in the read and write syscalls, and this change touches no syscall.
The profiler's per-scenario sys-time spread (±5–10%) is larger than the 9 µs
saved.

That is not a disappointing result, it is a directional one: it says the P-256
work had reached the point where **the syscall path, not the field arithmetic,
sets the cost of a connection**. Acting on that is
`docs/ENTROPY-SOURCE.md`, and with both changes in place the handshake
connection goes 235.2 → 192.4 µs (1.22x).

**What got slower.** Nothing measured. `p256_bn_mul` is still built and still
called by `p256_scalar_mul`; it is neither faster nor slower, it just has one
fewer caller.

---

## 7. What this exposes next

With `p256_bn_mul` out of the field path, it has left the profile's top 14
entirely. The handshake workload's remaining compute now ranks:

| function | share of busy |
|---|---:|
| `x25519_fe_mul` | 7.21% |
| `p256_reduce` (i.e. all of `p256_fe_mul`) | 5.50% |
| `x25519_fe_sqr_times` | 4.76% |
| `p256_fe_mul` (the product rows) | 1.02% |
| `p256_scalar_mont_mul` | 1.02% |

**X25519 is now the largest crypto cost in a handshake** — 13.3% of busy
samples across its routines, against 8.0% for all of P-256 — and it has had none
of the attention P-256 has had. `x25519_fe_mul` is the specific target.

Two smaller P-256 items remain, both previously listed and both still real:

- `p256_fe_inv` is still naive square-and-multiply over the bits of `p-2`: 256
  squarings + 128 multiplies = 384 operations, where the addition-chain
  treatment `docs/P256-SCALAR-INVERSION.md` applied to the scalar path gives
  roughly 270. It is called once per point multiplication.
- `p256_fe_sqr` is still a trampoline into `p256_fe_mul`. A dedicated squaring
  saves six of the sixteen limb products, since the off-diagonal terms appear
  twice — but it needs its own doubling carry chain and its own proof, and the
  squarings inside `p256_fe_inv` are where it would pay.

Per the discipline this change followed, neither should be started without a
fresh profile confirming the ranking first.
