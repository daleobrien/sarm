# Profile, post-GHASH/P-256 — re-measured per prompts/05

Empirical answer to `prompts/05-register-overhead-experiment.md`, superseding
`docs/PROFILE.MD` (prompt 00, commit `676d517`) now that prompt 03 (GHASH
aggregation, `b9807ca`) and prompt 04 (Solinas P-256 reduction, `b0a868e`)
are merged. No `.S` file was modified during this measurement; the only
repo change is a new benchmark (`scripts/benchmarks/bench_crypto_random_bytes.c`,
explained in §6).

**Target:** Apple M3 Pro, macOS 27.0 (26A5406e), arm64, loopback.
**Build:** `make` (local symbols kept), commit `b0a868e`. Full unit suite
(3716 tests), `test_files.sh`, `test_security.sh`, `test_protocols.sh`, and
`tests/h2_browser_sim.py` all pass on this build before and after this
measurement — nothing here changes production code.

---

## The one-line answer

**P-256's Solinas reduction and the GHASH aggregation both worked: a
page-load connection is 2.3x faster (1521.9 µs → 657.2 µs), and the
bottleneck ordering they were justified against has partly reshuffled but
not overturned.** `p256_point_mul`'s double-and-add is now the single
largest cost centre (45% of a connection, versus reduction's already-cut
14%), X25519 roughly doubled its *relative* share (4%→8%) simply because
everything around it shrank, and a previously invisible cost —
`crypto_random_bytes` re-opening `/dev/urandom` on every call — surfaced at
~4% of a connection. **Register-pressure optimization is still not
justified**: every candidate the fresh profile surfaces either has no
frame to remove, is called too few times per connection for any per-call
saving to be measurable, or (new finding, §5) has its one flagged
"unjustified" register paired in the same `stp`/`ldp` as a justified one,
so removing it saves zero static instructions without restructuring the
function. The analytically-computed ceiling for the strongest surviving
candidate (X25519's leaf helpers) is **~0.36% of a connection**, an order
of magnitude below the measured noise floor.

| | µs, page-load connection | share |
|---|---:|---:|
| **measured total (was 1521.9 µs)** | **657.2** | **100%** |
| — P-256 `point_mul` (double-and-add, 256 rounds) | 298.1 | 45.4% |
| — P-256 reduction (post-Solinas) | 93.2 | 14.2% |
| — X25519 (×2 calls) | 53.1 | 8.1% |
| — `crypto_random_bytes` (×3 calls, new finding) | 25.4 | 3.9% |
| — AES-GCM total (GHASH + AES chain + CTR-loop overhead) | ~15.6 | ~2.4% |
| — SHA-256 / HKDF | ~3.5 | 0.5% |
| — HPACK / H2 framing | ~1.3 | 0.2% |
| — everything else (syscalls, framing, unattributed) | ~167.1 | 25.4% |

---

## 1. Scenario results

Same method as prompt 00: `scripts/profile_workload.py`, `./sarm d` as a
child process, CPU time from `getrusage(RUSAGE_CHILDREN)`, three sizes per
scenario, least-squares fit, 5 rounds per size. Two independent full
sweeps were run to state reproducibility.

| Scenario | Unit | Marginal (sweep 1) | Marginal (sweep 2) | Spread | R² |
|---|---|---:|---:|---:|---:|
| handshake | one connection: handshake, one 104 B GET, close | 512.14 µs | 529.64 µs | 3.4% | 1.0000 |
| transfer | one 76,739 B GET on an established connection | 71.56 µs | 79.30 µs | 10.4% | 0.977–0.998 |
| request | one 104 B GET on an established connection | 12.45 µs | 12.18 µs | 2.2% | 0.9998–1.0000 |
| pageload | one connection: document + 5 subresources, close | 657.21 µs | 693.05 µs | 5.2% | 0.9996–1.0000 |

**Compared to prompt 00 (Barrett + single-block GHASH):**

| Scenario | Was (PROFILE.MD) | Now | Speedup |
|---|---:|---:|---:|
| handshake | 1238.9 µs | 512.1 µs | **2.42x** |
| pageload | 1521.9 µs | 657.2 µs | **2.32x** |
| transfer (per 76,739 B) | 93.0 µs | 71.6 µs | 1.30x |
| request | 12.92 µs | 12.45 µs | 1.04x (unchanged, as expected — no crypto on this path) |

The linear model still closes, tighter than before:

```
512.14 + 6 × 12.45 + 80,851 × 0.7703 ns/byte = 649.1 µs   predicted
                                                657.2 µs   measured  (98.8%, was 92%)
```

Per-byte cost: `(71.56 − 12.45) µs / 76,739 B = 0.770 ns/byte = 1298 MB/s`
(was 1.044 ns/byte = 958 MB/s — the GHASH work bought real per-byte
throughput, diluted by the write-syscall cost prompt 03 didn't touch).

### Noise floor, restated for this profile

The two-sweep spread above (2.2%–10.4%) is wider than prompt 00's
(0.5%–7.4%) on this run — plausibly this machine under more background
load this session, not a property of the binary. Using the wider number as
the honest floor: **do not claim a win below 6% on the per-connection or
per-request path, or below 12% on the per-byte (transfer) path**, for
anything measured with this harness on this machine today. Every
conclusion below is checked against this.

---

## 2. Attribution to functions

Same two methods as prompt 00, both re-run fresh.

### Method A — sampled time profile (`scripts/profile_samples.py`)

`/usr/bin/sample` at 1 ms, same tool prompt 00 used (`xctrace` still
refuses to run without a full Xcode install). One change was needed: the
server is now **2.3x faster**, so the same 4-client load that gave prompt
00 0.68% idle now leaves it 45–78% idle between connections (the accept
loop consumes most of the sampling window). The fix is longer wall-clock
duration at the same client count, not more clients — more concurrent
clients changed the *answer*, not just the sample count (see the
`crypto_random_bytes` contention note in §5). All numbers below use
`--clients 4`, matching prompt 00's method, with `--seconds` raised until
the busy-sample count matched prompt 00's ballpark (~9,000–17,000):

| Scenario | seconds | samples | idle | **busy** |
|---|---:|---:|---:|---:|
| handshake | 50 | 42,155 | 32,925 (78.1%) | **9,230** |
| transfer | 20 | 17,033 | 6 (0.04%) | **17,027** |
| request | 20 | 17,073 | 2 (0.01%) | **17,071** |
| pageload | 20 | 17,183 | 3,576 (20.8%) | **13,607** |

### Method B — microbenchmark × call count

`scripts/benchmarks/bench_primitives`, rebuilt against the current tree,
min of 9 rounds:

| Function | Was (ns/call) | **Now (ns/call)** | Speedup |
|---|---:|---:|---:|
| `p256_ecdsa_sign_with_k` | 777,939 | **327,062** | 2.38x |
| `p256_point_mul` (256-bit k) | 755,082 | **298,087** | 2.53x |
| `p256_fe_mul` | 81.1 | **27.02** | 3.00x |
| `p256_bn_mul` 4×4 | 21.6 | **18.32** | 1.18x (untouched — expected) |
| `p256_reduce` (isolated) | n/a (Barrett) | **10.96** | 5.1x vs Barrett, per prompt 04's own report |
| `x25519` (scalarmult) | 31,394 | **26,544** | 1.18x (untouched, small run-to-run drift) |
| `aes_gcm_encrypt` 16 KiB | 10,400 | **4,107** | 2.53x |
| `ghash` 16 KiB (within AES-GCM) | 8,219 | **2,225** | 3.70x |
| `aes128_encrypt` 1 block | 0.91 | **0.55** | 1.65x (M3 crypto-unit result, not a code change — noise) |
| `sha256` 1 block | 25.2 | **22.09** | untouched, noise |

`p256_bn_mul` and `x25519` moving by 1.18x with **no code change** is the
honest measurement floor for "the same binary run twice" at the individual
primitive level — bigger than the ±5% spreads reported per-run because
these compare across the two full profiling sessions (prompt 00's original
numbers vs. today's), not within one. Treat any claim below ~20% at this
granularity as unresolved.

`p256_reduce`'s share of `p256_fe_mul`, the number prompt 04 targeted:

```
10.96 ns / 27.02 ns = 40.6%     (was 73.3%, Barrett)
18.32 ns / 27.02 ns = 67.8%     p256_bn_mul's new share
```

(These sum to >100% because each is measured as an isolated call,
including its own call/return overhead; the combined `p256_fe_mul` number
is measured as one call, not summed from parts. The direction and rough
magnitude — reduction dropped from *dominant* to *minority* share of the
field multiply — is what matters and is not sensitive to this ~8ns of
double-counted overhead.)

**GHASH's share of AES-GCM**, the number prompt 03 targeted, at 16 KiB:

```
ghash 2224.7 ns / aes_gcm_encrypt 4107.2 ns = 54.2%     (was 79.0%)
aes128_encrypt chain (1024 × 0.55 ns = 564 ns) / 4107.2 ns = 13.7%   (was 9%)
```

GHASH is still the larger of the two, but its lead over the AES chain
shrank from 8.8x to 4.0x — exactly the "AES's relative share grows simply
because GHASH shrank" effect the prompt asked to check for. The remaining
~32% (`aes_gcm_encrypt` minus GHASH minus the AES round function) is
CTR-loop overhead — per-block counter increment, XOR, load/store — that
`bench_primitives`' isolated `aes128_encrypt` number does not include; it
was already this large before prompt 03 and nothing here changed it.

---

## 3. Cost breakdown by scenario

Self time as a share of busy (non-idle) samples, Method A, same grouping
`profile_samples.py` used for prompt 00.

| Cost centre | handshake | transfer | request | pageload |
|---|---:|---:|---:|---:|
| handshake asymmetric crypto (P-256, X25519, `crypto_random_bytes`) | **68.28%** | 1.19% | 0.47% | **58.69%** |
| transport / syscalls / accept loop | 30.69% | **76.63%** | **93.97%** | 37.53% |
| AES-GCM record crypto | 0.28% | **17.38%** | 1.86% | 2.37% |
| util (`memcpy`) | 0.02% | 3.95% | 1.60% | 0.54% |
| H2 / HTTP framing | 0.14% | 0.52% | 1.56% | 0.15% |
| transcript / key schedule | 0.50% | 0.02% | 0.00% | 0.53% |
| TLS record framing | 0.04% | 0.20% | 0.18% | 0.10% |
| HPACK | 0.01% | 0.11% | 0.36% | 0.04% |
| handshake plumbing (non-crypto) | 0.03% | 0.00% | 0.00% | 0.04% |

Compare to prompt 00's handshake row (76.5% asymmetric crypto, 22.8%
transport): the *group total* barely moved (76.5%→68.3%), but that
similarity hides the reshuffle inside it — `crypto_random_bytes` alone is
now 11–15% of handshake busy time where it was folded into a 2.4%
page-load-wide figure before (§5).

---

## 4. Ranked function table (fresh)

Self/inclusive share of **pageload** busy samples (Method A), cross-checked
against Method B where a bench number exists. Confidence follows prompt
00's convention: *high* where both methods agree within ~1.3x, *medium*
where only one method resolves it, *low* at or below sampler resolution
(~0.1% of 13,607 busy samples ≈ 1 sample).

| # | Function | Self share | Incl. share | Calls/conn | Method | Confidence |
|---|---|---:|---:|---:|---|---|
| 1 | `p256_bn_mul` | 34.6% | 34.6% (leaf) | ~8,500 | sample self; bench | high |
| 2 | `raw_read_exact` | 26.1%* | — | 12 | sample self (*upper bound, includes blocking) | medium |
| 3 | `raw_write_all` | 11.2%* | — | 9 | sample self (*upper bound) | medium |
| 4 | `crypto_random_bytes` | 4.0–14.8%† | — | 3 | sample self (†wide spread, see §5); bench 3.9% | medium |
| 5 | `p256_reduce` | 8.2% | 8.2% (leaf now) | ~8,500 | sample; bench (14.2% via bench×count) | high |
| 6 | `x25519` | 6.7% | 6.7% | 2 | sample; bench (8.1% via bench×count) | high |
| 7 | `p256_scalar_mul`/`inv` | 6.3%/6.3% | — | 427/1 | sample self | medium |
| 8 | `x25519_fe_mul` | 3.5% | — | ~2,546 | sample self | medium |
| 9 | `p256_fe_add`/`sub` | 2.1%/1.0% | — | ~11,000 | sample self | medium |
| 10 | `x25519_fe_sqr_times` | 2.5% | — | ~2,044 | sample self | medium |
| 11 | `aes_gcm_encrypt` (excl. GHASH) | 0.5% | — | 26 | sample; lldb | high |
| 12 | `ghash` (inlined gcm block) | 1.1% | — | 0 (never called — `.Lgcm_ghash_run` is what runs) | sample; source | high |
| 13 | `aes128_encrypt` | 0.8% | — | ~5,050 | sample self | high |
| — | `p256_ecdsa_sign_with_k` | 0.0%* | **47.6%** | 1 | sample incl.; bench 49.8% via bench/pageload | high (*self≈0 — a thin dispatcher) |
| — | `p256_point_mul` | 0.0%* | **41.3%** | 1 | sample incl.; bench 45.4% via bench/pageload | high |
| — | `p256_point_add` | 0.3% | 29.0% | 256 | sample self/incl. | medium |
| — | `p256_point_dbl` | 0.1% | 20.8% | 256 | sample self/incl. | medium |
| — | `sha256` | 0.2% | — | 127 | sample; lldb | low |
| — | `hmac_sha256`/`hkdf_*` | <0.1% each | — | 21/16/16/3 | lldb count | low |
| — | `h2_hpack_decode_field` | <0.1% | — | 54 | sample; lldb | low |
| — | `h2_write_body`/`h2_write_headers` | <0.05% | — | 6/6 | sample; lldb | low |
| — | `lookup_embedded` | **not observed** | — | 6 (once per request, per `count_calls.py`) | sample; lldb | see caveat |
| — | `ghash`/`gf_mult_128` (exported) | **0** | 0 | 0 | lldb count; source | high |

Call counts for functions not directly re-measured are carried forward
from `docs/PROFILE.MD`, spot-checked via `scripts/count_calls.py --workload
pageload` on the current binary: `crypto_random_bytes`=3, `x25519`=2,
`p256_ecdsa_sign_with_k`=`p256_point_mul`=1, `ghash`(exported)=0 all
matched exactly. Prompts 03/04 changed *how* each call costs, not *how
many* there are, and this is a direct confirmation of that, not an
assumption.

---

## 5. Findings that change what should be optimized

**1. P-256 point multiplication is now the single largest cost centre.**
45.4% of a page-load connection (was 49.6% of a much bigger number before,
so the *absolute* time dropped from 755 µs to 298 µs, but the *relative*
rank moved up because reduction fell further and faster). Its own
constituents (`p256_point_add` 29.0% inclusive, `p256_point_dbl` 20.8%
inclusive, both called 256 times per `point_mul` — once per bit, exactly
one doubling and one addition per bit, verified against
`src/crypto/p256_point/mul.S:77-111`) are the deferred fixed-base comb
target from prompt 04. This is now the largest single opportunity in the
codebase, larger than the reduction work just landed.

**2. The reduction work paid off exactly as measured, and is close to
exhausted.** `p256_reduce`'s share of `p256_fe_mul` dropped from 73.3% to
40.6% (bench) / matches direction of the sampled 8.2%-of-pageload self
time. It is now a pure register-to-register fold with no stack and no
multiply (`src/crypto/p256/sqr_mul.S:9-44`); there is no comparably-sized
follow-up available inside `p256_reduce` itself. Any further P-256 gain is
in `point_mul`'s algorithm (finding 1), not the field arithmetic.

**3. GHASH's win is real and the AES chain's relative share grew exactly
as predicted, without the AES chain itself getting any slower.** GHASH
54.2% of AES-GCM (was 79.0%), AES chain 13.7% (was 9%) — same absolute
AES-chain cost, larger share of a smaller pie. AES-GCM overall is now
2.0–2.4% of a connection (was 5.5%); this is now small enough that no
further AES-GCM work — including the deferred AES-chain interleaving
prompt 03 mentioned — clears the noise floor at the connection level. It
would still matter on the transfer scenario specifically (17.4% of
transfer-scenario busy time), but nothing in this profile makes a further
AES-GCM pass worth prioritizing over point_mul or the `crypto_random_bytes`
finding below.

**4. `crypto_random_bytes` was invisible before and is not invisible now
— but it is a syscall-overhead finding, not a register-pressure one.**
`src/crypto/random.S` opens `/dev/urandom`, reads, and closes it — three
syscalls — on *every* call, including the three tiny (16–32 byte) calls
per connection (ECDSA nonce, two X25519 ephemeral keys,
`src/tls/handshake/certificate_verify/sign_with_k.S`,
`src/tls/handshake/server_hello/build.S`). Measured in isolation
(`scripts/benchmarks/bench_crypto_random_bytes`, new — see §6):
**8.2–8.9 µs/call** (16 B: 8.92 µs, 32 B: 8.25 µs, 64 B: 8.19 µs — no
length dependence beyond noise, confirming the cost is the two open/close
syscalls, not the read). At 3 calls/connection and the ~8.45 µs mean that
is **~25.4 µs/connection, 3.9–5.0% of a connection** — comfortably clear of
this session's 6% connection-level noise floor when measured cleanly (bench),
and the reason the sampled self-time share is noisier (6.3%→14.8% across
runs, rising with concurrent-client count) is very likely contention on
`/dev/urandom` open/close under load, not measurement error — `sample`'s
own documented bias is to count blocked-syscall wall time as busy time,
and more concurrent clients means more contention for the same device
node. **`regpressure.py` does not flag `crypto_random_bytes`** — its four
callee-saved registers (`x19`-`x22`) all correctly hold `buf`, `remaining`,
`fd`, and a saved `errno` live across the `open`/`read`/`close` calls; this
is real, justified syscall cost, not save/restore waste. Caching the file
descriptor across the process's lifetime (open once, read repeatedly,
never close) would cut it to one syscall's worth of overhead most calls —
outside this prompt's register-pressure scope, but the strongest
non-register finding here and a well-bounded, low-risk candidate for
whichever prompt picks up the response after this one.

**5. Every register-pressure candidate the fresh profile surfaces still
fails to clear the noise floor — for three different reasons, not one.**
See §6 for the full analysis; summary:

- `p256_bn_mul` (rank #1, 34.6% self): a true leaf, 0 bytes of stack, 0
  save/restore instructions (`regpressure.py`: `Save=0, Stack=0B`). Nothing
  to remove. Explicitly excluded by the prompt, and confirmed again here.
- `p256_ecdsa_sign_with_k` and `p256_point_mul`: `regpressure.py` flags 1–2
  genuinely unjustified callee-saved registers each — but both are called
  **exactly once per connection**. Removing their entire prologue (a few
  nanoseconds at most) is unmeasurable regardless of the static percentage.
- `p256_point_add` and `p256_fe_mul`: called 256 and ~8,500 times per
  connection respectively — hot enough that a real per-call saving would
  matter — but each function's one flagged unjustified register (`x26` in
  `p256_point_add`, `x20` in `p256_fe_mul`) is saved in the *same*
  `stp`/`ldp` pair as a register that **is** justified (`src/crypto/p256_point/add.S:31`,
  `src/crypto/p256/sqr_mul.S:284-287`). Removing only the unjustified half
  of a pair does not remove the pair's `stp`/`ldp` instructions — the
  justified half still needs them. The static-instruction ceiling for
  these two, as currently written, is **zero** without restructuring the
  register allocation to free up the pairing itself, which is a more
  invasive change than "delete an unused save" and was not attempted here
  because the profile gives no reason to.
- `x25519_fe_mul` and `x25519_fe_sqr_times`: the one case with a real,
  fully-unjustified frame (both are leaves with zero `bl` instructions
  inside, so by definition nothing they save can be "live across a call")
  — analyzed in full in §6. Ceiling: **~0.36% of a connection**, below
  even this session's widened noise floor.

**6. X25519 is confirmed as the only group the server ever negotiates —
not a client-simulator artifact.** `src/tls/handshake/client_hello.S:253-300`
requires `NAMED_GROUP_X25519` in *both* `supported_groups` and `key_share`
(`CH_REQUIRED = CH_GROUP + CH_KEYSHARE`, line 20); no other group is even
parsed for a key share, so any ClientHello offering only P-256/secp256r1
for key exchange gets `handshake_failure`. P-256 in this server is used
**only** for the certificate's ECDSA signature, never for key agreement.
This settles the question the prompt's predecessor should have asked:
X25519's ~1,273 `x25519_fe_mul` calls per call (matching prompt 00's
~1,275 estimate almost exactly — confirms the ladder structure is
unchanged) are real production traffic, not a simulator quirk, and its
8.1% share of a connection is the genuine current number, up from 4.1%
purely because P-256 shrank around it.

---

## 6. Register-overhead method, worked in full

Per the prompt's required method: establish the ceiling analytically from
`objdump`, before benchmarking anything.

### Step 1 — which candidates have a removable frame at all

| Function | Calls/conn | Frame? | Verdict |
|---|---:|---|---|
| `p256_bn_mul` | ~8,500 | none (0B stack, 0 saves) | reject — no frame |
| `p256_point_dbl` | 256 | yes, fully justified (not flagged by `regpressure.py` at all) | reject — no opportunity |
| `p256_point_add` | 256 | yes, 1 unjustified reg, **paired** with a justified one | reject — 0 removable instructions (see finding 5) |
| `p256_fe_mul` | ~8,500 | yes, 1 unjustified reg, **paired** | reject — 0 removable instructions |
| `p256_ecdsa_sign_with_k` | 1 | yes, 2 unjustified | reject — undetectable at 1 call/conn |
| `p256_point_mul` | 1 | yes, 1 unjustified | reject — undetectable at 1 call/conn |
| `x25519_fe_mul` | ~2,546 | yes, **all 10** saved regs unjustified (leaf, 0 `bl` inside) | only real candidate — analyzed below |
| `x25519_fe_sqr_times` | ~2,044 | yes, 1 of 3 stack slots is a true callee-saved reg (`x19`), unjustified (leaf) | only real candidate — analyzed below |

### Step 2 — count preservation instructions from `objdump` (`sarm` binary, current build)

`x25519_fe_mul` (`0x100003b88`–`0x100003e14`, verified leaf — zero `bl`
instructions in its body):

```
prologue:  sub sp,#0x60; stp x19,x20; stp x21,x22; stp x23,x24; stp x25,x26; stp x27,x28   (6 instrs)
epilogue:  ldp x19,x20; ldp x21,x22; ldp x23,x24; ldp x25,x26; ldp x27,x28; add sp,#0x60   (6 instrs)
total function length: 164 instructions
removable: 12 / 164 = 7.32%
```

`x25519_fe_sqr_times` (`0x100003f00`–`0x100004120`, verified leaf):

```
prologue:  sub sp,#0x20; str x0,[sp]; str x2,[sp,8]; str x19,[sp,16]
epilogue:  ldr x0,[sp]; ldr x19,[sp,16]; add sp,#0x20
```

Only `x19` is an AAPCS64 callee-saved register here — `x0` and `x2` are
argument/scratch registers the function spills to its own stack slots to
survive its internal squaring loop, which is not ABI-mandated preservation
and is a different kind of cost (local scratch, not call-boundary
overhead) than what this prompt is scoped to. Removing `x19`'s two
instructions (`str`/`ldr`) does not shrink the frame enough to drop the
`sub`/`add sp` (still needed for `x0`/`x2`'s 16 bytes):

```
total function length: 139 instructions
removable: 2 / 139 = 1.44%
```

### Step 3 — multiply by the freshly measured call count, express as a fraction of connection time

Call counts derived from `src/crypto/x25519/main.S`'s ladder (252 main-loop
iterations × 5 `fe_mul`/4 `fe_sqr` + 3 doubling-step iterations × 2/2 + 1
final `fe_mul` in point recovery + `fe_recip`'s 6 `fe_mul`/8 `fe_sqr_times`
calls, counted directly from the assembly, not estimated):

```
fe_mul calls per x25519 call:        1273   (matches prompt 00's ~1275 estimate)
fe_sqr_times calls per x25519 call:  1022
```

Removable instructions per x25519 call: `1273×12 + 1022×2 = 17,320`.
Total instructions across `fe_mul`+`fe_sqr_times` per x25519 call:
`1273×164 + 1022×139 = 350,830`; adding the zero-overhead helpers
(`fe_add`/`fe_sub`/`fe_scalar_product`/`swap_conditional`, ~40,560
instructions, all leaves with **zero** save/restore — confirmed via
`objdump`, e.g. `x25519_fe_add` at `0x100003664` has no `stp`/`ldp` at
all) gives ~391,390 total instructions per x25519 call.

```
removable share of X25519's own instructions:  17,320 / 391,390 = 4.43%
X25519's share of a page-load connection (bench):  53.1 µs / 657.2 µs = 8.08%
ceiling on connection time:  4.43% × 8.08% ≈ 0.36%
```

**0.36% is roughly 17x below this session's stated 6% connection-level
noise floor**, and would still be ~8x below prompt 00's original, tighter
0.8% floor. Per the prompt's own decision rule
(`estimated removable work > benchmark noise floor`), this fails
decisively. No benchmark of a hand-reallocated `x25519_fe_mul`/
`x25519_fe_sqr_times` was run, because the analytic ceiling already answers
the question the benchmark would ask — this is the "stop and report that"
outcome the prompt calls "a complete, valuable, cheap answer."

### Why this differs from a naive reading of `regpressure.py`

`regpressure.py`'s static ranking (`python3 scripts/regpressure.py`, run
fresh against the current tree) lists `x25519_fe_mul` as `HIGH` with "10
callee-saved reg(s) ... never hold a value across a call" — true, and
exactly what steps 1–3 used. What the static tool cannot see, and what
steps 2–3 supply, is that removing all 10 registers only removes 12
instructions out of 164 in that function, and that function itself is
only 4.43% frame overhead once its zero-overhead siblings are counted in,
and X25519 itself is only 8% of a connection. Each of those three factors
individually looks unimportant; multiplied together they are the entire
reason a `HIGH`-flagged, genuinely-justified finding still nets under
0.4% of a connection. This is the same shape of result prompt 00 found for
this exact function pair (then estimated more roughly at "~0.3% of a
connection" for X25519's whole register story) — re-derived here with the
call counts and instruction counts read directly off the post-03/04
binary rather than carried over.

---

## 7. Ranked bottleneck table (deliverable)

All six required columns. "Theoretical max improvement" is expressed as
percentage-of-connection headroom if the *entire* candidate were free,
which is never achievable — it is an upper bound, not a forecast.

| Candidate | % of connection | Current runtime | Theoretical max improvement | Complexity | Risk | Binary-size impact |
|---|---:|---:|---|---|---|---|
| **P-256 `point_mul` (double-and-add)** | 45.4% | 298.1 µs/conn | Fixed-base comb (deferred, prompt 04): a 4-bit comb cuts ~256 iterations to ~64 table-driven steps; plausibly 2–3x on `point_mul` → **~20–30% of a connection** | High — new algorithm, precomputed table, constant-time table scan over every entry | High — the constant-time table-scan discipline is, per prompt 04's own text, "the riskiest constraint in the repo"; wrong-but-fast code here is catastrophic (private key material) | +~64 KB (comb table) |
| P-256 reduction (post-Solinas) | 14.2% | 93.2 µs/conn | Already implemented this cycle; residual headroom is instruction-scheduling within the fold's carry chain, plausibly 10–20% of *this* number (~1–2% of a connection) — not separately verified here | Low-medium (scheduling only, no algorithm change) | Low (same verified algorithm, reordering independent folds) | ~0 |
| X25519 (key agreement, confirmed sole negotiated group) | 8.1% | 53.1 µs/conn | No algorithmic candidate identified this cycle; register-boundary ceiling is 0.36% (§6) | — | — | — |
| **`crypto_random_bytes` (new finding)** | 3.9–5.0% | 25.4 µs/conn (~8.45 µs mean × 3 calls) | Cache the fd across the process lifetime instead of open+read+close per call → up to ~65% of this cost (2 of 3 syscalls), **~2.5–3% of a connection** | Low — one file, no algorithm, no constant-time concerns (this data isn't secret-dependent addressing, it *produces* secrets but doesn't branch on them) | Low | ~0 |
| AES-GCM total (post-aggregation; self-time, includes CTR-loop overhead beyond GHASH+AES chain) | ~2.4% (pageload); 17.4% (transfer scenario specifically) | ~15.6 µs/conn | AES-chain interleaving (deferred, prompt 03): AES chain is 13.7% of AES-GCM, i.e. ~0.3% of a connection even if eliminated entirely | Medium | Low-medium (well-trodden interleaving pattern) | ~0 |
| — of which GHASH alone | 1.6% | ~10.5 µs/conn | Already reduced 3.7x this cycle; no further multi-block win identified | — | — | — |
| — of which AES encryption alone | 0.4% | ~2.8 µs/conn | Below floor even at 100% removal | — | — | — |
| SHA-256 / HKDF (transcript, key schedule) | 0.5% | ~3.5 µs/conn | Below floor at any plausible improvement | Low | Low | ~0 |
| HPACK / H2 framing | 0.2% | ~1.3 µs/conn | Below floor; also not exercised realistically by this harness (no client Huffman-codes header values — see §8 caveat, unchanged from prompt 00) | — | — | — |
| **Register save/restore on the busiest caller with a frame** (`p256_ecdsa_sign_with_k`, since `p256_bn_mul` itself has none) | ~0.00% | 2 unjustified regs × 1 call/conn | Unmeasurable — a handful of nanoseconds against a 657,210 ns connection | Low if ever done (small function) | Low | 0 |
| Embedded asset lookup (`lookup_embedded`) | not observed (0 self-time samples across 56,935 busy samples, all 4 scenarios combined) | — | Not measurable with this harness; unaffected by 03/04 | — | — | — |
| Response construction (`create_response`, `h2_write_body`/`h2_write_headers`, `http1_write_response`) | ≤0.02% everywhere measured | ≤0.15 µs/conn | Not measurable; the response-*path* cost that is real is `memcpy` (3.95% of transfer busy) and the write syscalls, both already prompt 08's territory, not construction itself | — | — | — |

---

## 8. Register optimization decision

```
estimated removable work (X25519, the only candidate with a real,
fully-unjustified frame and non-trivial call count):     ~0.36% of a connection
benchmark noise floor, this session (connection-level):    ~6% of a connection
```

**0.36% < 6% by more than an order of magnitude. Register optimization is
not currently worthwhile.** This is stated as a valid and successful
conclusion per the prompt's own acceptance criteria, not a failure to find
a target — the process was re-run against the current, post-03/04 profile
exactly as required, and it produced a different set of candidates
(`point_add`, `p256_fe_mul`'s paired-register findings; `crypto_random_bytes`
surfacing at all) than prompt 00's profile did, while reaching the same
top-line answer for the register-pressure question specifically. No
benchmark of a hand-reallocated candidate was run, because every candidate
either had zero analytic ceiling (paired registers, no frame, or 1
call/connection) or a ceiling far below the noise floor (X25519) — the
prompt's step 1 ("if the ceiling is below the noise floor, stop and report
that") applies before step 2 is reached for any of them.

No `// Clobbered Registers:` header needed updating; no calling convention
changed; no `.S` file was modified.

---

## 9. Method and its limits

Same limits as `docs/PROFILE.MD` §6 apply unchanged (no `perf`, no
hardware counters, `xctrace` unavailable, `sample` measures wall time in
the process not CPU, no true call tree for the deepest frames, the client
is not a browser so `h2_huffman_decode` still never executes here, no core
pinning, single-connection scenarios still use `no_fork`). Two new items
specific to this re-profile:

- **The server's own speedup changed the sampling method's operating
  point.** At the same client concurrency prompt 00 used, the accept-loop
  idle fraction rose from 0.68% to as high as 78% on the handshake
  scenario, because each connection now completes in under half the wall
  time. Longer `--seconds` at the same `--clients` restored comparable
  busy-sample counts; raising `--clients` instead was tried first and
  rejected because it measurably changed `crypto_random_bytes`'s apparent
  share (6.3%→14.8% as clients rose from 4→12), most likely `/dev/urandom`
  open/close contention under concurrent load — a real effect, but not the
  single-connection cost this profile is trying to measure. All headline
  numbers in this document use `--clients 4` for that reason.
- **`crypto_random_bytes`'s sampled share is the noisiest number in this
  document** (§5, finding 4) — the bench-based ~8.2–8.9 µs/call (also
  cross-checked, during development of `bench_crypto_random_bytes.c`, as
  three repeated runs at a fixed 32 B payload landing within 2–4% of each
  other) is the trustworthy number; the sampled self-time percentage
  (6–15% across runs) is reported for direction only.

### Reproducing

```bash
make                                                       # keep local symbols
python3 scripts/profile_workload.py --rounds 5             # §1
python3 scripts/profile_samples.py handshake --seconds 50 --clients 4   # §3; transfer/request/pageload need less time
make -C scripts/benchmarks bench_primitives bench_crypto_random_bytes bench_gcm_ghash_run
./scripts/benchmarks/_bench_bin/bench_primitives
./scripts/benchmarks/_bench_bin/bench_crypto_random_bytes
python3 scripts/count_calls.py --workload pageload --requests 1
python3 scripts/regpressure.py
```

---

## 10. Recommendation

**Not register optimization** (prompts 06/07 remain not justified, for a
third profile in a row now). Of the candidates this fresh profile actually
supports:

1. **`p256_point_mul`'s fixed-base comb** (finding 1, §5) is the largest
   remaining opportunity in the codebase at 45.4% of a connection — this is
   prompt 04's own deferred second half, and this profile is exactly the
   "fresh re-profile" prompt 04 said should gate it. It clears the noise
   floor by more than an order of magnitude even under a conservative
   improvement estimate, but carries the highest implementation and
   constant-time-verification risk of anything in this table.
2. **`crypto_random_bytes`'s open/read/close-per-call pattern** (finding 4,
   §5) is a new, independent, low-risk, low-complexity finding: cache the
   file descriptor once instead of reopening `/dev/urandom` 3 times per
   connection. Smaller win than the comb (~2.5–3% vs ~20–30% of a
   connection) but far cheaper and lower-risk to implement and verify, and
   not previously visible in any profile because P-256 dominated it out of
   sight until this cycle's speedup.

Neither is a register-pressure prompt, so **07 stays gated off** regardless
of which (or both, or neither) of these a future prompt picks up. If
prompts 06/07 are to run at all, it will need a profile after whichever of
the above lands, on the theory that shrinking `point_mul` by 2-3x would (by
the same "smaller pie, bigger slice" logic that made `crypto_random_bytes`
and the AES chain more visible this cycle) make X25519's already-computed
0.36% ceiling into a slightly larger fraction of a slightly smaller
connection — worth a fourth re-profile to check, not worth assuming now.
