# 03 — Optimize the actual AES-GCM bottleneck: GHASH

**The largest measured AES-GCM opportunity.** The workload profile
(`docs/PROFILE.MD`) disproves the earlier assumption that the AES encryption
chain dominates. Measured AES-GCM cost breaks down approximately as:

```text
GHASH             ~79%
AES encryption     ~9%
other              ~12%
```

The primary objective of this prompt is therefore GHASH, not
`aes128_encrypt`.

## Context

Every TLS record is authenticated with GHASH over GF(2^128), computed with
`PMULL`/`PMULL2`. That part of the implementation is already using the right
instructions — there is no order-of-magnitude win available from switching to
hardware crypto extensions, they are already in use.

**The implementation that matters is `.Lgcm_ghash_run`**, a local label in
`src/crypto/gcm/data.S:131`, included into the GCM translation unit and called
directly by `bl` from `src/crypto/gcm/encrypt.S`, `decrypt.S`, and
`ghash.S`. Read `src/crypto/gcm/data.S:107-166` before touching anything — it
documents the exact calling convention (H' in v19, accumulator in v20, nibble
table and constants in v16–v18).

**Do not optimize the standalone `ghash` symbol** (`src/crypto/gcm/ghash.S:38`)
unless you first confirm with evidence that AES-GCM actually calls it — it
does not; grep confirms every GCM caller reaches `.Lgcm_ghash_run` directly.
Optimizing `ghash` would not change server behavior.

The current structure, from `.Lgcm_ghash_run`'s loop
(`src/crypto/gcm/data.S:140-147`):

```asm
.Lgcm_ghash_run_loop:
    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b
    eor     v0.16b, v0.16b, v20.16b   // Y ⊕ X
    bl      .Lgcm_gf_mul              // (Y ⊕ X)·H'
    mov     v20.16b, v0.16b
    subs    x9, x9, #1
    b.ne    .Lgcm_ghash_run_loop
```

This is textbook Horner evaluation: multiply-then-reduce, one block at a time,
fully serialized — each iteration depends on the previous iteration's
reduced result before it can start its own `PMULL`. `PMULL`/`PMULL2` are
pipelined on Apple Silicon; a serialized one-block-at-a-time loop leaves that
throughput mostly unused.

## First investigate

Before writing any assembly, determine and write down:

1. Exactly how `.Lgcm_ghash_run` is invoked (`bl` sites, register state on
   entry, in `encrypt.S`, `decrypt.S`, `ghash.S`).
2. How many blocks it processes per invocation, and what the call sites'
   record-size distribution looks like (from `docs/PROFILE.MD`).
3. How the GHASH accumulator is represented (`v20`, natural bit-reversed
   domain — see `gcm_rbit`).
4. How H is represented (`v19`, natural domain; `.Lgcm_gf_mul` reads its
   multiplier from `v1`).
5. Whether multiplication and reduction are serialized (`.Lgcm_gf_mul`,
   `data.S:60-105` — yes: the same routine does one `PMULL`-set then an
   immediate 3-fold reduction, called once per block).
6. Whether `PMULL`/`PMULL2` latency is being hidden (it is not — each call is
   a hard dependency for the next).
7. Whether multiple GHASH blocks can be processed together (yes, via
   precomputed powers of H — see below).
8. Whether powers of H can be precomputed (H², H³, H⁴ — yes, once per key,
   since H is fixed for the lifetime of a GCM key).
9. Whether the current implementation performs unnecessary reductions (yes —
   one full reduction per block; a k-block aggregation needs only one
   reduction per k blocks).
10. Whether register pressure prevents a wider GHASH pipeline — use the
    analyzer from prompt 01 (`scripts/regpressure.py`) on the
    `.Lgcm_ghash_run` region specifically, now that it can see local-label
    regions, rather than guessing.

## Optimization directions

Investigate, benchmark, and compare:

### 1. Multi-block GHASH

Instead of block → multiply → reduce → block → multiply → reduce, process
multiple blocks per iteration: accumulate several `PMULL`/`PMULL2` products
before performing a single reduction.

### 2. Horner restructuring

The current recurrence is:

```text
Y = (Y ⊕ X1)·H
Y = (Y ⊕ X2)·H
Y = (Y ⊕ X3)·H
```

Analyze whether this can be reorganized, using precomputed powers of H, to
expose independent `PMULL` operations that do not depend on each other's
result:

```text
Y' = (Y ⊕ X1)·H^k ⊕ X2·H^(k-1) ⊕ ... ⊕ Xk·H
```

**Prove the transformation** against the existing carry-less-multiplication
representation before implementing it — this is a change to the mathematical
structure of the accumulation, not just instruction scheduling, and it must
be validated the way `verified-asm-crypto` prescribes: reference
implementation first, cross-checked against the current implementation over
many random inputs, before any assembly is written.

### 3. Precomputed powers

Investigate whether precomputing H², H³, H⁴ (or higher) once per key allows
several blocks to be accumulated in GF(2^128) before a single reduction pass,
replacing k serialized multiply-reduce steps with k independent multiplies and
one reduction.

### 4. PMULL scheduling

Use instruction scheduling and dependency analysis to determine whether
independent `PMULL`/`PMULL2` operations from different blocks can overlap in
the pipeline. The objective is not simply fewer instructions; it is better
utilization of the vector/crypto execution pipeline on Apple Silicon.

### 5. Register-pressure-aware design

A wider GHASH implementation consumes more vector registers for held powers
of H and in-flight partial products. **Do not blindly unroll.** Measure:

```text
1 block
2 blocks
4 blocks
8 blocks
```

where practical, and check register pressure at each width with the prompt-01
tooling rather than assuming it fits. The fastest implementation wins,
provided stack usage and correctness constraints are satisfied.

## Critical distinction

The AES encryption chain (`aes128_encrypt`, called from the GCM block loop)
may still benefit from multi-block processing — interleaved `AESE`/`AESMC`
across several blocks is a legitimate secondary win. **However, that is now a
secondary optimization**, since it accounts for only ~9% of measured AES-GCM
cost against GHASH's ~79%. Do not spend the majority of this prompt on
`aes128_encrypt`. First establish the maximum achievable improvement from
GHASH, and only pursue AES-chain interleaving afterward if time and register
budget allow.

## Constraints

These are hard. A fast implementation that violates any of them is a defect.

- **Constant time.** No secret-dependent branches, no secret-dependent memory
  addressing. The block count derives from the record length, which is
  public; the key, H, and plaintext are not. Tail handling must branch on
  *length* only.
- **Behaviour identical.** Same authentication tag for every input, including
  all partial-block and zero-length cases, and identical ciphertext where the
  change touches the shared encrypt/decrypt path.
- **Tag verification must stay constant time** on the decrypt side —
  `aes_gcm_decrypt` must not leak where a tag mismatch occurred.
- **No stack growth beyond what the extra state genuinely requires**, and no
  heap use at all. If a wider pipeline forces a larger frame, report the
  trade explicitly with measurements rather than absorbing it silently.
- Both `aes_gcm_encrypt` and `aes_gcm_decrypt`, and the standalone `ghash`
  entry point in `ghash.S` if it shares `.Lgcm_ghash_run`, must be updated
  consistently.

## Testing

- `make -C tests/unit test`, and specifically the GCM suites in
  `tests/unit/test_gcm/`.
- **Differential testing against the current implementation** is the
  strongest gate here: run both over thousands of random (key, IV, AAD,
  plaintext) tuples spanning every length class — 0, 1, 15, 16, 17, 63, 64,
  65, and multi-block sizes with and without a partial tail — and require
  byte-exact tag agreement (and ciphertext agreement where relevant).
  `scripts/differential.py` provides the pattern.
- Known-answer tests: the NIST GCM vectors, if not already present.
- End-to-end: `tests/test_protocols.sh` and `tests/h2_browser_sim.py`, which
  exercise real records through a real handshake.

## Acceptance

An optimization must:

- exercise the actual GCM GHASH path (`.Lgcm_ghash_run`), not the standalone
  `ghash` symbol;
- preserve constant-time behaviour;
- pass all crypto tests;
- produce identical authentication tags;
- not increase stack/heap usage;
- demonstrate a result beyond the noise floor established in prompt 02;
- report its contribution to complete AES-GCM throughput, isolating the
  GHASH-only improvement from the AES-only improvement.

## Deliverable

Working implementation plus a short report: baseline vs optimized GHASH-only
throughput, baseline vs optimized complete AES-GCM throughput per record size,
register pressure before and after (from the prompt-01 tooling), stack usage
before and after, and the differential test count that passed. If AES-chain
interleaving was also attempted, report its contribution separately from
GHASH's.
