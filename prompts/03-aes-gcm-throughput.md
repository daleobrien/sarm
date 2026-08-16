# 03 — Multi-block AES-GCM throughput

**Likely the largest per-byte win.** This is the cost paid on every byte the
server sends and receives.

## Context

Every TLS record is encrypted with AES-128-GCM. The implementation already
uses the ARMv8 Crypto Extensions correctly — `AESE`/`AESMC` in
`src/crypto/aes128/encrypt.S`, `PMULL`/`PMULL2` for GHASH — so there is no
order-of-magnitude win available from switching to hardware instructions. They
are already in use.

The problem is structural. `aes128_encrypt` encrypts **one 16-byte block per
call**, and `aes_gcm_encrypt` drives it from a per-block loop
(`src/crypto/gcm/encrypt.S:100-112`):

```asm
.Lgcm_enc_blockloop:
    ...
    bl      aes128_encrypt
    ...
    b.ne    .Lgcm_enc_blockloop
```

Two costs follow:

1. **The AESE dependency chain is serialized.** `AESE`/`AESMC` have multi-cycle
   latency but are pipelined: independent blocks can be in flight
   simultaneously. Processing one block at a time leaves nearly all of that
   throughput unused — the core stalls on each round's latency instead of
   overlapping four or eight independent blocks.
2. **Function-call overhead per 16 bytes** — the prologue, the `bl`/`ret`, and
   the round-key reload, all paid 64 times per kilobyte.

Interleaving 4 or 8 CTR blocks is the standard fix and is typically worth
**3–4×** on bulk AES-GCM. GHASH benefits from the same treatment: aggregated
reduction over 4 blocks with precomputed H² H³ H⁴ powers replaces four
serialized multiply-reduce steps with four multiplies and one reduction.

## Objective

Raise bulk AES-GCM throughput by restructuring encryption and authentication
to process multiple blocks per iteration, without changing observable
behaviour, the ABI, or constant-time properties.

## Method

Work incrementally; each step is separately testable.

1. **Benchmark first.** Prompt 02 should have produced `bench_aes_gcm_encrypt`
   across record sizes. If not, write it before changing anything. Record
   baseline throughput at 16 B, 256 B, 1 KB, 4 KB and 16 KB — the win will be
   size-dependent and the small sizes must not regress.
2. **Add an internal multi-block CTR core.** A private routine encrypting 4
   blocks with interleaved `AESE`/`AESMC` chains, keeping the existing
   single-block `aes128_encrypt` intact for its other callers and for the tail.
   Round keys are loaded once into registers (`v0`–`v10` covers all 11) and
   held across the whole loop rather than reloaded per block.
3. **Restructure the GCM loop** to consume 4 blocks per iteration, with a tail
   path for the remainder. The tail must handle 0–3 blocks and the final
   partial block exactly as today.
4. **Aggregate GHASH.** Precompute H², H³, H⁴ once per key. Accumulate four
   `PMULL`/`PMULL2` products and perform a single reduction per group. Keep the
   existing `.Lgcm_ghash_run` path for the tail.
5. **Consider 8-block interleaving** only if 4-block measures well and register
   pressure allows. The NEON register file is 32 × 128-bit; 8 blocks plus 11
   round keys plus GHASH state will be tight. `python3 scripts/regpressure.py
   --function aes_gcm_encrypt` reports vector pressure — check it rather than
   guessing.

## Constraints

These are hard. A fast implementation that violates any of them is a defect.

- **Constant time.** No secret-dependent branches, no secret-dependent memory
  addressing. The block count derives from the record length, which is public;
  the key and plaintext are not. Tail handling must branch on *length* only.
- **Behaviour identical.** Same ciphertext and same authentication tag for
  every input, including all partial-block and zero-length cases.
- **Tag verification must stay in constant time** on the decrypt side —
  `aes_gcm_decrypt` must not leak where a tag mismatch occurred.
- **No stack growth beyond what the extra state genuinely requires**, and no
  heap use at all. If interleaving forces a larger frame, report the trade
  explicitly with measurements rather than absorbing it silently.
- **Small records must not regress.** TLS handshake records are small; a
  change that wins at 16 KB and loses at 64 B may be a net loss for this
  workload. Prompt 00's data says which sizes actually occur — optimize for
  those.
- Both `aes_gcm_encrypt` and `aes_gcm_decrypt` must be updated consistently.

## Testing

- `make -C tests/unit test`, and specifically the GCM suites in
  `tests/unit/test_gcm/`.
- **Differential testing against the current implementation** is the strongest
  gate here: run both over thousands of random (key, IV, AAD, plaintext)
  tuples spanning every length class — 0, 1, 15, 16, 17, 63, 64, 65, and
  multi-block sizes with and without a partial tail — and require byte-exact
  ciphertext and tag. `scripts/differential.py` provides the pattern.
- Known-answer tests: the NIST GCM vectors, if not already present.
- End-to-end: `tests/test_protocols.sh` and `tests/h2_browser_sim.py`, which
  exercise real records through a real handshake.

## Acceptance criteria

- Byte-exact agreement with the current implementation on every differential
  case.
- Measured throughput improvement at the record sizes prompt 00 identified as
  representative, beyond the noise floor from prompt 02.
- No regression at small record sizes.
- No increase in heap use; any stack increase quantified and justified.
- Constant-time properties preserved — state explicitly what you checked.

## Deliverable

Working implementation plus a short report: baseline vs optimized throughput
per record size, register pressure before and after, stack usage before and
after, and the differential test count that passed.
