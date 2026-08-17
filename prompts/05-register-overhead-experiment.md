# 05 — Re-profile after the algorithmic optimizations

**Do not carry forward any earlier target.** The previous version of this
prompt tried to measure X25519 call-boundary overhead and decide whether
register optimization was worthwhile, on the assumption that the X25519
ladder's ~4,600 calls/handshake was the next-biggest thing after prompts 03
and 04. That assumption is not supported by measurement yet — it predates the
GHASH and P-256-reduction work, which changes the shape of the cost
breakdown in ways that have to be re-measured, not guessed.

The earlier reasoning that made `p256_bn_mul` a plausible register-removal
target is also invalid: `p256_bn_mul` (`src/crypto/p256/bn_mul.S:38`) is a
hot leaf function with no frame to remove — there is no prologue/epilogue
overhead to strip from it. Being hot is not sufficient justification for a
register-pressure pass; being hot *and* paying avoidable call-boundary or
save/restore cost is.

## Objective

Determine the next highest-value optimization target after prompts 03 and 04
have landed, using fresh measurement.

**Do not assume it is register pressure. Do not assume it is X25519. Do not
assume it is P-256 multiplication.** Any of those may turn out to be correct,
but the way to establish that is to re-run the workload profile now that
GHASH and the P-256 reduction have changed, not to reuse prompt 00's original
ranking, which was measured against a Barrett-reduction, single-block-GHASH
binary that no longer exists.

## Required process

After the accepted GHASH (prompt 03) and P-256 reduction (prompt 04) changes
are merged:

1. Rebuild the complete server.
2. Re-run the workload profile using the same method as prompt 00
   (`tests/h2_browser_sim.py`-based end-to-end harness, `xctrace` sampling
   cross-checked against a second method, ≥5 rounds, stated noise floor).
3. Measure complete TLS connection cost (handshake-dominated,
   transfer-dominated, request-dominated scenarios, as in prompt 00).
4. Measure AES-GCM throughput (should now show GHASH's reduced share; report
   whether AES encryption, previously ~9%, has become relatively larger simply
   because GHASH shrank, and whether that new balance justifies revisiting the
   AES chain).
5. Measure P-256 operations (`p256_reduce`, `p256_fe_mul`, `p256_point_mul`,
   ECDSA, ECDH) — confirm how much of the original 73%
   reduction-vs-multiplication split moved, and re-evaluate whether
   `p256_point_mul`'s double-and-add now represents enough of the remaining
   cost to justify a fixed-base comb (deferred from prompt 04).
6. Measure X25519 operations, including whether it is even the group actually
   negotiated in practice — check `src/tls/handshake/client_hello.S` and the
   key-schedule path for which groups are offered and chosen, the same way
   prompt 04's predecessor should have before proposing X25519 work.
7. Measure SHA-256/HKDF (transcript and key schedule cost).
8. Measure HTTP/2 request/response processing (HPACK decode, framing).
9. Measure embedded asset lookup.
10. Measure response construction.

## Deliverable: ranked bottleneck table

Produce `docs/PROFILE-POST.MD` (or an update to `docs/PROFILE.MD`) containing
a ranked table. For every candidate calculate:

```text
percentage of end-to-end workload
current runtime
theoretical maximum improvement
implementation complexity
risk
expected binary-size impact
```

Include, at minimum: GHASH (post-optimization), AES encryption, P-256
reduction (post-optimization), P-256 point multiplication, X25519, SHA-256/
HKDF, HPACK/H2 framing, register save/restore overhead on whichever function
is now the busiest caller, embedded lookup, response construction.

## Register optimization decision

**Only recommend a register-focused optimization if:**

```text
estimated removable work  >  benchmark noise floor
```

**and** the target is actually on a hot path in the fresh profile — not the
prompt-00 profile, not a static instruction-count ranking.

Specifically reject these as automatic targets, regardless of what any
earlier prompt assumed:

- `p256_bn_mul` merely because it is hot — it is a leaf with no frame.
- The standalone `ghash` symbol merely because it exists — it is not on the
  execution path; `.Lgcm_ghash_run` is (see prompt 03).
- Leaf functions with no save/restore overhead in general.
- Functions whose theoretical register improvement cannot affect measured
  runtime — i.e. removable static instructions that execute rarely enough
  that the change would sit below the noise floor (the `h2_huffman_decode`
  amortization trap from the original register-overhead analysis: 23.5% of
  *static* instructions removable, but under 2% of *executed* instructions,
  because the loop body dominates).

If X25519's call-boundary overhead (the original ~4,600 calls/handshake,
~1,275 of them `x25519_fe_mul`) is still supported by the fresh profile as a
meaningful share of handshake time, it remains a legitimate candidate — but
it must earn that place in the new table, not be assumed into it.

## Method for the register-overhead question specifically

If the fresh profile does surface a call-heavy inner loop (X25519's ladder or
otherwise) as a plausible target:

1. **Establish the ceiling analytically first.** Count preservation
   instructions per call from `objdump`, multiply by the freshly measured
   call count, express it as a fraction of total handshake instructions. If
   the ceiling is below the noise floor, stop and report that — a complete,
   valuable, cheap answer.
2. Benchmark the candidate function end-to-end and per-call (prompt 02
   substrate, extended if needed).
3. Apply register reallocation by hand to the candidate. Measure.
4. If that measures, consider a private calling convention or inlining for
   its tight-loop helpers, in escalating order of implementation cost.
   Note that any of these requires updating callers in lockstep, and that
   the target symbols may be referenced directly by unit tests — check
   before changing their convention.

## Constraints

- **All invariants in `prompts/README.md` apply**, especially constant time:
  any curve code touched must remain free of secret-dependent branches and
  addressing.
- **Prompt 01 must be complete first** (it already is, as a prerequisite for
  03/04) — the fixed CFG parser, macro expansion, and NZCV liveness are what
  make any register-pressure claim in this prompt trustworthy.
- If a calling convention changes, **update its documented
  `// Clobbered Registers:` header** and check whether `tests/unit/` links
  against it directly.
- Verify structurally: disassembly should differ only in register numbers and
  removed prologue/epilogue for a pure register-reallocation change.

## Acceptance criteria

- A fresh, dated workload profile, not a reuse of prompt 00's numbers.
- A ranked bottleneck table with the six columns above for every candidate.
- If register optimization is recommended: a number for removable work per
  handshake, measured, with the noise floor stated alongside it, and
  confirmation the target is hot in the *current* profile.
- If register optimization is not recommended: an explicit statement of that,
  with the evidence. **"Register optimization is not currently worthwhile" is
  a valid and successful conclusion for this prompt** — the process follows
  the workload rather than forcing a planned optimization into the project.
- All crypto tests pass, including differential and known-answer vectors, for
  anything touched while investigating.

## Deliverable

`docs/PROFILE-POST.MD`: scenario results, cost breakdown, ranked bottleneck
table with the six columns, and a single recommended next-prompt target (which
may be "none — register optimization is not justified; recommend closing out
the series" or a pointer to a genuinely new prompt this data justifies).
