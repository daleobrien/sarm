# 06 — Generalize the optimizer into workload-driven strategies

**Retained and generalized, not rebuilt.** The existing `scripts/`
architecture already has the right shape:

```text
propose
→ ABI/safety check
→ build
→ tests
→ differential testing
→ benchmark
→ accept/reject
→ archive
```

**Do not build a register-specific optimization framework.** The objective of
this prompt is to make the *optimization strategy* selectable while keeping
that pipeline shared across every strategy — speed, algorithmic, register, or
otherwise.

## Context

`scripts/` already contains a well-built harness implementing
`docs/OPTIMISATION.MD`: `optimizer.py` (the loop), `abi.py` (static gate),
`benchmark.py`, `compiler.py`, `disassembler.py`, `differential.py`, `llm.py`,
`mutations/`, and the `arm-optimize.py` CLI.

Three things currently block a workload-driven strategy model:

1. **Acceptance is hardwired to runtime.** `optimizer.py:444` is a bare
   `runtime < best * (1 - min_improvement/100)`. There is no scoring
   abstraction, and no way to say "judge this candidate by AES-GCM throughput,
   not by its own microbenchmark."
2. **A benchmark is mandatory** with no per-strategy metric model
   (`optimizer.py:298-302` raises without one). Prompt 02 supplies real
   benchmarks; the harness still needs to know *which* metric a given
   strategy is judged against.
3. **The mutations are function-specific and speed-only** — nothing currently
   represents "propose a multi-block GHASH restructuring" or "propose a
   Solinas-style P-256 reduction" as a strategy alongside register
   transformations.

## Strategy model

Introduce a strategy abstraction capable of supporting:

```text
speed
algorithm
instruction
register-pressure
load-store
crypto
combined
```

**Strategies must not be run blindly.** Each strategy must declare:

```text
target functions
required metrics
hard constraints
candidate transformations
acceptance criteria
```

For example:

```text
GHASH strategy
    target: actual .Lgcm_ghash_run (src/crypto/gcm/data.S:131),
             not the standalone ghash symbol
    metrics: GHASH blocks/sec, AES-GCM throughput
    constraints: constant time

P256 reduction strategy
    target: p256_reduce (src/crypto/p256/sqr_mul.S:37)
    metrics: reduce latency, field multiply latency,
             handshake latency
    constraints: constant time

register strategy
    target: functions selected by the current workload profile,
             not by static regpressure.py ranking alone
    metrics: runtime, save/restore count, instruction count,
             register pressure
```

## Important rule

The optimizer must never decide that a function is worth optimizing solely
because:

- it uses many registers;
- it has many instructions;
- it has many save/restore instructions;
- it appears high in a static ranking.

**The target must be connected to measured workload** — a fresh
`docs/PROFILE.MD` / `docs/PROFILE-POST.MD` entry showing the function's
actual share of end-to-end cost, not just its static shape. This is the same
rule prompts 03–05 already apply by hand; this prompt makes the harness
enforce it structurally.

## Design

```python
class Strategy(Protocol):
    def propose(self, function_text: str, analysis: Analysis) -> list[Candidate]: ...
    def measure(self, ctx: BuildContext) -> Metrics: ...
    def score(self, m: Metrics) -> float: ...
    def accept(self, before: Metrics, after: Metrics) -> tuple[bool, str]: ...
```

CLI: `--strategy {speed,algorithm,instruction,register-pressure,load-store,crypto,combined}`,
defaulting to `speed`.

## Metrics

Extend the existing metrics model to include:

```text
runtime
instruction_count
load_count
store_count
save_restore_count
peak_register_pressure
stack_bytes
binary_size
algorithm-specific metrics
```

Algorithm-specific metrics are strategy-declared and workload-relevant, for
example:

```text
GHASH blocks/sec
AES-GCM bytes/sec
P256 reduction ns
P256 multiplication ns
TLS handshake ns
```

## Acceptance

**Hard constraints** reject outright, regardless of any score:

```text
correctness failure       reject
ABI violation              reject
NZCV violation              reject
constant-time violation    reject
stack increase              reject
heap increase                reject
benchmark failure            reject
```

Then, and only for candidates that survive the hard constraints, evaluate
performance against the **strategy-appropriate workload metric**.

**Do not use one universal score for all optimization types.**

- A GHASH optimization should primarily be judged by AES-GCM throughput, not
  by an isolated `.Lgcm_ghash_run` microbenchmark number in a vacuum.
- A P-256 reduction optimization should ultimately be judged by its effect on
  P-256 operations and handshake cost, not just `p256_reduce` latency alone.
- A register optimization should be judged by the hot-path function and the
  end-to-end workload it affects — never by register count or instruction
  count in isolation.

## Tasks

1. Add `scripts/strategy.py` with the `Strategy` protocol, `Metrics`, and the
   shared hard-constraint checks.
2. Port existing speed-only behaviour to a `SpeedStrategy`, and implement
   `GHASHStrategy` and `P256ReductionStrategy` as the concrete non-speed
   examples, each declaring its target, metrics, constraints, and acceptance
   criteria as above. These map directly onto prompts 03 and 04.
3. Extend `Metrics` collection: instruction and load/store counts from
   `objdump`, register metrics from `scripts/regpressure.py` (prompt 01),
   stack bytes from frame analysis, and the algorithm-specific throughput
   metrics from the prompt-02 benchmark substrate.
4. Replace `optimizer.py:444`'s bare comparison with `strategy.accept(...)`.
5. Wire `--strategy` through `arm-optimize.py`.

## Acceptance criteria

- `--strategy speed` reproduces today's behaviour **exactly** on
  `--function memcpy --mutate-only`. This is the regression test for the
  refactor; verify against a run captured before the change.
- Hard constraints are enforced independently of any score — a stack increase
  cannot be outweighed by a runtime gain, and a constant-time violation
  cannot be outweighed by anything.
- A GHASH-strategy candidate is judged against AES-GCM throughput and a
  P256-reduction-strategy candidate against handshake latency, not against a
  generic combined score.
- Every accept/reject decision logs which rule fired and which metric decided
  it.

## Constraints

- **Do not modify any `.S` file.**
- Refactor rather than rewrite. The existing archiving
  (`.arm-optimize/{baseline,candidates,accepted,rejected}`) and history format
  are good — keep them.
- Keep the harness failing closed: no benchmark and no explicit,
  strategy-declared justification means no acceptance.
