# 06 — Generalize the harness into pluggable strategies

**Conditional.** Run only if prompt 05 showed the overhead is measurable.
If it did not, skip this and prompt 07.

## Context

`scripts/` already contains a well-built optimization harness implementing
`docs/OPTIMISATION.MD`: `optimizer.py` (the loop), `abi.py` (static gate),
`benchmark.py`, `compiler.py`, `disassembler.py`, `differential.py`, `llm.py`,
`mutations/`, and the `arm-optimize.py` CLI. The pipeline is already the right
shape:

```
propose -> ABI check -> install -> build -> tests -> differential
        -> benchmark -> keep/reject -> archive
```

**Do not build a second framework.** Three things block a register strategy:

1. **Acceptance is hardwired to runtime.** `optimizer.py:444` is a bare
   `runtime < best * (1 - min_improvement/100)`. There is no scoring
   abstraction — this is the seam where a strategy must plug in.
2. **A benchmark is mandatory** (`optimizer.py:298-302` raises without one).
   Prompt 02 addresses the supply side; the harness still needs to express
   "this strategy may accept on instruction count when the benchmark cannot
   resolve the change, and here is why that is legitimate".
3. **The mutations are memcpy-specific** — `unroll the 16-byte ldp/stp loop`,
   `32-byte NEON ld1/st1 main loop`. Only `remove_redundant_mov` and
   `reschedule` generalize.

## Objective

Introduce a `Strategy` abstraction so the existing loop can run speed-oriented,
register-oriented, or combined optimization, without duplicating the
infrastructure.

## Design

```python
class Strategy(Protocol):
    def propose(self, function_text: str, analysis: Analysis) -> list[Candidate]: ...
    def measure(self, ctx: BuildContext) -> Metrics: ...
    def score(self, m: Metrics) -> float: ...
    def accept(self, before: Metrics, after: Metrics) -> tuple[bool, str]: ...
```

`Metrics` carries runtime, instruction count, load/store count, save/restore
count, peak pressure and stack bytes. `accept` applies hard constraints first,
then the score.

CLI: `--strategy {speed,registers,combined}`, defaulting to `speed`.

## Fitness

Hard constraints reject outright, regardless of speed:

```
correctness / differential failure   -> reject
ABI or NZCV-liveness violation       -> reject
stack usage increased                -> reject
heap usage / dynamic allocation      -> reject
loads or stores increased            -> reject
runtime regression beyond noise      -> reject
```

Then among survivors:

```
score =  w1 * runtime_ns          (primary, measured)
       + w2 * save_restore_insns
       + w3 * instruction_count
       + w4 * load_store_count
       + w5 * peak_pressure       (tie-breaker only)
       + w6 * stack_bytes
```

Two deliberate choices, both from `docs/REGISTER-PRESSURE.MD`:

- **Peak pressure is a tie-breaker, not a goal.** It is the constraint that
  makes a transformation legal, not the thing being minimized. Rewarding it
  directly recreates the "optimize for register count" failure mode.
- **Acceptance requires either a measured speedup, or a strictly smaller
  instruction/save-restore count with no measurable regression.** The second
  clause is what lets a legitimate 12-instruction removal be accepted when the
  benchmark cannot resolve it — but it must be an explicit, logged decision,
  never a silent fallback.

Fit the weights on the first accepted candidates. Do not assume them.

## Tasks

1. Add `scripts/strategy.py` with the protocol, `Metrics`, and the shared
   constraint checks.
2. Port the existing behaviour to `SpeedStrategy` and replace
   `optimizer.py:444` with `strategy.accept(...)`.
3. Extend `Metrics` collection: instruction and load/store counts from
   `objdump`, register metrics from `scripts/regpressure.py`, stack bytes from
   the frame analysis.
4. Wire `--strategy` through `arm-optimize.py`.

## Acceptance criteria

- `--strategy speed` reproduces today's behaviour **exactly** on
  `--function memcpy --mutate-only`. This is the regression test for the
  refactor; verify against a run captured before the change.
- Hard constraints are enforced independently of the score — a stack increase
  cannot be outweighed by a runtime gain.
- Every accept/reject decision logs which rule fired.

## Constraints

- **Do not modify any `.S` file.**
- Refactor rather than rewrite. The existing archiving
  (`.arm-optimize/{baseline,candidates,accepted,rejected}`) and history format
  are good — keep them.
- Keep the harness failing closed: no benchmark and no explicit
  instruction-count justification means no acceptance.
