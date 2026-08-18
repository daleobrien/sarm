#!/usr/bin/env python3
"""Workload-driven optimization strategies (prompts/06-optimizer-strategy-
framework.md).

``optimizer.py`` already runs the whole pipeline OPTIMISATION.MD describes --
propose, ABI check, build, tests, differential, benchmark, archive. The one
thing hardwired into it was the *accept* decision: a bare comparison of the
candidate's own runtime against the running best. That means the loop could
only ever answer "is this function faster in isolation", never "does this
change the thing that actually costs the server time" -- the exact trap
prompts/03 and 04 avoided by hand (GHASH is judged by AES-GCM throughput,
P-256 reduction by handshake cost, not by a microbenchmark in a vacuum).

A ``Strategy`` is what makes that judgement call structural instead of
manual: it says which function is being optimized, which metric decides
whether a candidate is kept, and which hard constraints reject a candidate
outright regardless of any score. ``optimizer.py`` calls exactly three
things on it -- ``workload_benchmark_cmd`` (what else to measure besides the
function's own benchmark), ``accept`` (keep or reject, with the metric and
rule that decided it) -- everything else about the pipeline is unchanged.

Strategies are deliberately not allowed to justify a target by its static
shape (register count, instruction count, save/restore count) alone -- see
``Strategy.__init__``'s workload-connection check. That is the same rule
prompts 03-05 already applied by hand; this module is what makes the harness
itself enforce it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from asmparse import index_source

# ----------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------


@dataclass
class Metrics:
    """Everything a Strategy might judge a candidate by.

    Every field is optional: not every metric is available in every run
    (llvm-mca/perf are absent on macOS -- docs/SCRIPTS.md), and a
    Strategy only needs to read the ones its own ``primary_metric``/
    ``required_metrics`` actually use.
    """

    runtime_ns: float | None = None
    instruction_count: int | None = None
    load_count: int | None = None
    store_count: int | None = None
    save_restore_count: int | None = None
    peak_register_pressure: int | None = None
    stack_bytes: int | None = None
    binary_size: int | None = None
    # Algorithm-specific / workload-level metrics a strategy adds itself,
    # e.g. "workload_runtime_ns" (the AES-GCM or P-256-sign benchmark, not
    # the target function's own microbenchmark).
    extra: dict[str, float] = field(default_factory=dict)
    # Hard-constraint inputs that have no dedicated Metrics field of their
    # own -- collected here so a Strategy.accept() call is self-contained.
    heap_ok: bool = True
    constant_time_ok: bool = True

    def get(self, name: str) -> float | None:
        if hasattr(self, name):
            value = getattr(self, name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
        value = self.extra.get(name)
        return float(value) if value is not None else None


@dataclass
class AcceptDecision:
    """One accept/reject verdict: which rule fired, which metric decided it
    (prompts/06's acceptance criterion, "every accept/reject decision logs
    which rule fired and which metric decided it")."""

    keep: bool
    rule: str
    metric: str | None
    reason: str

    def render(self) -> str:
        return f"[{self.rule}] {self.reason}"


class StrategyTargetError(Exception):
    """A strategy's target function is not connected to measured workload."""


# ----------------------------------------------------------------------
# Shared metric collection (reused by every strategy -- prompt 06 forbids
# building a parallel, strategy-specific measurement stack).
# ----------------------------------------------------------------------

_LOAD_RE = re.compile(
    r"^(ldr|ldp|ldur|ldnp|ld1|ld2|ld3|ld4|ldar|ldxr|ldaxr|ldpsw|ldrsw|ldrsb|"
    r"ldrsh)\w*\b"
)
_STORE_RE = re.compile(
    r"^(str|stp|stur|stnp|st1|st2|st3|st4|stlr|stxr|stlxr)\w*\b"
)


def instruction_counts(
    disassembly: str | None,
) -> tuple[int | None, int | None, int | None]:
    """(instruction_count, load_count, store_count) from objdump text.

    Generalizes optimizer.py's own ``_instruction_count`` (an exact,
    zero-noise static count -- prompts/02-benchmark-substrate.md) with a
    load/store breakdown, on the same normalized text.
    """
    if not disassembly:
        return None, None, None
    from disassembler import Disassembler

    lines = Disassembler.normalize(disassembly).splitlines()
    insns = [ln for ln in lines if ln and not ln.rstrip().endswith(":")]
    loads = sum(1 for ln in insns if _LOAD_RE.match(ln.strip()))
    stores = sum(1 for ln in insns if _STORE_RE.match(ln.strip()))
    return len(insns), loads, stores


def register_metrics(
    workdir: Path, function: str
) -> tuple[int | None, int | None, int | None]:
    """(peak_register_pressure, save_restore_count, stack_bytes) for
    ``function`` from a fresh regpressure.py pass (prompt 01) over the
    *current* on-disk source. Reused, not reimplemented: prompt 06 is
    explicit that this must not become a parallel register-specific
    framework.

    Must be called while ``function``'s source on disk matches what is
    being measured -- ``optimizer.py`` only calls this right after writing
    a candidate (or the untouched baseline) to ``self.source``.
    """
    import regpressure

    try:
        rows, _ = regpressure.collect(root=workdir)
    except Exception:
        return None, None, None
    for info in rows:
        if info.name == function:
            return info.peak, info.save_restore, info.frame
    return None, None, None


def find_region(workdir: Path, function: str):
    """The asmparse Region for ``function``, or None.

    ``.Lgcm_ghash_run`` (src/crypto/gcm/data.S) has no ``.global`` and sits
    among other file-local ``.L`` labels with no clean textual boundary a
    regex can find; asmparse's region parser (prompt 01) already solves
    this correctly via a real CFG, so both ``optimizer.py``'s extraction
    and this module's target-validation reuse it instead of a second,
    worse regex.
    """
    index = index_source(workdir)
    return index.by_name.get(function)


# ----------------------------------------------------------------------
# Hard-constraint heuristics not covered by abi.py
# ----------------------------------------------------------------------

_BRANCH_RE = re.compile(r"^(b\.\w+|cbz|cbnz|tbz|tbnz)\b")


def _branch_signature(disassembly: str | None) -> list[str] | None:
    if not disassembly:
        return None
    from disassembler import Disassembler

    lines = Disassembler.normalize(disassembly).splitlines()
    return [
        ln.split()[0] for ln in lines if ln and _BRANCH_RE.match(ln.strip())
    ]


def constant_time_violation(
    baseline_dis: str | None, candidate_dis: str | None
) -> str | None:
    """A conservative, fail-closed proxy for "control flow stayed
    secret-independent" -- not a proof.

    Proving data-independent control/address flow needs a taint analysis
    this repo has no static tool for; scripts/p256_reduce_derivation.py's own
    "Constant time" section is argued by hand, not machine-checked. This
    only checks whether the candidate introduces MORE conditional branches
    than the current best -- a necessary, not sufficient, condition -- and
    rejects when it cannot show the count held. A function whose disassembly
    is unavailable is treated as unprovable-but-not-rejected: this check
    only fires for candidates where both sides were actually disassembled.
    """
    base = _branch_signature(baseline_dis)
    cand = _branch_signature(candidate_dis)
    if base is None or cand is None:
        return None
    if len(cand) > len(base):
        return (
            f"candidate has {len(cand)} conditional branch(es) vs the "
            f"current best's {len(base)} -- cannot prove secret-independent "
            "control flow is preserved"
        )
    return None


_HEAP_CALL_RE = re.compile(r"\bble?\s+_?(malloc|calloc|realloc|mmap)\b")


def heap_violation(baseline_src: str, candidate_src: str) -> str | None:
    """A candidate that starts calling an allocator the baseline never
    called. Hand-written leaf crypto/util functions in this repo never
    allocate; a candidate that starts is either a mistake or does not
    belong in this harness's accept path."""
    base_calls = set(_HEAP_CALL_RE.findall(baseline_src))
    cand_calls = set(_HEAP_CALL_RE.findall(candidate_src))
    new_calls = cand_calls - base_calls
    if new_calls:
        return (
            f"candidate calls {', '.join(sorted(new_calls))}, which the "
            "baseline never did"
        )
    return None


# ----------------------------------------------------------------------
# docs/HISTORY.md workload-connection check
# ----------------------------------------------------------------------

_PROFILE_DOCS = ("HISTORY.md",)


def workload_share(
    keyword: str, workdir: Path, docs: tuple[str, ...] = _PROFILE_DOCS
) -> float | None:
    """The most recent measured share-of-connection (%) for a row in
    docs/PROFILE*.MD whose label contains ``keyword`` (case-insensitive).

    Only matches simple ``| label | value | pct% |`` rows (exactly three
    cells) -- the multi-scenario breakdown tables further down each doc
    have more columns and would otherwise produce false matches (e.g. "P-256"
    also appears in a 5-column cost-centre row that is not the per-function
    breakdown this check cares about).

    This is what "connected to measured workload" means structurally
    (prompts/06, "Important rule"): a strategy target must point at an
    actual row a profiling run produced, not just a static ranking.
    """
    for doc in docs:
        path = workdir / "docs" / doc
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.startswith("|") or keyword.lower() not in line.lower():
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) != 3:
                continue
            match = re.search(r"(\d+(?:\.\d+)?)\s*%", cells[2])
            if match:
                return float(match.group(1))
    return None


# ----------------------------------------------------------------------
# Strategy base
# ----------------------------------------------------------------------


class Strategy:
    """Base class for every optimization strategy.

    ``propose`` is deliberately not overridden by most strategies below:
    the LLM + rule-based mutations (``optimizer.py``'s existing candidate
    sources) are already function-agnostic, and prompt 06 explicitly says
    not to build a second, strategy-specific proposal mechanism. What a
    Strategy actually customizes is *how a candidate is judged* --
    ``workload_benchmark_cmd``, ``primary_metric`` and ``accept``.
    """

    name = "strategy"
    # Set on a subclass to require the target be a measured line item in
    # docs/PROFILE*.MD before the strategy will even construct.
    workload_keyword: str | None = None
    min_workload_share_pct: float | None = None
    # Set on a subclass whose target must not gain a data-dependent branch.
    constant_time: bool = False

    def __init__(self, *, function: str, workdir: Path) -> None:
        self.function = function
        self.workdir = workdir
        if self.workload_keyword is not None:
            share = workload_share(self.workload_keyword, workdir)
            required = self.min_workload_share_pct or 0.0
            if share is None or share < required:
                have = "no row for" if share is None else f"only {share:.1f}% for"
                raise StrategyTargetError(
                    f"{self.name}: {function!r} is not connected to measured "
                    f"workload -- docs/PROFILE*.MD shows {have} "
                    f"{self.workload_keyword!r} (need >= {required:.1f}%). "
                    "Re-profile first (scripts/profile_workload.py), or pick "
                    "a strategy/target the profile actually supports."
                )

    # -- what to propose -------------------------------------------------

    def propose(self, function_text: str, analysis: dict | None = None) -> list:
        """Strategies that need candidates beyond the LLM/mutation sources
        optimizer.py already runs can override this; the default is "use
        whatever optimizer.py's normal pipeline produces" (return nothing
        extra)."""
        return []

    # -- what to measure --------------------------------------------------

    def required_metrics(self) -> tuple[str, ...]:
        return ("runtime_ns",)

    def workload_benchmark_cmd(self) -> list[str] | None:
        """An extra benchmark command, run in addition to the target
        function's own, whose result decides acceptance -- e.g. AES-GCM
        throughput for a GHASH strategy. None means: judge on the target
        function's own benchmark, same as today's speed-only behaviour."""
        return None

    def workload_label(self) -> str:
        return "runtime"

    # -- how good is a candidate -------------------------------------------

    def primary_metric_name(self) -> str:
        return "runtime_ns"

    def primary_metric(self, m: Metrics) -> float | None:
        """The single number accept() compares before/after. Lower is
        better for every metric this module defines (nanoseconds, counts,
        bytes)."""
        return m.get(self.primary_metric_name())

    # -- accept/reject -----------------------------------------------------

    def hard_constraints(
        self, before: Metrics, after: Metrics
    ) -> AcceptDecision | None:
        """Checks that reject regardless of any score.

        Correctness, ABI/NZCV, differential mismatch and benchmark failure
        are already gated earlier in optimizer.py's loop (unchanged --
        those checks existed before this module and still produce their
        own history entries); by the time ``accept`` runs, only the
        strategy-scoped hard constraints below have no other home.
        """
        if (
            before.stack_bytes is not None
            and after.stack_bytes is not None
            and after.stack_bytes > before.stack_bytes
        ):
            return AcceptDecision(
                False,
                "stack-increase",
                "stack_bytes",
                f"stack frame grew {before.stack_bytes} -> "
                f"{after.stack_bytes} bytes",
            )
        if not after.heap_ok:
            return AcceptDecision(
                False,
                "heap-increase",
                None,
                "candidate introduces a heap allocation the baseline did "
                "not have",
            )
        if self.constant_time and not after.constant_time_ok:
            return AcceptDecision(
                False,
                "constant-time",
                None,
                "candidate may not preserve constant-time control flow",
            )
        return None

    def accept(
        self,
        before: Metrics,
        after: Metrics,
        *,
        min_improvement_pct: float,
        noise_floor_pct: float,
    ) -> AcceptDecision:
        violation = self.hard_constraints(before, after)
        if violation is not None:
            return violation

        metric_name = self.primary_metric_name()
        before_value = self.primary_metric(before)
        after_value = self.primary_metric(after)
        if before_value is None or after_value is None:
            return AcceptDecision(
                False,
                "missing-metric",
                metric_name,
                f"{metric_name} unavailable -- cannot score against "
                f"{self.name}",
            )
        if before_value == 0:
            return AcceptDecision(
                False,
                "missing-metric",
                metric_name,
                f"{metric_name} baseline is zero -- cannot score",
            )

        improvement = (before_value - after_value) / before_value * 100.0
        required = max(min_improvement_pct, noise_floor_pct)
        if improvement > required:
            return AcceptDecision(
                True,
                "workload-improvement",
                metric_name,
                f"{metric_name} improved {improvement:+.3f}% "
                f"(> required {required:.3f}%)",
            )
        return AcceptDecision(
            False,
            "no-improvement",
            metric_name,
            f"{metric_name} changed {improvement:+.3f}% "
            f"(required > {required:.3f}%)",
        )


# ----------------------------------------------------------------------
# Concrete strategies
# ----------------------------------------------------------------------


class SpeedStrategy(Strategy):
    """Today's behaviour, unchanged: judge a candidate purely on its own
    runtime. The regression test for the whole refactor
    (prompts/06-optimizer-strategy-framework.md's acceptance criteria)."""

    name = "speed"


class RegisterPressureStrategy(Strategy):
    """Register-focused optimization -- but still judged by runtime.

    prompts/06's "Important rule" is explicit: a register optimization must
    never be justified, or scored, by register count/save-restore count/
    instruction count in isolation. Those numbers are collected (via
    ``required_metrics``) purely as evidence for the LLM/reviewer; the
    accept decision below is exactly SpeedStrategy's -- runtime of the
    actual hot-path function. What differs from SpeedStrategy is the
    workload-connection gate: a target is only eligible if a profiling run
    actually put it on the hot path, not because ``regpressure.py`` ranked
    it HIGH statically.
    """

    name = "register-pressure"

    def __init__(self, *, function: str, workdir: Path,
                workload_keyword: str, min_workload_share_pct: float = 1.0
                ) -> None:
        self.workload_keyword = workload_keyword
        self.min_workload_share_pct = min_workload_share_pct
        super().__init__(function=function, workdir=workdir)

    def required_metrics(self) -> tuple[str, ...]:
        return (
            "runtime_ns", "save_restore_count", "instruction_count",
            "peak_register_pressure",
        )


class CryptoStrategy(Strategy):
    """Shared base for algorithm-specific strategies (GHASH, P-256
    reduction, and any future crypto restructuring): judge a candidate by
    a *different* function's benchmark -- the algorithm it feeds into, not
    itself in isolation. Concrete subclasses only need to declare the
    target, the workload keyword/threshold and the workload benchmark.
    """

    constant_time = True

    def __init__(
        self,
        *,
        function: str,
        workdir: Path,
        workload_bench_name: str,
        workload_label: str,
    ) -> None:
        self._workload_bench_name = workload_bench_name
        self._workload_label = workload_label
        super().__init__(function=function, workdir=workdir)

    def workload_benchmark_cmd(self) -> list[str] | None:
        name = self._workload_bench_name
        return [
            f"make -s -C scripts/benchmarks bench_{name}",
            "&&",
            f"./scripts/benchmarks/_bench_bin/bench_{name}",
        ]

    def workload_label(self) -> str:
        return self._workload_label

    def required_metrics(self) -> tuple[str, ...]:
        return ("runtime_ns", "workload_runtime_ns")

    def primary_metric_name(self) -> str:
        return "workload_runtime_ns"


class GHASHStrategy(CryptoStrategy):
    """.Lgcm_ghash_run (src/crypto/gcm/data.S), judged by AES-GCM
    throughput -- prompts/03-aes-gcm-throughput.md did this by hand; this
    is the harness doing it structurally. There is no bytes/sec metric
    anywhere in this repo's benchmark protocol (every bench_*.c reports
    runtime_ns), so "AES-GCM throughput" is operationalized as
    bench_aes_gcm_encrypt's runtime -- lower runtime, higher throughput,
    the same monotonic relationship the doc's own numbers use.
    """

    name = "crypto-ghash"

    def __init__(self, *, function: str, workdir: Path) -> None:
        if function != ".Lgcm_ghash_run":
            raise StrategyTargetError(
                f"{self.name}: target is .Lgcm_ghash_run "
                "(src/crypto/gcm/data.S), not the standalone `ghash` "
                f"symbol or {function!r}"
            )
        self.workload_keyword = "AES-GCM"
        self.min_workload_share_pct = 1.0
        super().__init__(
            function=function,
            workdir=workdir,
            workload_bench_name="aes_gcm_encrypt",
            workload_label="AES-GCM encrypt throughput (bench_aes_gcm_encrypt "
                           "runtime; lower is higher throughput)",
        )


class P256ReductionStrategy(CryptoStrategy):
    """p256_reduce (src/crypto/p256/sqr_mul.S), judged by handshake cost.

    There is no dedicated TLS-handshake microbenchmark in this repo
    (scripts/profile_workload.py drives the real server for that, which is
    far too slow to run every candidate); bench_p256_ecdsa_sign_with_k is
    the closest proxy -- per docs/HISTORY.md, ECDSA
    CertificateVerify/sign is ~45-51% of connection cost and p256_reduce is
    the majority of *that* -- so it stands in for "handshake latency" here,
    which is why this strategy is judged by it rather than p256_reduce's
    own microbenchmark alone.
    """

    name = "crypto-p256-reduce"

    def __init__(self, *, function: str, workdir: Path) -> None:
        if function != "p256_reduce":
            raise StrategyTargetError(
                f"{self.name}: target is p256_reduce "
                "(src/crypto/p256/sqr_mul.S), not {function!r}"
            )
        self.workload_keyword = "P-256 reduction"
        self.min_workload_share_pct = 1.0
        super().__init__(
            function=function,
            workdir=workdir,
            workload_bench_name="p256_ecdsa_sign_with_k",
            workload_label="P-256 ECDSA sign latency (handshake-cost proxy "
                           "-- no dedicated handshake microbenchmark exists)",
        )


class GenericMetricStrategy(Strategy):
    """A strategy over any of the static/count metrics (instruction count,
    load/store count, or a combined score) for a target the caller has
    already justified against a profiling run.

    Backs the ``instruction``, ``load-store`` and ``combined`` CLI
    categories from prompts/06 -- these have no per-function keyword table
    the way GHASH/P-256 do, so the workload connection is supplied
    explicitly (``--workload-keyword``/``--min-workload-share``) rather
    than guessed; omitting it is refused outright (prompts/06's "failing
    closed: no benchmark and no explicit, strategy-declared justification
    means no acceptance").
    """

    _METRICS = {
        "instruction": "instruction_count",
        "load-store": "load_count",
        "combined": "combined_score",
    }

    def __init__(
        self,
        *,
        mode: str,
        function: str,
        workdir: Path,
        workload_keyword: str,
        min_workload_share_pct: float,
    ) -> None:
        if mode not in self._METRICS:
            raise ValueError(f"unknown generic strategy mode {mode!r}")
        self._mode = mode
        self.name = mode
        self.workload_keyword = workload_keyword
        self.min_workload_share_pct = min_workload_share_pct
        super().__init__(function=function, workdir=workdir)

    def required_metrics(self) -> tuple[str, ...]:
        if self._mode == "load-store":
            return ("runtime_ns", "load_count", "store_count")
        if self._mode == "combined":
            return ("runtime_ns", "instruction_count", "peak_register_pressure")
        return ("runtime_ns", "instruction_count")

    def primary_metric_name(self) -> str:
        return self._METRICS[self._mode]

    def primary_metric(self, m: Metrics) -> float | None:
        if self._mode == "load-store":
            if m.load_count is None or m.store_count is None:
                return None
            return float(m.load_count + m.store_count)
        if self._mode == "combined":
            # A candidate must still be at least as fast, and its combined
            # score is runtime plus a fraction of instruction count and
            # register pressure -- multiple axes, one number, still
            # strictly "lower is better".
            if m.runtime_ns is None:
                return None
            score = m.runtime_ns
            if m.instruction_count is not None:
                score += m.instruction_count * 0.01
            if m.peak_register_pressure is not None:
                score += m.peak_register_pressure * 0.001
            return score
        return m.get(self.primary_metric_name())


# ----------------------------------------------------------------------
# Factory
# ----------------------------------------------------------------------

STRATEGY_CHOICES = (
    "speed",
    "algorithm",
    "instruction",
    "register-pressure",
    "load-store",
    "crypto",
    "combined",
)

# Functions with a registered algorithm-specific strategy -- the "algorithm"
# and "crypto" CLI choices dispatch here by --function.
_CRYPTO_STRATEGIES = {
    ".Lgcm_ghash_run": GHASHStrategy,
    "p256_reduce": P256ReductionStrategy,
}


def build_strategy(
    name: str,
    *,
    function: str,
    workdir: Path,
    workload_keyword: str | None = None,
    min_workload_share_pct: float | None = None,
) -> Strategy:
    """Construct the Strategy named by ``--strategy``."""
    if name == "speed":
        return SpeedStrategy(function=function, workdir=workdir)

    if name in ("algorithm", "crypto"):
        cls = _CRYPTO_STRATEGIES.get(function)
        if cls is None:
            registered = ", ".join(sorted(_CRYPTO_STRATEGIES))
            raise StrategyTargetError(
                f"--strategy {name} has no strategy registered for "
                f"{function!r}; registered targets: {registered}. Add a "
                "CryptoStrategy subclass in scripts/strategy.py to add one."
            )
        return cls(function=function, workdir=workdir)

    if name == "register-pressure":
        if workload_keyword is None or min_workload_share_pct is None:
            raise StrategyTargetError(
                "--strategy register-pressure requires --workload-keyword "
                "and --min-workload-share -- a register optimization must "
                "be connected to a docs/PROFILE*.MD row, never justified by "
                "register count alone (prompts/06's \"Important rule\")"
            )
        return RegisterPressureStrategy(
            function=function, workdir=workdir,
            workload_keyword=workload_keyword,
            min_workload_share_pct=min_workload_share_pct,
        )

    if name in ("instruction", "load-store", "combined"):
        if workload_keyword is None or min_workload_share_pct is None:
            raise StrategyTargetError(
                f"--strategy {name} requires --workload-keyword and "
                "--min-workload-share -- a static-metric target must be "
                "connected to a docs/PROFILE*.MD row, never justified by "
                "its static shape alone (prompts/06's \"Important rule\")"
            )
        return GenericMetricStrategy(
            mode=name, function=function, workdir=workdir,
            workload_keyword=workload_keyword,
            min_workload_share_pct=min_workload_share_pct,
        )

    raise ValueError(f"unknown strategy {name!r}; choices: {STRATEGY_CHOICES}")
