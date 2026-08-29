#!/usr/bin/env bash
# profiling.sh — the measurement stack that only bare metal can use:
# perf against a real PMU, and FlameGraph to render what it collects.
#
# Writes its verdict to /tmp/sarm-pmu ("available" or "unavailable") so
# the caller's final report does not have to re-run the probe.
#
# Run on the instance. Safe to re-run.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

# ── perf ──────────────────────────────────────────────────────────────
# Installed by packages.sh; what is left is to verify it, because the
# /usr/bin/perf wrapper happily exists while the versioned binary behind
# it does not.
if ! perf --version >/dev/null 2>&1; then
    warn "the packaged perf does not match this kernel."
    warn "Fix with:  sudo apt-get install linux-tools-\$(uname -r)"
    warn "If that package does not exist, the running kernel is newer than the"
    warn "archive's tools; either boot the matching kernel or build perf from"
    warn "the kernel source tree."
else
    info "perf: $(perf --version)"
fi

# ── FlameGraph (not packaged anywhere) ────────────────────────────────
say "Installing FlameGraph"
if [ -d /opt/FlameGraph ]; then
    sudo git -C /opt/FlameGraph pull -q || true
else
    sudo git clone --depth 1 -q https://github.com/brendangregg/FlameGraph.git /opt/FlameGraph
fi
info "/opt/FlameGraph"

# ── the PMU itself ────────────────────────────────────────────────────
say "Verifying hardware performance counters"
PMU=unavailable
if perf --version >/dev/null 2>&1; then
    PMU_OUT=$(perf stat -e cycles,instructions -x, true 2>&1 || true)
    if printf '%s' "$PMU_OUT" | grep -q "not supported"; then
        warn "hardware counters read <not supported>."
        warn "On EC2 the PMU is exposed on bare-metal instances; if this is c6g.metal"
        warn "and you still see this, check that nothing else holds the PMU."
        warn "Sampling (-F/cpu-clock) and everything else still works."
    else
        PMU=available
        info "cycles + instructions readable"
        info "$(perf list 2>/dev/null | grep -ci 'armv8\|cpu-cycles' || true) PMU event names visible to perf"
    fi
fi
printf '%s\n' "$PMU" > /tmp/sarm-pmu
