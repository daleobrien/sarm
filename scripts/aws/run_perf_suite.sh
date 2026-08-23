#!/usr/bin/env bash
# run_perf_suite.sh — measure sarm on Linux/aarch64 (Graviton, c6g.metal).
#
# Runs the whole measurement stack in one pass and writes everything to a
# timestamped directory:
#
#   1. environment    what machine, what binary, what kernel settings
#   2. throughput     req/s over HTTP/1.1, h2c, and HTTP/2+TLS
#   3. worker scaling how req/s moves with --workers on a 64-core box
#   4. counters       cycles / IPC / stalls / branch and cache misses
#   5. profile        which functions burn the time, per protocol
#   6. annotate       per-instruction attribution for the hottest functions
#   7. micro          per-function benchmarks (crypto, memcpy, P-256)
#   8. calls          how often the hot functions actually run
#
# Everything is pinned: the server on one core set, the load generator on
# another, with the low cores left to the kernel and NIC interrupts. That
# is what makes two runs comparable — an unpinned run on a 64-core box
# measures the scheduler as much as the server.
#
# Usage:
#   ./scripts/aws/run_perf_suite.sh
#   ./scripts/aws/run_perf_suite.sh --quick             # short durations
#   ./scripts/aws/run_perf_suite.sh --duration 30 --repeat 7
#   ./scripts/aws/run_perf_suite.sh --server-cpus 8-15 --load-cpus 32-39
#   ./scripts/aws/run_perf_suite.sh --skip micro,calls
#
# Compare two builds by running it twice and diffing the summary.txt files.

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"

# ── options ───────────────────────────────────────────────────────────
PORT=0
DURATION=20
REPEAT=5
CONNECTIONS=16
THREADS=8
REQ_PATH=/
SERVER_CPUS=""
LOAD_CPUS=""
OUTDIR=""
SKIP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --port)         PORT="$2"; shift ;;
        --duration)     DURATION="$2"; shift ;;
        --repeat)       REPEAT="$2"; shift ;;
        --connections)  CONNECTIONS="$2"; shift ;;
        --threads)      THREADS="$2"; shift ;;
        --path)         REQ_PATH="$2"; shift ;;
        --server-cpus)  SERVER_CPUS="$2"; shift ;;
        --load-cpus)    LOAD_CPUS="$2"; shift ;;
        --out)          OUTDIR="$2"; shift ;;
        --skip)         SKIP="$2"; shift ;;
        --quick)        DURATION=5; REPEAT=2 ;;
        -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

skipped() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

CPUS=$(nproc)
[ "$PORT" -eq 0 ] && PORT=$(( 8080 + ($$ % 200) ))
[ -z "$OUTDIR" ] && OUTDIR="$REPO/perf-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

# Default pinning for a 64-core c6g.metal: leave 0-7 to the kernel and NIC
# interrupts, give the server 8-23 and the load generator 32-47. On a
# smaller box fall back to quarters.
if [ -z "$SERVER_CPUS" ]; then
    if [ "$CPUS" -ge 64 ]; then SERVER_CPUS="8-23"; else SERVER_CPUS="$((CPUS/4))-$((CPUS/2-1))"; fi
fi
if [ -z "$LOAD_CPUS" ]; then
    if [ "$CPUS" -ge 64 ]; then LOAD_CPUS="32-47"; else LOAD_CPUS="$((CPUS/2))-$((CPUS-1))"; fi
fi
SERVER_CORE_COUNT=$(taskset -c "$SERVER_CPUS" nproc 2>/dev/null || echo 1)

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*" | tee -a "$OUTDIR/summary.txt"; }
info() { printf '   %s\n' "$*" | tee -a "$OUTDIR/summary.txt"; }
warn() { printf '\033[1;33m   ! %s\033[0m\n' "$*" >&2; printf '   ! %s\n' "$*" >> "$OUTDIR/summary.txt"; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

for cmd in curl taskset make nm; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found — run scripts/aws/setup_c6g_metal.sh first"
done
[ -x ./sarm ] || die "./sarm not built — run 'make' (not 'make production'; perf needs the symbols)"

# perf needs system-wide access for -a/-C. With kernel.perf_event_paranoid
# at -1 that works unprivileged; otherwise fall back to sudo and fix up the
# ownership of anything it writes.
PERF=""
if command -v perf >/dev/null 2>&1 && perf --version >/dev/null 2>&1; then
    if perf stat -a -C 0 -e task-clock -- true >/dev/null 2>&1; then
        PERF="perf"
    elif sudo -n perf stat -a -C 0 -e task-clock -- true >/dev/null 2>&1; then
        PERF="sudo perf"
    else
        warn "perf cannot profile system-wide. Either set kernel.perf_event_paranoid=-1"
        warn "or run this script with sudo. Skipping the counter and profile phases."
    fi
else
    warn "perf unavailable — skipping the counter and profile phases"
fi

# ── server / load helpers ─────────────────────────────────────────────
SERVER_PID=""
stop_server() {
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    local leftover
    leftover=$(pgrep -f "sarm $PORT" 2>/dev/null)
    if [ -n "$leftover" ]; then
        sleep 0.5
        leftover=$(pgrep -f "sarm $PORT" 2>/dev/null)
        # shellcheck disable=SC2086
        [ -n "$leftover" ] && kill -9 $leftover 2>/dev/null
    fi
    SERVER_PID=""
    set -e
}
trap stop_server EXIT INT TERM

start_server() {  # start_server <workers>
    local workers="$1"
    stop_server
    # --workers auto reads the affinity mask, so taskset here also decides
    # how many workers 'auto' spawns.
    taskset -c "$SERVER_CPUS" ./sarm "$PORT" --workers "$workers" >/dev/null 2>&1 &
    SERVER_PID=$!
    local deadline=$((SECONDS + 15))
    while [ $SECONDS -lt $deadline ]; do
        curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null && return 0
        kill -0 "$SERVER_PID" 2>/dev/null || die "server died on startup"
        sleep 0.1
    done
    die "server never became ready on 127.0.0.1:$PORT"
}

LOAD_PID=""
start_load() {  # start_load <h1|h2c|h2tls> <seconds>
    local kind="$1" secs="$2"
    case "$kind" in
        h1)    taskset -c "$LOAD_CPUS" wrk -t"$THREADS" -c"$CONNECTIONS" -d"${secs}s" \
                   "http://127.0.0.1:${PORT}${REQ_PATH}" >/dev/null 2>&1 & ;;
        h2c)   taskset -c "$LOAD_CPUS" h2load --no-tls-proto=h2c -t"$THREADS" -c"$CONNECTIONS" \
                   -m10 -D"$secs" "http://127.0.0.1:${PORT}${REQ_PATH}" >/dev/null 2>&1 & ;;
        h2tls) taskset -c "$LOAD_CPUS" h2load -t"$THREADS" -c"$CONNECTIONS" \
                   -m10 -D"$secs" "https://127.0.0.1:${PORT}${REQ_PATH}" >/dev/null 2>&1 & ;;
    esac
    LOAD_PID=$!
    sleep 1   # let the connections establish before measuring
}
wait_load() { [ -n "$LOAD_PID" ] && wait "$LOAD_PID" 2>/dev/null || true; LOAD_PID=""; }

# ══ 1. environment ════════════════════════════════════════════════════
say "1. Environment"
{
    echo "date          : $(date -Is)"
    echo "host          : $(uname -a)"
    echo "cpus          : $CPUS"
    echo "virt          : $(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo "git           : $(git -C "$REPO" log --oneline -1 2>/dev/null || echo 'not a checkout')"
    echo "git dirty     : $(git -C "$REPO" status --porcelain 2>/dev/null | wc -l) modified files"
    echo "binary        : $(sha256sum ./sarm)"
    echo "binary symbols: $(nm ./sarm 2>/dev/null | grep -c ' T ' || echo 0) global text"
    echo "stripped      : $(file ./sarm | grep -o 'not stripped\|stripped')"
    echo "server cpus   : $SERVER_CPUS ($SERVER_CORE_COUNT cores)"
    echo "load cpus     : $LOAD_CPUS"
    echo "port          : $PORT"
    echo
    echo "── sysctl ──"
    sysctl kernel.perf_event_paranoid kernel.pid_max net.core.somaxconn 2>/dev/null
    echo
    echo "── lscpu ──"
    lscpu
} > "$OUTDIR/environment.txt" 2>&1
info "written to environment.txt"
info "$(grep '^Model name' "$OUTDIR/environment.txt" | head -1 | sed 's/  */ /g')"
info "server on CPUs $SERVER_CPUS, load on CPUs $LOAD_CPUS, $CPUS total"

# ══ 2. throughput ═════════════════════════════════════════════════════
# The repo's own benchmark, which is the number to quote and compare
# against the macOS baseline. It starts and stops its own server.
if ! skipped throughput; then
    say "2. Throughput (rps_bench.sh, median of $REPEAT)"
    stop_server
    if ./scripts/benchmarks/rps_bench.sh --no-build --port "$PORT" \
            --duration "$DURATION" --repeat "$REPEAT" \
            --connections "$CONNECTIONS" --threads "$THREADS" \
            --path "$REQ_PATH" --json > "$OUTDIR/throughput.json" 2> "$OUTDIR/throughput.log"; then
        if command -v jq >/dev/null 2>&1; then
            info "HTTP/1.1     : $(jq -r '.http1_rps' "$OUTDIR/throughput.json") req/s (±$(jq -r '.http1_spread_pct' "$OUTDIR/throughput.json")%)"
            info "HTTP/2 h2c   : $(jq -r '.http2_h2c_rps' "$OUTDIR/throughput.json") req/s (±$(jq -r '.http2_h2c_spread_pct' "$OUTDIR/throughput.json")%)"
            info "HTTP/2 + TLS : $(jq -r '.http2_tls_rps' "$OUTDIR/throughput.json") req/s (±$(jq -r '.http2_tls_spread_pct' "$OUTDIR/throughput.json")%)"
        else
            info "$(cat "$OUTDIR/throughput.json")"
        fi
    else
        warn "rps_bench.sh failed — see throughput.log"
    fi
fi

# ══ 3. worker scaling ═════════════════════════════════════════════════
# A 64-core box is the only place this question can actually be answered.
#
# Two things this phase has to get right, and both differ from the pinned
# phases below:
#
#   * rps_bench.sh starts its own server and does NOT pin it, so the
#     ceiling here is the whole machine, not the 16 cores the profiling
#     phases reserve. Capping the sweep at the pinned core count would
#     stop it right where the interesting part begins.
#   * The connection count is held FIXED across the sweep, and set high
#     enough to keep the largest worker count busy. rps_bench.sh's own
#     header says connection count is part of the result; varying it
#     alongside workers would make the table unreadable. More workers
#     than concurrent connections is also just idle workers, so the sweep
#     stops at the connection count.
if ! skipped scaling; then
    # Half the machine, leaving the other half for wrk/h2load. sarm serves
    # one connection per process, so this is also the number of concurrent
    # server processes.
    SCALING_CONNS=$(( CPUS / 2 ))
    [ "$SCALING_CONNS" -lt 4 ] && SCALING_CONNS=4
    say "3. Worker scaling (${DURATION}s each, ${SCALING_CONNS} connections held fixed, unpinned)"
    printf 'workers\thttp1_rps\th2c_rps\th2tls_rps\n' > "$OUTDIR/worker_scaling.tsv"
    for w in 1 2 4 8 16 32 64; do
        [ "$w" -gt "$SCALING_CONNS" ] && break
        [ "$w" -gt "$CPUS" ] && break
        stop_server
        out="$OUTDIR/scaling_w${w}.json"
        if ./scripts/benchmarks/rps_bench.sh --no-build --port "$PORT" \
                --duration "$DURATION" --repeat 1 --workers "$w" \
                --connections "$SCALING_CONNS" --threads "$THREADS" \
                --path "$REQ_PATH" --json > "$out" 2>>"$OUTDIR/worker_scaling.log"; then
            if command -v jq >/dev/null 2>&1; then
                printf '%s\t%s\t%s\t%s\n' "$w" \
                    "$(jq -r '.http1_rps' "$out")" \
                    "$(jq -r '.http2_h2c_rps' "$out")" \
                    "$(jq -r '.http2_tls_rps' "$out")" >> "$OUTDIR/worker_scaling.tsv"
            fi
        else
            warn "workers=$w failed"
        fi
    done
    column -t "$OUTDIR/worker_scaling.tsv" 2>/dev/null | tee -a "$OUTDIR/summary.txt" || cat "$OUTDIR/worker_scaling.tsv"
fi

# ══ 4. hardware counters ══════════════════════════════════════════════
# IPC and the stall breakdown decide what kind of rewrite is worth
# attempting at all: a frontend-bound loop and a backend-bound one want
# opposite changes. This is the phase that needs bare metal.
if [ -n "$PERF" ] && ! skipped counters; then
    say "4. Hardware counters"

    # Event names vary by core and kernel; keep only what this box answers.
    EVENTS=""
    for ev in cycles instructions branches branch-misses \
              cache-references cache-misses \
              stalled-cycles-frontend stalled-cycles-backend \
              L1-dcache-loads L1-dcache-load-misses L1-icache-load-misses \
              dTLB-load-misses; do
        if ! $PERF stat -e "$ev" -x, true 2>&1 | grep -q "not supported\|<not counted>"; then
            EVENTS="${EVENTS:+$EVENTS,}$ev"
        fi
    done
    if [ -z "$EVENTS" ]; then
        warn "no hardware events are readable on this instance — is it really bare metal?"
    else
        info "events: $EVENTS"
        start_server auto
        for kind in h1 h2c h2tls; do
            start_load "$kind" "$DURATION"
            # System-wide over the server's cores only. Per-pid does not
            # work here: sarm forks a child per connection, and those
            # children are not followed by 'perf stat -p'.
            $PERF stat -a -C "$SERVER_CPUS" -e "$EVENTS" \
                -o "$OUTDIR/counters_${kind}.txt" -- sleep "$((DURATION - 2))" 2>/dev/null || true
            wait_load
            if [ -f "$OUTDIR/counters_${kind}.txt" ]; then
                cyc=$(awk '/ cycles/ {gsub(/,/,"",$1); print $1; exit}' "$OUTDIR/counters_${kind}.txt")
                ins=$(awk '/ instructions/ {gsub(/,/,"",$1); print $1; exit}' "$OUTDIR/counters_${kind}.txt")
                if [ -n "${cyc:-}" ] && [ -n "${ins:-}" ] && [ "$cyc" -gt 0 ] 2>/dev/null; then
                    info "$(printf '%-6s IPC %.2f  (%s instructions / %s cycles)' \
                        "$kind" "$(echo "$ins $cyc" | awk '{print $1/$2}')" "$ins" "$cyc")"
                fi
                grep -E "frontend|backend|branch-misses|cache-misses" "$OUTDIR/counters_${kind}.txt" \
                    | sed "s/^/   ${kind}  /" | tee -a "$OUTDIR/summary.txt" || true
            fi
        done
        stop_server
    fi
fi

# ══ 5. sampled profile ════════════════════════════════════════════════
# Flat self-time, by design. The sources carry no .cfi directives and no
# frame-pointer chain, so no unwinder can build a call tree — which is
# fine, because "which function is hot" is a self-time question.
TOP_SYMS=""
if [ -n "$PERF" ] && ! skipped profile; then
    say "5. Sampled profile"
    start_server auto
    for kind in h1 h2c h2tls; do
        start_load "$kind" "$DURATION"
        $PERF record -a -C "$SERVER_CPUS" -F 999 \
            -o "$OUTDIR/perf_${kind}.data" -- sleep "$((DURATION - 2))" >/dev/null 2>&1 || true
        wait_load
        [ -f "$OUTDIR/perf_${kind}.data" ] || continue
        [ "$PERF" = "sudo perf" ] && sudo chown "$(id -u):$(id -g)" "$OUTDIR/perf_${kind}.data"

        perf report -i "$OUTDIR/perf_${kind}.data" --stdio --no-children \
            -s dso,symbol --percent-limit 0.3 > "$OUTDIR/profile_${kind}.txt" 2>/dev/null || true

        info "── $kind: top functions in sarm ──"
        # Keep only samples that landed in the sarm binary; everything else
        # is kernel and load-generator noise from the shared cores.
        grep -E '^\s+[0-9]' "$OUTDIR/profile_${kind}.txt" 2>/dev/null \
            | grep -i 'sarm' | head -12 \
            | awk '{printf "   %8s  %s\n", $1, $NF}' | tee -a "$OUTDIR/summary.txt" || true

        if [ "$kind" = "h2tls" ] && [ -z "$TOP_SYMS" ]; then
            TOP_SYMS=$(grep -E '^\s+[0-9]' "$OUTDIR/profile_${kind}.txt" 2>/dev/null \
                | grep -i 'sarm' | head -12 | awk '{print $NF}' | grep -E '^[a-z_][a-z0-9_]*$' || true)
        fi

        if [ -x /opt/FlameGraph/flamegraph.pl ]; then
            perf script -i "$OUTDIR/perf_${kind}.data" 2>/dev/null \
                | /opt/FlameGraph/stackcollapse-perf.pl 2>/dev/null \
                | /opt/FlameGraph/flamegraph.pl --title "sarm $kind" > "$OUTDIR/flame_${kind}.svg" 2>/dev/null \
                && info "flame_${kind}.svg"
        fi
    done
    stop_server
fi

# ══ 6. per-instruction annotation ═════════════════════════════════════
# The payoff of profiling hand-written assembly: sample counts against the
# actual instructions, so a stall shows up on the instruction that stalls.
if [ -n "$PERF" ] && [ -n "$TOP_SYMS" ] && ! skipped annotate; then
    say "6. Per-instruction annotation (top functions, HTTP/2+TLS)"
    mkdir -p "$OUTDIR/annotate"
    n=0
    for sym in $TOP_SYMS; do
        [ "$n" -ge 5 ] && break
        if perf annotate -i "$OUTDIR/perf_h2tls.data" --stdio -s "$sym" \
                > "$OUTDIR/annotate/${sym}.txt" 2>/dev/null && \
                [ -s "$OUTDIR/annotate/${sym}.txt" ]; then
            info "annotate/${sym}.txt"
            n=$((n + 1))
        else
            rm -f "$OUTDIR/annotate/${sym}.txt"
        fi
    done
    [ "$n" -eq 0 ] && warn "annotation produced nothing — the sources have no .size directives, so perf may not have symbol extents"
fi

# ══ 7. micro-benchmarks ═══════════════════════════════════════════════
# scripts/benchmarks/Makefile hardcodes clang's -arch arm64, which GCC on
# Linux rejects; the flags are overridden on the command line rather than
# patched, so the file stays as the macOS side expects it.
if ! skipped micro; then
    say "7. Per-function micro-benchmarks"
    LINUX_FLAGS=(ASFLAGS="-g -O2" CFLAGS="-g -O2 -march=armv8-a+crypto" LDFLAGS="")
    : > "$OUTDIR/micro.jsonl"
    for bench in memcpy aes128_encrypt aes_gcm_encrypt gcm_ghash_run \
                 p256_fe_mul p256_bn_mul p256_reduce p256_point_mul \
                 p256_ecdsa_sign_with_k p256_scalar_inv \
                 lookup_embedded crypto_random_bytes primitives; do
        if make -C scripts/benchmarks "${LINUX_FLAGS[@]}" "bench_${bench}" \
                >>"$OUTDIR/micro.log" 2>&1 && [ -x "scripts/benchmarks/_bench_bin/bench_${bench}" ]; then
            out=$(taskset -c "${SERVER_CPUS%%-*}" "scripts/benchmarks/_bench_bin/bench_${bench}" 2>>"$OUTDIR/micro.log" || true)
            printf '%s\n' "$out" >> "$OUTDIR/micro.jsonl"
            if command -v jq >/dev/null 2>&1 && printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
                info "$(printf '%-26s %s ns' "$bench" "$(printf '%s' "$out" | jq -r '.runtime_ns // "?"')")"
            else
                info "$(printf '%-26s %s' "$bench" "${out:-no output}")"
            fi
        else
            warn "bench_${bench} did not build — see micro.log"
        fi
    done
    info "raw JSON in micro.jsonl"
fi

# ══ 8. call counts ════════════════════════════════════════════════════
# The Linux replacement for count_calls.py, which drives lldb on macOS.
# uprobes on the hot symbols identified above: frequency, not size, is what
# makes a function worth optimising.
if ! skipped calls && command -v bpftrace >/dev/null 2>&1 && [ -n "$TOP_SYMS" ]; then
    say "8. Call counts under load (bpftrace uprobes)"
    PROG=""
    for sym in $(printf '%s\n' "$TOP_SYMS" | head -12); do
        PROG="${PROG}uprobe:${REPO}/sarm:${sym} { @${sym} = count(); } "
    done
    start_server auto
    start_load h2tls 12
    if sudo timeout 10 bpftrace -e "$PROG" > "$OUTDIR/call_counts.txt" 2>"$OUTDIR/call_counts.log"; then
        grep '^@' "$OUTDIR/call_counts.txt" | sed 's/^/   /' | tee -a "$OUTDIR/summary.txt" || true
    else
        warn "bpftrace failed — see call_counts.log (uprobes on a PIE binary need a recent bpftrace)"
    fi
    wait_load
    stop_server
elif ! skipped calls; then
    info "8. Call counts — skipped (bpftrace missing, or no profile to pick symbols from)"
fi

# ══ done ══════════════════════════════════════════════════════════════
stop_server
say "Done"
info "results: $OUTDIR"
info "summary: $OUTDIR/summary.txt"
ls -1 "$OUTDIR" | sed 's/^/   /'
