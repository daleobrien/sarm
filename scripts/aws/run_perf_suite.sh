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
[ -x ./sarm ] || die "./sarm not built — run 'make production' first"

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
#
# The events are measured in SMALL GROUPS rather than all at once.
# Neoverse N1 has six programmable counters plus a dedicated cycle
# counter; asking for twelve events forces the kernel to time-multiplex
# them, and every figure comes back extrapolated from the fraction of the
# run it was actually scheduled. Each group below fits the hardware, so
# the numbers are counted rather than estimated. cycles and instructions
# repeat in every group as the common denominator.
if [ -n "$PERF" ] && ! skipped counters; then
    say "4. Hardware counters"

    # NOT named GROUPS: that is a bash special variable holding the current
    # user's group IDs, and assigning to it silently does nothing — the loop
    # then iterates over numeric gids and asks perf for events called "1000".
    EVENT_GROUPS=(
        "cycles,instructions,branches,branch-misses,stalled-cycles-frontend,stalled-cycles-backend"
        "cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses"
        "cycles,instructions,L1-icache-load-misses,dTLB-load-misses"
    )

    # Drop any event this core or kernel does not implement, so one
    # unsupported name does not void the whole group.
    supported_only() {
        local out="" ev probe
        for ev in ${1//,/ }; do
            # Accept only if perf exits clean AND the value it printed is a
            # number. A bad event name makes perf say "invalid or unsupported
            # event", which does not contain the string "not supported" — so
            # matching on that phrase alone waves nonsense through.
            if probe=$($PERF stat -e "$ev" -x, true 2>&1) \
               && printf '%s' "$probe" | head -1 | grep -qE '^[0-9,]+,'; then
                out="${out:+$out,}$ev"
            fi
        done
        printf '%s' "$out"
    }

    start_server auto
    for kind in h1 h2c h2tls; do
        : > "$OUTDIR/counters_${kind}.txt"
        g=0
        for group in "${EVENT_GROUPS[@]}"; do
            g=$((g + 1))
            evs=$(supported_only "$group")
            [ -z "$evs" ] && continue
            start_load "$kind" "$DURATION"
            # System-wide over the server's cores only. Per-pid does not
            # work here: sarm forks a child per connection, and those
            # children are not followed by 'perf stat -p'.
            $PERF stat -a -C "$SERVER_CPUS" -e "$evs" \
                -o "$OUTDIR/counters_${kind}_g${g}.txt" -- sleep "$((DURATION - 2))" \
                2>>"$OUTDIR/counters.log" || warn "perf stat failed for ${kind} group ${g} — see counters.log"
            wait_load
            if [ -f "$OUTDIR/counters_${kind}_g${g}.txt" ]; then
                cat "$OUTDIR/counters_${kind}_g${g}.txt" >> "$OUTDIR/counters_${kind}.txt"
                rm -f "$OUTDIR/counters_${kind}_g${g}.txt"
            fi
        done

        if [ -s "$OUTDIR/counters_${kind}.txt" ]; then
            # A trailing percentage on a counter line means it was still
            # multiplexed; say so rather than quoting an estimate as fact.
            if grep -qE '\([0-9]{2}\.[0-9]{2}%\)' "$OUTDIR/counters_${kind}.txt"; then
                warn "${kind}: some events were still multiplexed — values are extrapolated"
            fi
            cyc=$(awk '/ cycles/ {gsub(/,/,"",$1); print $1; exit}' "$OUTDIR/counters_${kind}.txt")
            ins=$(awk '/ instructions/ {gsub(/,/,"",$1); print $1; exit}' "$OUTDIR/counters_${kind}.txt")
            if [ -n "${cyc:-}" ] && [ -n "${ins:-}" ] && [ "$cyc" -gt 0 ] 2>/dev/null; then
                info "$(printf '%-6s IPC %.2f  (%s instructions / %s cycles)' \
                    "$kind" "$(echo "$ins $cyc" | awk '{print $1/$2}')" "$ins" "$cyc")"
            fi
            grep -E "frontend|backend|branch-misses|cache-misses|icache|dTLB" "$OUTDIR/counters_${kind}.txt" \
                | sed "s/^/   ${kind}  /" | tee -a "$OUTDIR/summary.txt" || true
        fi
    done
    stop_server
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
        # Columns are: Overhead, "Shared Object", "[.]", Symbol, then IPC
        # and [IPC Coverage] when the recorded event is cycles. The symbol
        # is $4; $NF is the trailing IPC placeholder.
        awk '$2 == "sarm" {printf "   %8s  %s\n", $1, $4}' \
            "$OUTDIR/profile_${kind}.txt" 2>/dev/null | head -12 \
            | tee -a "$OUTDIR/summary.txt" || true

        # Where the cycles went overall, which decides whether optimising
        # sarm at all is the right move for this protocol.
        awk '/^ +[0-9]/ {
                pct = $1; gsub(/%/, "", pct)
                if ($2 == "sarm") sarm += pct
                else if ($4 ~ /idle/) idle += pct
                else kern += pct
             } END {
                printf "   ── %s totals: sarm %.1f%%  kernel %.1f%%  idle %.1f%%\n", K, sarm, kern, idle
             }' K="$kind" "$OUTDIR/profile_${kind}.txt" | tee -a "$OUTDIR/summary.txt" || true

        if [ "$kind" = "h2tls" ] && [ -z "$TOP_SYMS" ]; then
            TOP_SYMS=$(awk '$2 == "sarm" {print $4}' "$OUTDIR/profile_${kind}.txt" 2>/dev/null \
                | head -12 | grep -E '^[a-zA-Z_][a-zA-Z0-9_]*$' || true)
        fi

        # Flame graph only if perf script yielded real stacks. Recorded
        # without -g (the sources carry no CFI and no frame pointers), so
        # this is usually empty — an empty SVG looks like a failure, so it
        # is deleted rather than kept.
        if [ -x /opt/FlameGraph/flamegraph.pl ]; then
            perf script -i "$OUTDIR/perf_${kind}.data" 2>/dev/null \
                | /opt/FlameGraph/stackcollapse-perf.pl 2>/dev/null \
                > "$OUTDIR/stacks_${kind}.txt" || true
            if [ -s "$OUTDIR/stacks_${kind}.txt" ]; then
                /opt/FlameGraph/flamegraph.pl --title "sarm $kind" \
                    < "$OUTDIR/stacks_${kind}.txt" > "$OUTDIR/flame_${kind}.svg" 2>/dev/null \
                    && info "flame_${kind}.svg"
            fi
            rm -f "$OUTDIR/stacks_${kind}.txt"
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
    # +crypto on ASFLAGS as well as CFLAGS: the AES and GHASH sources use
    # aese/aesmc/pmull, which GNU as rejects under a plain -march=armv8-a.
    # Without it every bench that links an AES object fails to assemble.
    # -I ../../include has to be repeated here: overriding CFLAGS on the
    # command line replaces the Makefile's value outright, and the C drivers
    # include include/asm_sym.h.
    LINUX_FLAGS=(ASFLAGS="-g -O2 -march=armv8-a+crypto" CFLAGS="-g -O2 -march=armv8-a+crypto -I ../../include" LDFLAGS="")
    : > "$OUTDIR/micro.jsonl"
    for bench in memcpy aes128_encrypt aes_gcm_encrypt gcm_ghash_run \
                 p256_fe_mul p256_bn_mul p256_reduce p256_point_mul \
                 p256_ecdsa_sign_with_k p256_scalar_inv \
                 lookup_embedded crypto_random_bytes primitives; do
        if make -C scripts/benchmarks "${LINUX_FLAGS[@]}" "bench_${bench}" \
                >>"$OUTDIR/micro.log" 2>&1 && [ -x "scripts/benchmarks/_bench_bin/bench_${bench}" ]; then
            out=$(taskset -c "${SERVER_CPUS%%-*}" "scripts/benchmarks/_bench_bin/bench_${bench}" 2>>"$OUTDIR/micro.log" || true)
            printf '%s\n' "$out" >> "$OUTDIR/micro.jsonl"
            # The drivers print one JSON object per measurement plus a
            # trailing RESULT_NS= line for the optimizer. Most emit a single
            # object; bench_primitives emits one per function/case pair. Keep
            # only the JSON and slurp it, so a multi-object driver summarises
            # as a table instead of one "?" per line.
            json=$(printf '%s\n' "$out" | grep '^{' || true)
            if command -v jq >/dev/null 2>&1 && [ -n "$json" ] &&
               printf '%s\n' "$json" | jq -se . >/dev/null 2>&1; then
                if [ "$(printf '%s\n' "$json" | jq -s 'length')" -eq 1 ]; then
                    info "$(printf '%-26s %s ns' "$bench" \
                        "$(printf '%s\n' "$json" | jq -r '.runtime_ns // "?"')")"
                    # Breakdowns live under a per-driver key (sizes, shapes,
                    # cases) and are either a scalar or a map of named
                    # timings, so render whatever object-valued fields exist
                    # rather than naming them.
                    while IFS= read -r line; do
                        [ -n "$line" ] && info "$line"
                    done < <(printf '%s\n' "$json" | jq -r '
                        to_entries[] | select(.value | type == "object")
                        | .key as $k | .value | to_entries[]
                        | "  \($k)/\(.key) = " +
                          (if (.value | type) == "object"
                           then (.value | to_entries
                                 | map("\(.key)=\(.value)") | join("  "))
                           else (.value | tostring) end)')
                else
                    info "$(printf '%-26s %s measurements' "$bench" \
                        "$(printf '%s\n' "$json" | jq -s 'length')")"
                    while IFS=$'\t' read -r label ns; do
                        info "$(printf '  %-32s %12s ns' "$label" "$ns")"
                    done < <(printf '%s\n' "$json" | jq -r '
                        [ (.function // "?") + " " + (.case // ""),
                          (.ns_per_call // .runtime_ns // "?" | tostring) ]
                        | @tsv')
                fi
            else
                info "$(printf '%-26s %s' "$bench" "${out:-no output}")"
            fi
        elif grep -q "@PAGE" "$OUTDIR/micro.log" 2>/dev/null && \
             [ "$bench" = "primitives" -o "$bench" = "aes_gcm_encrypt" ]; then
            # bench_primitives.c and bench_aes_gcm_encrypt.c carry inline asm
            # written in Mach-O syntax (adrp x8, _sym@PAGE / add x8, x8,
            # _sym@PAGEOFF). GNU as needs adrp x8, sym / add x8, x8, :lo12:sym.
            # No compiler flag fixes this — the drivers need porting.
            warn "bench_${bench}: macOS-only inline asm (@PAGE/@PAGEOFF) — needs :lo12: for ELF"
        else
            warn "bench_${bench} did not build — see micro.log"
        fi
    done
    info "raw JSON in micro.jsonl"
fi

# ══ 8. call counts ════════════════════════════════════════════════════
# The Linux replacement for count_calls.py, which drives lldb on macOS.
# Frequency, not size, is what makes a function worth optimising.
#
# Attached by FILE OFFSET through the kernel's own uprobe_events interface,
# not by name and not through bpftrace. sarm's sources emit no
# `.type name, %function` directives, so all 170 of its globals are
# STT_NOTYPE — bpftrace rejects those both by name ("No matches for uprobe")
# and by address ("Could not resolve address"), because it validates the
# address against a containing STT_FUNC symbol before attaching. The tracefs
# interface performs no such validation: it takes a raw file offset. So take
# the symbol's virtual address from nm, translate it through the PT_LOAD
# segment that contains it, and count the resulting tracepoint with perf.
if ! skipped calls && [ -n "$TOP_SYMS" ] && [ -n "$PERF" ]; then
    say "8. Call counts under load (uprobe_events + perf stat)"

    TRACEFS=/sys/kernel/tracing
    [ -d "$TRACEFS/events" ] || TRACEFS=/sys/kernel/debug/tracing

    # Pure bash arithmetic rather than awk: strtonum() is a gawk extension
    # and Ubuntu's default awk is mawk, which does not have it.
    file_offset_of() {  # file_offset_of <symbol> -> hex file offset, or empty
        local sym="$1" vaddr target o v z seg_off seg_va seg_sz
        vaddr=$(nm ./sarm 2>/dev/null | awk -v s="$sym" '$3 == s {print $1; exit}')
        [ -z "$vaddr" ] && return 1
        target=$(( 16#$vaddr ))
        # readelf -lW LOAD line: LOAD Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
        while read -r _ seg_off seg_va _ _ seg_sz _; do
            case "$seg_off$seg_va$seg_sz" in *0x*) ;; *) continue ;; esac
            o=$(( seg_off )); v=$(( seg_va )); z=$(( seg_sz ))
            if [ "$target" -ge "$v" ] && [ "$target" -lt $(( v + z )) ]; then
                printf '0x%x\n' $(( target - v + o ))
                return 0
            fi
        done < <(readelf -lW ./sarm 2>/dev/null | awk '$1 == "LOAD"')
        return 1
    }

    probe_del() {  # remove one probe, ignoring "was never there"
        printf -- '-:sarmbench/%s\n' "$1" | sudo tee -a "$TRACEFS/uprobe_events" >/dev/null 2>&1 || true
    }

    if [ ! -w "$TRACEFS/uprobe_events" ] && ! sudo test -w "$TRACEFS/uprobe_events"; then
        warn "no writable $TRACEFS/uprobe_events — skipping call counts"
    else
        # kernel.perf_event_paranoid=-1 buys unprivileged access to hardware
        # counters, but not to tracefs: /sys/kernel/tracing is mode 700 and
        # root-owned, so an unprivileged perf cannot read the tracepoint's
        # id file even though the probe exists ("No permissions to read
        # .../events/sarmbench/<sym>"). Count these events as root.
        CALL_PERF="$PERF"
        if [ "$CALL_PERF" != "sudo perf" ] && [ ! -r "$TRACEFS/events" ]; then
            if sudo -n perf --version >/dev/null 2>&1; then
                CALL_PERF="sudo perf"
            else
                warn "$TRACEFS not readable and no sudo perf — call counts may fail"
            fi
        fi
        EVENTS=""
        ATTACHED=""
        for sym in $(printf '%s\n' "$TOP_SYMS" | head -12); do
            off=$(file_offset_of "$sym" || true)
            if [ -z "$off" ]; then
                warn "no file offset for ${sym} — skipping"
                continue
            fi
            probe_del "$sym"
            if printf 'p:sarmbench/%s %s/sarm:%s\n' "$sym" "$REPO" "$off" \
               | sudo tee -a "$TRACEFS/uprobe_events" >>"$OUTDIR/call_counts.log" 2>&1; then
                EVENTS="${EVENTS:+$EVENTS,}sarmbench:${sym}"
                ATTACHED="${ATTACHED} ${sym}"
            else
                warn "could not create uprobe for ${sym} at ${off}"
            fi
        done

        if [ -z "$EVENTS" ]; then
            warn "no uprobes created — see call_counts.log"
        else
            info "counting:${ATTACHED}"
            start_server auto
            start_load h2tls "$DURATION"
            $CALL_PERF stat -a -C "$SERVER_CPUS" -e "$EVENTS" \
                -o "$OUTDIR/call_counts.txt" -- sleep "$((DURATION - 2))" \
                2>>"$OUTDIR/call_counts.log" || warn "perf stat failed — see call_counts.log"
            wait_load
            stop_server
            [ "$CALL_PERF" = "sudo perf" ] && \
                sudo chown "$(id -u):$(id -g)" "$OUTDIR/call_counts.txt" 2>/dev/null
            awk '$2 ~ /^sarmbench:/ {sub(/^sarmbench:/, "", $2); printf "   %16s  %s\n", $1, $2}' \
                "$OUTDIR/call_counts.txt" 2>/dev/null | tee -a "$OUTDIR/summary.txt"
        fi

        for sym in $ATTACHED; do probe_del "$sym"; done
    fi
elif ! skipped calls; then
    info "8. Call counts — skipped (no perf, or no profile to pick symbols from)"
fi

# ══ done ══════════════════════════════════════════════════════════════
stop_server
say "Done"
info "results: $OUTDIR"
info "summary: $OUTDIR/summary.txt"
ls -1 "$OUTDIR" | sed 's/^/   /'
