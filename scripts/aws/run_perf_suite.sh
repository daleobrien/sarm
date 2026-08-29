#!/usr/bin/env bash
# run_perf_suite.sh — measure sarm on Linux/aarch64 (Graviton, ec2 metal).
#
# Runs the whole measurement stack in one pass and writes everything to a
# timestamped directory:
#
#   1. environment    what machine, what binary, what kernel settings
#   2. throughput     req/s, latency and concurrency over h1, h2c, h2+TLS
#   3. worker scaling how req/s moves with --workers, swept to the host's
#                     core count
#   4. counters       IPC, stalls, misses, and which cpuset was busy
#   5. profile        which functions burn the time, per protocol
#   6. annotate       per-instruction attribution for the hottest functions
#   7. micro          per-function benchmarks (crypto, memcpy, P-256)
#   8. calls          how often the hot functions actually run
#
# Everything is pinned: the server on one core set, the load generator on
# another, with the low cores left to the kernel and NIC interrupts. That
# is what makes two runs comparable — an unpinned run on a many-core box
# measures the scheduler as much as the server.
#
# THE TWO SIDES ARE NOT GIVEN EQUAL CORES, and should not be. On loopback
# the client pays for TLS, HPACK and frame handling exactly like the
# server does, and it pays more: the 2026-08-26 run had h2load pegged at
# 99.8% of its 16 cores while sarm sat at 24.5% of its 16 — i.e. ~16
# client cores of work to drive ~3.9 cores of server work, a 4:1 cost
# ratio. Splitting the box evenly therefore hands the bottleneck to the
# client and measures h2load. The default below gives the server an
# eighth of the machine and the client everything above it (on 64 cores:
# reserve 0-7, server 8-15, load 16-63), which is 6:1 in cores and so
# leaves the server the slower side by a comfortable margin.
#
# Because the two sides have different core counts, ABSOLUTE cycle counts
# and busy percentages are not comparable across them. Section 4 reports
# both sides in CORES BUSY (cycles / core clock / seconds — 3.92 of 16
# rather than 24.5%), plus req/s per busy server core and cycles per
# request, which are the figures that stay meaningful when the split
# changes.
#
# READ SECTIONS 2 AND 4 TOGETHER. This is a closed-loop benchmark over
# loopback, so it can only measure the server when the server is the
# slowest part of the loop, and two separate things can stop that being
# true:
#
#   * the concurrency ceiling (connections x max-streams). Below it,
#     req/s is just concurrency/latency. Section 2 prints the in-flight
#     count and its percentage of the ceiling next to every figure.
#   * the load generator itself. h2load pays for TLS on the client side
#     too. Section 4 counts cycles on the load cpuset over the same
#     window as the server's and prints both as a percentage of their
#     cycle budget, so "client-bound" is a reading rather than a guess.
#
# The 2026-08-25 run (perf-results/ec2-20260825-175523) was caught by
# both at once: every protocol sat on the 160-request ceiling while
# sarm's cores were ~85% idle, and its h2tls figure swung 607k-799k
# between two passes of one binary. The defaults here (-m64, one client
# thread per load core, a 3s settle) exist to keep that from recurring.
#
# Usage:
#   ./scripts/aws/run_perf_suite.sh
#   ./scripts/aws/run_perf_suite.sh --quick             # short durations
#   ./scripts/aws/run_perf_suite.sh --duration 30 --repeat 7
#   ./scripts/aws/run_perf_suite.sh --max-streams 128   # raise the ceiling
#   ./scripts/aws/run_perf_suite.sh --warm-up 5         # longer settle
#   ./scripts/aws/run_perf_suite.sh --server-cpus 8-15 --load-cpus 16-63
#   ./scripts/aws/run_perf_suite.sh --connections 96   # more client load
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
# 0 = derive from the load cpuset. h2load requires connections >= threads
# and we want one client thread per load core, so a fixed 16 would cap the
# client at 16 threads no matter how many cores it was given -- which is
# exactly the bottleneck this layout exists to remove. See CONNECTIONS
# below the cpuset derivation.
CONNECTIONS=0
# 0 = derive from the load cpuset (one h2load thread per load core), so
# the client is not the thing being measured. See MAX_STREAMS below.
THREADS=0
# Concurrency per connection. 10 x 16 conns = 160 outstanding requests
# was the old default and it was the binding constraint on every
# protocol -- see the header of scripts/benchmarks/rps_bench.sh.
MAX_STREAMS=64
# HTTP/1.1 requests per send. 1 -- an ordinary keep-alive client -- is
# the default and what every stored result was measured at. Raising it
# is how you ask what an h1 request costs when the server is not woken
# for each one; see scripts/benchmarks/pipeline.lua.
PIPELINE=1
WARMUP=3
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
        --max-streams)  MAX_STREAMS="$2"; shift ;;
        --pipeline)     PIPELINE="$2"; shift ;;
        --warm-up)      WARMUP="$2"; shift ;;
        --path)         REQ_PATH="$2"; shift ;;
        --server-cpus)  SERVER_CPUS="$2"; shift ;;
        --load-cpus)    LOAD_CPUS="$2"; shift ;;
        --out)          OUTDIR="$2"; shift ;;
        --skip)         SKIP="$2"; shift ;;
        --quick)        DURATION=5; REPEAT=2; WARMUP=1 ;;
        -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

skipped() { case ",$SKIP," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

CPUS=$(nproc)
# Builds here (the micro-benchmark drivers in section 7) happen between
# measurements, never during one, so they may as well use the whole box.
export MAKEFLAGS="-j$CPUS"
[ "$PORT" -eq 0 ] && PORT=$(( 8080 + ($$ % 200) ))
[ -z "$OUTDIR" ] && OUTDIR="$REPO/perf-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

# Default pinning, derived from the core count rather than assuming a
# 64-core c6g.metal: leave the first eighth of the machine to the kernel
# and NIC interrupts, give the server the next eighth, and give the load
# generator EVERYTHING ABOVE IT. On a 64-core box: reserve 0-7, server
# 8-15, load 16-63, and it keeps that shape on 16, 96 or 192 cores.
#
# This used to be a quarter each (server 8-23, load 32-47) and that is
# the split that produced the client-bound 2026-08-26 run: equal cores
# for a client that costs ~4x what the server costs per request means the
# client runs out first, and section 2 then reports h2load's ceiling
# under sarm's name. Six load cores per server core turns that around
# with room to spare; if the server still does not saturate, the fix is
# fewer server cores (--server-cpus), not more.
RESERVED_CORES=$(( CPUS / 8 ))
SERVER_BLOCK=$(( CPUS / 8 ))
[ "$SERVER_BLOCK" -lt 1 ] && SERVER_BLOCK=1
if [ -z "$SERVER_CPUS" ]; then
    s_lo=$RESERVED_CORES
    s_hi=$(( s_lo + SERVER_BLOCK - 1 ))
    [ "$s_hi" -gt $(( CPUS - 1 )) ] && s_hi=$(( CPUS - 1 ))
    SERVER_CPUS="$s_lo-$s_hi"
fi
if [ -z "$LOAD_CPUS" ]; then
    # Start after the default server block even when --server-cpus moved
    # the server elsewhere: the two are checked for overlap below, and a
    # list-form --server-cpus has no "last core" to read off.
    l_lo=$(( RESERVED_CORES + SERVER_BLOCK ))
    l_hi=$(( CPUS - 1 ))
    [ "$l_lo" -gt "$l_hi" ] && l_lo=$l_hi
    LOAD_CPUS="$l_lo-$l_hi"
fi
SERVER_CORE_COUNT=$(taskset -c "$SERVER_CPUS" nproc 2>/dev/null || echo 1)
LOAD_CORE_COUNT=$(taskset -c "$LOAD_CPUS" nproc 2>/dev/null || echo 1)

# One h2load thread per load core. h2load has no per-thread affinity of
# its own, so the closest thing to pinning it 1:1 is to give it exactly
# as many threads as the cpuset has cores and let the scheduler settle
# one per core. With fewer threads than cores (the old hardcoded 8 on a
# 16-core cpuset) the client had spare cores it could never use while
# still being the bottleneck.
[ "$THREADS" -eq 0 ] && THREADS=$LOAD_CORE_COUNT
# Connections follow the load cores for the same reason. h2load requires
# connections >= threads, so a connection count below the thread count
# silently throws load cores away -- and sarm serves one connection per
# process, so this is also how many server processes the (smaller) server
# cpuset has to multiplex, which is the point: the server is meant to be
# the side that runs out.
if [ "$CONNECTIONS" -eq 0 ]; then
    CONNECTIONS=$LOAD_CORE_COUNT
    [ "$CONNECTIONS" -lt 16 ] && CONNECTIONS=16
fi
# An explicit --connections below the thread count still has to be honoured.
[ "$CONNECTIONS" -lt "$THREADS" ] && THREADS=$CONNECTIONS

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*" | tee -a "$OUTDIR/summary.txt"; }
info() { printf '   %s\n' "$*" | tee -a "$OUTDIR/summary.txt"; }
warn() { printf '\033[1;33m   ! %s\033[0m\n' "$*" >&2; printf '   ! %s\n' "$*" >> "$OUTDIR/summary.txt"; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

for cmd in curl taskset make nm; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found — run scripts/aws/setup_ec2_metal.sh first"
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
# --pipeline has to reach THIS load generator too, not just the one
# rps_bench.sh runs in section 2. The 2026-08-29 run passed --pipeline 8
# and got a section 2 that pipelined and sections 4-8 that did not, so
# the counters described a different workload from the throughput above
# them — and reported the unpipelined 1.02 context switches per request
# under a heading that said pipeline 8.
H1_LOAD_SCRIPT=()
H1_LOAD_SCRIPT_ARGS=()
if [ "$PIPELINE" -gt 1 ]; then
    if [ -f scripts/benchmarks/pipeline.lua ]; then
        H1_LOAD_SCRIPT=(-s scripts/benchmarks/pipeline.lua)
        H1_LOAD_SCRIPT_ARGS=(-- "$PIPELINE")
    else
        warn "scripts/benchmarks/pipeline.lua is missing — sections 4-8 will not pipeline"
    fi
fi

start_load() {  # start_load <h1|h2c|h2tls> <seconds>
    local kind="$1" secs="$2"
    # The client's own report is kept rather than discarded: it is the
    # only req/s figure measured over the same run as the counters, and
    # section 4 divides it by the server cores that were actually busy.
    local log="$OUTDIR/load_${kind}.txt"
    case "$kind" in
        h1)    taskset -c "$LOAD_CPUS" wrk -t"$THREADS" -c"$CONNECTIONS" -d"${secs}s" \
                   ${H1_LOAD_SCRIPT[@]+"${H1_LOAD_SCRIPT[@]}"} \
                   "http://127.0.0.1:${PORT}${REQ_PATH}" \
                   ${H1_LOAD_SCRIPT_ARGS[@]+"${H1_LOAD_SCRIPT_ARGS[@]}"} >"$log" 2>&1 & ;;
        h2c)   taskset -c "$LOAD_CPUS" h2load --no-tls-proto=h2c -t"$THREADS" -c"$CONNECTIONS" \
                   -m"$MAX_STREAMS" -D"$secs" "http://127.0.0.1:${PORT}${REQ_PATH}" >"$log" 2>&1 & ;;
        h2tls) taskset -c "$LOAD_CPUS" h2load -t"$THREADS" -c"$CONNECTIONS" \
                   -m"$MAX_STREAMS" -D"$secs" "https://127.0.0.1:${PORT}${REQ_PATH}" >"$log" 2>&1 & ;;
    esac
    LOAD_PID=$!
    # Let the connections establish AND the run reach steady state before
    # measuring. The 2026-08-25 run settled for 1s against a ~2.7ms
    # connect and a TLS handshake per connection, so setup transients
    # landed inside the measurement window.
    sleep "$SETTLE"
}
wait_load() { [ -n "$LOAD_PID" ] && wait "$LOAD_PID" 2>/dev/null || true; LOAD_PID=""; }

# load_rps <kind> — req/s as the client reported it, or empty. wrk prints
# "Requests/sec:  12345.67"; h2load prints "finished in 20.00s, 12345.67
# req/s, ...". This is an average over the WHOLE run including the settle,
# so it is a little below the steady-state rate the counters window saw.
load_rps() {
    awk '/Requests\/sec:/ { print $2; exit }
         /req\/s/ { for (i = 2; i <= NF; i++)
                        if ($i ~ /^req\/s,?$/) { r = $(i-1); gsub(/,/, "", r); print r; exit } }' \
        "$OUTDIR/load_${1}.txt" 2>/dev/null | head -1
}

# How long a load runs (DURATION) vs how much of it is measured: skip the
# settle at the front and stop a second before the client does, so no
# window ever contains connection setup or teardown.
SETTLE=$WARMUP
[ "$SETTLE" -lt 1 ] && SETTLE=1
MEASURE_SECS=$(( DURATION - SETTLE - 1 ))
[ "$MEASURE_SECS" -lt 1 ] && MEASURE_SECS=1

# ══ 1. environment ════════════════════════════════════════════════════
say "1. Environment"
{
    echo "date          : $(date -Is)"
    echo "host          : $(uname -a)"
    echo "cpus          : $CPUS"
    echo "virt          : $(systemd-detect-virt 2>/dev/null || echo unknown)"
    # A tree uploaded by quick_test_ec2.sh has no .git — it is a tarball of
    # `git ls-files`, not a clone — so both git calls below fail there and
    # the dirty count degrades to a confident, wrong 0. Prefer the
    # .perf-provenance file that script stamps before uploading; fall back
    # to real git when the suite is run inside an actual checkout.
    if [ -r "$REPO/.perf-provenance" ]; then
        sed 's/^/git /' "$REPO/.perf-provenance"
    elif git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
        echo "git commit    : $(git -C "$REPO" log --oneline -1)"
        echo "git dirty     : $(git -C "$REPO" status --porcelain | wc -l | tr -d ' ') modified files"
    else
        echo "git commit    : UNKNOWN — no .git and no .perf-provenance"
        echo "git dirty     : unknown"
    fi
    echo "binary        : $(sha256sum ./sarm)"
    echo "binary symbols: $(nm ./sarm 2>/dev/null | grep -c ' T ' || true) global text"
    echo "stripped      : $(file ./sarm | grep -o 'not stripped\|stripped')"
    echo "server cpus   : $SERVER_CPUS ($SERVER_CORE_COUNT cores)"
    echo "load cpus     : $LOAD_CPUS ($LOAD_CORE_COUNT cores)"
    echo "load:server   : $(awk -v l="$LOAD_CORE_COUNT" -v s="$SERVER_CORE_COUNT" \
                              'BEGIN{printf "%.1f:1 cores", (s>0?l/s:0)}')"
    echo "connections   : $CONNECTIONS ($THREADS client threads, -m$MAX_STREAMS)"
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
info "$(printf 'server on CPUs %s (%d cores), load on CPUs %s (%d cores), %d total — %.1f load cores per server core' \
    "$SERVER_CPUS" "$SERVER_CORE_COUNT" "$LOAD_CPUS" "$LOAD_CORE_COUNT" "$CPUS" \
    "$(awk -v l="$LOAD_CORE_COUNT" -v s="$SERVER_CORE_COUNT" 'BEGIN{print (s>0?l/s:0)}')")"
# Too few cores to keep the two apart: the load generator then competes
# with the server for the cores it is measuring, so every figure below
# is a lower bound rather than a measurement of the server.
if [ "$SERVER_CPUS" = "$LOAD_CPUS" ]; then
    warn "server and load share CPUs $SERVER_CPUS — only $CPUS core(s) on this host."
    warn "Results measure the whole box, not the server. Use a larger instance."
fi

# ══ 2. throughput ═════════════════════════════════════════════════════
# The repo's own benchmark, which is the number to quote and compare
# against the macOS baseline. It starts and stops its own server.
if ! skipped throughput; then
    say "2. Throughput (rps_bench.sh, median of $REPEAT, -c$CONNECTIONS -m$MAX_STREAMS -t$THREADS$(
        [ "$PIPELINE" -gt 1 ] && printf ' --pipeline %s' "$PIPELINE"))"
    stop_server
    # The cpusets travel with it. Without them rps_bench.sh starts an
    # UNPINNED server on the whole machine, so section 2 measured 64
    # cores while sections 4-6 measured the 2 they were given -- the
    # 2026-08-26 run read 9.5M req/s here and 909k there for one binary.
    if ./scripts/benchmarks/rps_bench.sh --no-build --port "$PORT" \
            --server-cpus "$SERVER_CPUS" --load-cpus "$LOAD_CPUS" \
            --duration "$DURATION" --repeat "$REPEAT" \
            --connections "$CONNECTIONS" --threads "$THREADS" \
            --max-streams "$MAX_STREAMS" --pipeline "$PIPELINE" --warm-up "$WARMUP" \
            --path "$REQ_PATH" --json > "$OUTDIR/throughput.json" 2> "$OUTDIR/throughput.log"; then
        if command -v jq >/dev/null 2>&1; then
            # Latency and in-flight concurrency next to every req/s, so a
            # concurrency-bound run is legible as one. See the header of
            # rps_bench.sh for why the bare req/s number misleads.
            jq -r '
              [ ["HTTP/1.1    ", .http1_rps, .http1_spread_pct, .http1_latency_us,
                 .http1_inflight, .http1_ceiling, .http1_saturation_pct],
                ["HTTP/2 h2c  ", .http2_h2c_rps, .http2_h2c_spread_pct, .http2_h2c_latency_us,
                 .http2_h2c_inflight, .http2_ceiling, .http2_h2c_saturation_pct],
                ["HTTP/2 + TLS", .http2_tls_rps, .http2_tls_spread_pct, .http2_tls_latency_us,
                 .http2_tls_inflight, .http2_ceiling, .http2_tls_saturation_pct] ][]
              | "\(.[0]) : \(.[1]) req/s (±\(.[2])%)  \(.[3])us mean  \(.[4])/\(.[5]) in flight (\(.[6])% of ceiling)"
            ' "$OUTDIR/throughput.json" | while IFS= read -r line; do info "$line"; done
            # h2 only: wrk holds exactly --connections in flight always,
            # so HTTP/1.1 reads ~100% on every run and --max-streams
            # cannot move it. See rps_bench.sh for the full reasoning.
            worst=$(jq -r '[.http2_h2c_saturation_pct,
                            .http2_tls_saturation_pct] | max' "$OUTDIR/throughput.json")
            if awk -v w="$worst" 'BEGIN{exit !(w >= 85)}' 2>/dev/null; then
                warn "concurrency ceiling is binding (${worst}%) — raise --max-streams above $MAX_STREAMS"
                warn "req/s at that saturation is concurrency/latency, not server capacity"
            fi
        else
            info "$(cat "$OUTDIR/throughput.json")"
        fi
    else
        warn "rps_bench.sh failed — see throughput.log"
    fi
fi

# ══ 3. worker scaling ═════════════════════════════════════════════════
# A many-core box is the only place this question can actually be
# answered; the sweep sizes itself to whatever the host reports.
#
# Two things this phase has to get right, and both differ from the pinned
# phases below:
#
#   * rps_bench.sh starts its own server and does NOT pin it, so the
#     ceiling here is the whole machine, not the quarter of it the
#     profiling phases reserve. Capping the sweep at the pinned core count would
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
    printf 'workers\thttp1_rps\th2c_rps\th2tls_rps\th2c_sat%%\th2tls_sat%%\n' > "$OUTDIR/worker_scaling.tsv"
    # Powers of two up to the machine, not a fixed 1..64 list: on a box
    # with more than 64 cores the sweep has to keep going to find the
    # knee, and on a smaller one it has to stop early.
    SCALING_MAX=$SCALING_CONNS
    [ "$SCALING_MAX" -gt "$CPUS" ] && SCALING_MAX=$CPUS
    # h2load requires connections >= threads, and this phase holds its own
    # (smaller) connection count fixed, so the client thread count has to
    # be clamped to it rather than inherited from the load cpuset.
    SCALING_THREADS=$THREADS
    [ "$SCALING_THREADS" -gt "$SCALING_CONNS" ] && SCALING_THREADS=$SCALING_CONNS
    w=1
    while [ "$w" -le "$SCALING_MAX" ]; do
        stop_server
        out="$OUTDIR/scaling_w${w}.json"
        if ./scripts/benchmarks/rps_bench.sh --no-build --port "$PORT" \
                --duration "$DURATION" --repeat 1 --workers "$w" \
                --connections "$SCALING_CONNS" --threads "$SCALING_THREADS" \
                --max-streams "$MAX_STREAMS" --pipeline "$PIPELINE" --warm-up "$WARMUP" \
                --path "$REQ_PATH" --json > "$out" 2>>"$OUTDIR/worker_scaling.log"; then
            if command -v jq >/dev/null 2>&1; then
                # Saturation travels with each row: a flat rps column
                # means nothing if every row sat on the same ceiling.
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$w" \
                    "$(jq -r '.http1_rps' "$out")" \
                    "$(jq -r '.http2_h2c_rps' "$out")" \
                    "$(jq -r '.http2_tls_rps' "$out")" \
                    "$(jq -r '.http2_h2c_saturation_pct' "$out")" \
                    "$(jq -r '.http2_tls_saturation_pct' "$out")" >> "$OUTDIR/worker_scaling.tsv"
            fi
        else
            warn "workers=$w failed"
        fi
        w=$(( w * 2 ))
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
        # context-switches and cpu-migrations are software events: the
        # kernel counts them, they occupy no PMU slot, and they therefore
        # ride along in an existing group rather than costing a fourth
        # load run. They are here because the h1 profile is 18% of cycles
        # in finish_task_switch and 8% in the wakeup path — a
        # process-per-connection server with more connections than cores
        # pays a wake/sleep per request, and without this row that cost
        # has to be inferred from icache-miss ratios.
        "cycles,instructions,L1-icache-load-misses,dTLB-load-misses,context-switches,cpu-migrations"
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

    # Cycles a single fully-busy core retires per second, measured rather
    # than assumed: it is the denominator for every utilisation figure
    # below, and neither /proc/cpuinfo (BogoMIPS is the arch timer, not
    # the core clock) nor cpufreq (absent on Graviton) reports it.
    CORE_HZ=""
    calib=$($PERF stat -e cycles -x, -- \
        taskset -c "${SERVER_CPUS%%-*}" timeout 1 \
        bash -c 'while :; do :; done' 2>&1 | \
        awk -F, '$1 ~ /^[0-9]+$/ && $3 ~ /^cycles/ {print $1; exit}' || true)
    if [ -n "$calib" ] && [ "$calib" -gt 0 ] 2>/dev/null; then
        CORE_HZ=$calib
        info "$(printf 'core clock    : %.2f GHz (measured on a busy core)' \
            "$(awk -v h="$CORE_HZ" 'BEGIN{print h/1e9}')")"
    else
        warn "could not measure core clock — utilisation percentages omitted"
    fi

    # busy_pct <cycles> <cores> — share of that cpuset's cycle budget used.
    busy_pct() {
        [ -z "$CORE_HZ" ] && { printf '?'; return; }
        awk -v c="$1" -v n="$2" -v hz="$CORE_HZ" -v s="$MEASURE_SECS" \
            'BEGIN { b = n * s * hz; printf "%.1f", (b > 0 ? c / b * 100 : 0) }'
    }

    # cores_busy <cycles> — the same measurement expressed as whole cores
    # of work, which is the only form comparable across two cpusets of
    # different sizes. "24.5% of 16" and "99.8% of 16" describe a 4:1 gap
    # that neither percentage states; 3.92 cores against 15.97 does.
    cores_busy() {
        [ -z "$CORE_HZ" ] && { printf '?'; return; }
        awk -v c="$1" -v hz="$CORE_HZ" -v s="$MEASURE_SECS" \
            'BEGIN { b = s * hz; printf "%.2f", (b > 0 ? c / b : 0) }'
    }

    start_server auto
    for kind in h1 h2c h2tls; do
        : > "$OUTDIR/counters_${kind}.txt"
        : > "$OUTDIR/counters_${kind}_load.txt"
        g=0
        for group in "${EVENT_GROUPS[@]}"; do
            g=$((g + 1))
            evs=$(supported_only "$group")
            [ -z "$evs" ] && continue
            start_load "$kind" "$DURATION"
            # System-wide over the server's cores only. Per-pid does not
            # work here: sarm forks a child per connection, and those
            # children are not followed by 'perf stat -p'.
            #
            # The load cores get their own counter over the SAME window,
            # in parallel. Without it there is no way to tell a server at
            # its limit from a saturated client feeding an idle server —
            # which is exactly what the 2026-08-25 h2tls numbers turned
            # out to be. Only the first group needs it; cycles is all the
            # utilisation figure uses.
            if [ "$g" -eq 1 ]; then
                $PERF stat -a -C "$LOAD_CPUS" -e cycles,instructions \
                    -o "$OUTDIR/counters_${kind}_load.txt" -- sleep "$MEASURE_SECS" \
                    2>>"$OUTDIR/counters.log" &
                load_stat_pid=$!
            else
                load_stat_pid=""
            fi
            $PERF stat -a -C "$SERVER_CPUS" -e "$evs" \
                -o "$OUTDIR/counters_${kind}_g${g}.txt" -- sleep "$MEASURE_SECS" \
                2>>"$OUTDIR/counters.log" || warn "perf stat failed for ${kind} group ${g} — see counters.log"
            [ -n "$load_stat_pid" ] && { wait "$load_stat_pid" 2>/dev/null || true; }
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

            # The verdict line: which side of the loopback was actually
            # working. Load cores near their budget mean the number in
            # section 2 is a measurement of the client, not of sarm;
            # server headroom is reported separately and does not gate
            # the verdict.
            #
            # Reported per core throughout, because the two cpusets are
            # deliberately different sizes: cores of work on each side,
            # the client's cost as a multiple of the server's, req/s per
            # busy server core, and cycles per request. Only the last two
            # survive a change of core split or instance size, so they are
            # the figures to quote and to compare between builds.
            lcyc=$(awk '/ cycles/ {gsub(/,/,"",$1); print $1; exit}' \
                "$OUTDIR/counters_${kind}_load.txt" 2>/dev/null)
            if [ -n "${cyc:-}" ] && [ -n "${lcyc:-}" ] && [ -n "$CORE_HZ" ]; then
                sbusy=$(busy_pct "$cyc" "$SERVER_CORE_COUNT")
                lbusy=$(busy_pct "$lcyc" "$LOAD_CORE_COUNT")
                scores=$(cores_busy "$cyc")
                lcores=$(cores_busy "$lcyc")
                verdict=$(awk -v s="$sbusy" -v l="$lbusy" 'BEGIN {
                    if (l >= 85)      print "  <- CLIENT-BOUND: section 2 is not measuring sarm (give the client more cores: --load-cpus, or run it on a second instance)"
                    else if (s >= 85) print "  <- server saturated"
                    else              print "  <- neither side saturated: check the concurrency ceiling"
                }')
                info "$(printf '%-6s sarm %s of %s cores busy (%s%%), client %s of %s cores busy (%s%%)%s' \
                    "$kind" "$scores" "$SERVER_CORE_COUNT" "$sbusy" \
                    "$lcores" "$LOAD_CORE_COUNT" "$lbusy" "$verdict")"
                info "$(awk -v k="$kind" -v s="$scores" -v l="$lcores" 'BEGIN {
                    if (s > 0) printf "%-6s cost ratio: the client burns %.2f cores per busy sarm core", k, l / s
                    else       printf "%-6s cost ratio: server cycles too low to divide by", k
                }')"
                # Per-core efficiency, from the client's own req/s over the
                # same run. Divided by cores actually busy rather than cores
                # allocated: allocation is a knob, occupancy is the result.
                rps=$(load_rps "$kind")
                if [ -n "$rps" ]; then
                    info "$(awk -v k="$kind" -v r="$rps" -v s="$scores" -v l="$lcores" \
                             -v sc="$cyc" -v lc="$lcyc" -v secs="$MEASURE_SECS" 'BEGIN {
                        n = r * secs
                        printf "%-6s per core: %.0f req/s per busy sarm core", k, (s > 0 ? r / s : 0)
                        if (n > 0) printf "  |  cycles/request: sarm %.0f, client %.0f", sc / n, lc / n
                    }')"

                    # Switches per request is the figure that separates a
                    # server spending its cycles on work from one spending
                    # them on being scheduled. Two per request is the floor
                    # for a blocking read/write pair; well above that means
                    # the wake path, not the protocol code, is the cost.
                    #
                    # The request count comes from the group-1 load run and
                    # the switch count from group 3 — different runs of the
                    # same load for the same seconds, so this is a rate
                    # comparison, not an exact per-request tally.
                    # $1 is only taken when it is a number: perf writes
                    # "<not counted>" into that column for an event it
                    # could not schedule, and %d of that is a confident 0.
                    csw=$(awk '/ context-switches/ && $1 ~ /^[0-9,]+$/ {
                        gsub(/,/,"",$1); print $1; exit }' \
                        "$OUTDIR/counters_${kind}.txt")
                    sched=""
                    [ -n "${csw:-}" ] && sched=$(awk -v k="$kind" -v c="$csw" \
                        -v r="$rps" -v secs="$MEASURE_SECS" 'BEGIN {
                            n = r * secs
                            if (n > 0) printf "%-6s scheduling: %.2f context switches per request (%d in %ds)", k, c / n, c, secs
                        }')
                    [ -n "$sched" ] && info "$sched"
                fi
            fi
            grep -E "frontend|backend|branch-misses|cache-misses|icache|dTLB|context-switches|cpu-migrations" "$OUTDIR/counters_${kind}.txt" \
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
            -o "$OUTDIR/perf_${kind}.data" -- sleep "$MEASURE_SECS" >/dev/null 2>&1 || true
        wait_load
        [ -f "$OUTDIR/perf_${kind}.data" ] || continue
        [ "$PERF" = "sudo perf" ] && sudo chown "$(id -u):$(id -g)" "$OUTDIR/perf_${kind}.data"

        perf report -i "$OUTDIR/perf_${kind}.data" --stdio --no-children \
            -s dso,symbol --percent-limit 0.3 > "$OUTDIR/profile_${kind}.txt" 2>/dev/null || true

        # The same report with nothing filtered out. The 0.3% cutoff above
        # is right for a readable top-N list and wrong for a total: h1
        # spreads its work over many small parse functions, so summing
        # only what clears the cutoff accounted for 71% of the samples and
        # reported sarm at 8.4% when the honest answer was "somewhere
        # between 8.4% and 37%" — which is too wide a band to decide
        # whether optimising sarm is worth doing at all.
        perf report -i "$OUTDIR/perf_${kind}.data" --stdio --no-children \
            -s dso,symbol --percent-limit 0 > "$OUTDIR/profile_${kind}_full.txt" 2>/dev/null || true

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
        # sarm at all is the right move for this protocol. Summed over the
        # unfiltered report, so these are totals rather than the visible
        # part of totals; the truncated file is the fallback if the second
        # perf report did not run.
        totals_src="$OUTDIR/profile_${kind}_full.txt"
        [ -s "$totals_src" ] || totals_src="$OUTDIR/profile_${kind}.txt"
        awk '/^ +[0-9]/ {
                pct = $1; gsub(/%/, "", pct)
                if ($2 == "sarm") sarm += pct
                else if ($4 ~ /idle/) idle += pct
                else kern += pct
             } END {
                printf "   ── %s totals: sarm %.1f%%  kernel %.1f%%  idle %.1f%%  (%.0f%% of samples accounted)\n", \
                    K, sarm, kern, idle, sarm + kern + idle
             }' K="$kind" "$totals_src" | tee -a "$OUTDIR/summary.txt" || true

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
                -o "$OUTDIR/call_counts.txt" -- sleep "$MEASURE_SECS" \
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
