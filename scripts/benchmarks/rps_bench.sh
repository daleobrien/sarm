#!/usr/bin/env bash
# Requests-per-second benchmark for sarm, over HTTP/1.1, plaintext
# HTTP/2 (h2c), and HTTP/2 over TLS.
#
# sarm auto-detects the protocol per connection (src/sarm/main.S peeks
# the first byte: 0x16 -> TLS handshake, "PRI * HTTP/2.0" preface ->
# h2c prior knowledge, else HTTP/1.1 — see tests/test_protocols.sh and
# src/tls/server/README.md), so all three benchmarks hit the same
# server instance on the same port:
#   - HTTP/1.1:      `wrk`, standard keep-alive requests.
#   - HTTP/2 (h2c):  `h2load --no-tls-proto=h2c` — RFC 9113 §3.4 prior
#     knowledge, no TLS.
#   - HTTP/2 + TLS:  `h2load` against `https://`, TLS 1.3 with ALPN
#     h2 (the server's cert is the self-signed `certs/cert.pem`, CN
#     localhost — h2load doesn't verify server certs, so no -k/--insecure
#     equivalent is needed).
#
# Usage:
#   ./scripts/benchmarks/rps_bench.sh                  # build + benchmark
#   ./scripts/benchmarks/rps_bench.sh --no-build        # reuse existing binary
#   ./scripts/benchmarks/rps_bench.sh --port 8090
#   ./scripts/benchmarks/rps_bench.sh --duration 15 --connections 100 --threads 4
#   ./scripts/benchmarks/rps_bench.sh --path /pretty/index.html
#   ./scripts/benchmarks/rps_bench.sh --workers 4   # pre-forked accept workers
#   ./scripts/benchmarks/rps_bench.sh --server-cpus 8-9 --load-cpus 10-63
#   ./scripts/benchmarks/rps_bench.sh --repeat 5    # median of 5, with the spread
#   ./scripts/benchmarks/rps_bench.sh --max-streams 64  # h2 concurrency per conn
#   ./scripts/benchmarks/rps_bench.sh --warm-up 3   # discard the first 3s
#   ./scripts/benchmarks/rps_bench.sh --pipeline 8  # 8 h1 requests per send
#   ./scripts/benchmarks/rps_bench.sh --json           # machine-readable summary
#   ./scripts/benchmarks/rps_bench.sh --target 10.0.1.7:8080   # a server on
#                                                      # another machine
#   ./scripts/benchmarks/rps_bench.sh --target host:8080 --only h2tls
#
# CONNECTION COUNT IS PART OF THE RESULT. sarm serves one connection per
# process, so once --connections exceeds the machine's logical CPUs the
# number measures oversubscription, not the server: on a 12-core box h2c
# falls from ~282k req/s at -c4 to ~93k at -c50, monotonically, with no
# code change involved. Worse, past the core count the result goes
# bimodal (P-core vs E-core placement), so a single run at -c50 can read
# either ~170k or ~290k for the same binary. Compare builds at a
# connection count the machine can actually run, and use --repeat.
#
# SO IS THE CONCURRENCY CEILING, and it is the easier one to misread.
# This is a closed-loop benchmark: the client never has more than
# (connections x max-streams) requests outstanding -- 16 x 10 = 160 for
# the perf suite's old defaults, and just `connections` for wrk, which
# does not multiplex. By Little's Law throughput is then
# concurrency / latency, so if the ceiling is the binding constraint the
# req/s number is a restatement of latency and says nothing about how
# much load the server could actually absorb. The perf-results/ run of
# 2026-08-25 was pinned against that ceiling on all three protocols
# (h1 15.8/16, h2c 128/160, h2tls 115/160) while sarm's own cores sat
# 85% idle, which is why its h2tls figure swung 607k-799k between two
# passes of the same binary: it was measuring h2load's scheduling.
#
# The summary therefore reports mean latency and in-flight concurrency
# next to every req/s figure. Read the saturation percentage first: at
# or near 100% the run is concurrency-bound and the req/s number is not
# a throughput measurement. Raise --max-streams (not --connections,
# which oversubscribes the one-process-per-connection server) until
# saturation drops well below 100%, or until req/s stops rising -- that
# plateau is the real server ceiling.
#
# The h2 defaults below are set to start off that ceiling rather than on
# it, but --connections is the flag you lower on a small box and it
# lowers the ceiling with it, so re-read the saturation column after any
# -c change. The h1 default is deliberately NOT set that way: --pipeline
# stays at 1, because a pipelined client is not what a browser does, and
# an h1 row that is honestly ceiling-bound at `connections` in flight is
# more useful than one that is fast for a reason no real client enjoys.
# Raise --pipeline when you want HTTP/1.1's plateau specifically; on the
# 12-core box it is ~316k req/s, flat from depth 20 to 80 while latency
# climbs linearly, against 2.61M h2c and 2.40M h2tls at -c6 -m32.
#
# --target CHANGES WHAT IS BEING MEASURED, and for the better. Without it
# this script starts its own sarm and drives it over loopback, so the
# client's cost lands on the same cores as the server's: h2load pays for
# TLS, HPACK and frame handling roughly 4x what sarm pays per request, so
# on one box the two compete for the machine and the figure is a floor
# rather than a ceiling. With --target the server is somewhere else
# entirely -- nothing is built, nothing is started, and every core here
# belongs to the client. That is what scripts/aws/rps_two_box_ec2.sh
# rents: a small sarm box and a large load box, so the server is the only
# side that can run out.
#
# --target also makes one of the pinning flags meaningless. --load-cpus
# still applies, since it pins the generators on THIS box; --server-cpus
# does not, because the server is not this script's to start, and passing
# it is an error rather than a silent no-op.

set -euo pipefail

cd "$(dirname "$0")/../.."

DO_BUILD=1
HOST_PORT=0
# Empty: start a local sarm and drive it over loopback. Set to HOST[:PORT]:
# drive a server already running somewhere else and start nothing here.
TARGET=""
# Which protocols to run, as a comma list of h1,h2c,h2tls. Empty is all
# three. A two-box run measures each one over its own window -- so that
# the server-side CPU sample beside it describes one protocol and not an
# average of three -- and so asks for them one at a time.
ONLY=""
DURATION=10
CONNECTIONS=50
THREADS=4
REQ_PATH=/
WORKERS=1
# CPU pinning for the server this script starts, and for the load
# generators it runs against it. Empty means "no taskset", which is the
# standalone default: on a laptop there is nothing sensible to pin to.
# run_perf_suite.sh passes both, because an UNPINNED server here while
# its own phases pin theirs makes section 2 and section 4 describe two
# different machines -- the 2026-08-26 run reported 9.5M req/s h2c in
# section 2 while section 4 measured the same binary at 909k, a 10x gap
# that was entirely 64 cores versus 2.
SERVER_CPUS=""
LOAD_CPUS=""
REPEAT=1
JSON=0
# h2load streams per connection, so the h2 ceiling is
# connections x max-streams. 32 rather than 10 because the connection
# advice above steers a 12-core box to -c6, and -c6 -m10 pins both h2
# legs at ~85% of their ceiling -- exactly the regime the block above
# says not to quote. Swept on that box at -c6, median of 3: -m10 gave
# 1.19M req/s, -m20 2.05M, -m32 2.6965M, -m40 2.69M, -m80 2.70M.
#
# 32 and not more because that is MAX_CONCURRENT_STREAMS in src/defs.S,
# which sarm advertises in its SETTINGS frame and h2load obeys: -m40 and
# -m80 open the same 32 streams per connection that -m32 does, which is
# why all three read ~148 in flight and ~2.69M. Above 32 this script's
# ceiling arithmetic (connections x max-streams) is the only thing that
# changes, and it changes in the misleading direction -- -m80 reported
# 30.9% saturation against a ceiling of 480 the server would never have
# granted. Keep this at or below the advertised limit so the saturation
# column stays honest, and raise BOTH together if you raise it.
MAX_STREAMS=32
WARMUP=0
# HTTP/1.1 requests written per send. 1 is an ordinary keep-alive client
# and the default; above 1 the connection holds that many requests
# outstanding, which is the only way an HTTP/1.1 client lets sarm serve
# more than one request per wakeup. See scripts/benchmarks/pipeline.lua.
PIPELINE=1

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)      DO_BUILD=0 ;;
        --port)          HOST_PORT="$2"; shift ;;
        --target)        TARGET="$2"; shift ;;
        --only)          ONLY="$2"; shift ;;
        --duration)      DURATION="$2"; shift ;;
        --connections)   CONNECTIONS="$2"; shift ;;
        --threads)       THREADS="$2"; shift ;;
        --max-streams)   MAX_STREAMS="$2"; shift ;;
        --warm-up)       WARMUP="$2"; shift ;;
        --path)          REQ_PATH="$2"; shift ;;
        --workers)       WORKERS="$2"; shift ;;
        --server-cpus)   SERVER_CPUS="$2"; shift ;;
        --load-cpus)     LOAD_CPUS="$2"; shift ;;
        --repeat)        REPEAT="$2"; shift ;;
        --pipeline)      PIPELINE="$2"; shift ;;
        --json)          JSON=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

# ── HTTP/1.1 pipelining ───────────────────────────────────────────────
# Off by default, so every existing invocation and every stored result
# keeps meaning what it meant. When on, wrk drives the connection through
# a script rather than its built-in request path.
case "$PIPELINE" in
    ''|*[!0-9]*) echo "$0: --pipeline wants a positive integer, got '$PIPELINE'" >&2; exit 2 ;;
esac
[ "$PIPELINE" -ge 1 ] || { echo "$0: --pipeline must be at least 1" >&2; exit 2; }

WRK_SCRIPT=()
WRK_SCRIPT_ARGS=()
PIPE_NOTE=""
if [ "$PIPELINE" -gt 1 ]; then
    # Repo-relative, not $0-relative: the script has already cd'd to the
    # repo root, so a relative $0 no longer points where it did.
    PIPE_LUA="scripts/benchmarks/pipeline.lua"
    [ -f "$PIPE_LUA" ] || { echo "$0: $PIPE_LUA is missing" >&2; exit 2; }
    WRK_SCRIPT=(-s "$PIPE_LUA")
    # wrk passes everything after a bare -- to the script's init().
    WRK_SCRIPT_ARGS=(-- "$PIPELINE")
    PIPE_NOTE=", pipeline ${PIPELINE}"
fi

# ── which protocols to run ────────────────────────────────────────────
# Default is all three against the one server instance, which is the
# point: sarm detects the protocol per connection, so this is the same
# binary answering three different clients.
RUN_H1=1; RUN_H2C=1; RUN_H2TLS=1
if [ -n "$ONLY" ]; then
    RUN_H1=0; RUN_H2C=0; RUN_H2TLS=0
    for proto in $(printf '%s' "$ONLY" | tr ',' ' '); do
        case "$proto" in
            h1|http1)        RUN_H1=1 ;;
            h2c|http2|h2)    RUN_H2C=1 ;;
            h2tls|tls|https) RUN_H2TLS=1 ;;
            *) echo "$0: --only wants h1, h2c and/or h2tls, got '$proto'" >&2; exit 2 ;;
        esac
    done
    [ $((RUN_H1 + RUN_H2C + RUN_H2TLS)) -gt 0 ] || { echo "$0: --only selected nothing" >&2; exit 2; }
fi

# ── where the server is ───────────────────────────────────────────────
# With --target it is somewhere else and already running; without one this
# script starts it here. The difference decides whether `make` and the
# ./sarm binary are needed at all, which is what lets a load-generator box
# carry no compiler and no sources but this script.
REMOTE_TARGET=0
if [ -n "$TARGET" ]; then
    REMOTE_TARGET=1
    DO_BUILD=0
    if [ -n "$SERVER_CPUS" ]; then
        echo "$0: --server-cpus cannot apply with --target — the server is not this" >&2
        echo "    script's to start. Pin it on the box it runs on." >&2
        exit 2
    fi
    case "$TARGET" in
        *:*) TARGET_HOST="${TARGET%:*}"; TARGET_PORT="${TARGET##*:}" ;;
        *)   TARGET_HOST="$TARGET"; TARGET_PORT="$HOST_PORT" ;;
    esac
    [ -n "$TARGET_HOST" ] || { echo "$0: --target needs a host" >&2; exit 2; }
    case "$TARGET_PORT" in
        ''|0|*[!0-9]*) echo "$0: --target needs a port, as host:port or via --port" >&2; exit 2 ;;
    esac
    HOST_PORT="$TARGET_PORT"
fi

# `make` is only needed for the build this script does when it owns the
# server, and wrk/h2load only for the protocols actually being run. A box
# provisioned purely to drive HTTP/2 has no reason to carry wrk.
NEEDED=(curl)
[ "$RUN_H1" = 1 ] && NEEDED+=(wrk)
{ [ "$RUN_H2C" = 1 ] || [ "$RUN_H2TLS" = 1 ]; } && NEEDED+=(h2load)
[ "$DO_BUILD" -eq 1 ] && NEEDED+=(make)
for cmd in "${NEEDED[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for this benchmark" >&2
        exit 2
    fi
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8080 + ($$ % 200) ))
fi

# taskset is Linux-only and absent on macOS, where this script also runs.
# A requested pinning that cannot be honoured is an error rather than a
# warning: silently measuring the whole box under a flag that says
# otherwise is the failure this exists to prevent.
# Expanded below as ${ARR[@]+"${ARR[@]}"}, not "${ARR[@]}": macOS ships
# bash 3.2, where an empty array under `set -u` is an unbound variable
# rather than zero words. This script runs there.
SERVER_PIN=()
LOAD_PIN=()
if [ -n "$SERVER_CPUS" ] || [ -n "$LOAD_CPUS" ]; then
    if ! command -v taskset >/dev/null 2>&1; then
        echo "$0: --server-cpus/--load-cpus need taskset, which this host lacks" >&2
        exit 2
    fi
    [ -n "$SERVER_CPUS" ] && SERVER_PIN=(taskset -c "$SERVER_CPUS")
    [ -n "$LOAD_CPUS" ]   && LOAD_PIN=(taskset -c "$LOAD_CPUS")
fi

# logical CPUs. Used for the oversubscription warning, which is about the
# SERVER's core count -- so it is only meaningful when the server is this
# machine. With --target the server's core count is not ours to read and
# the warning is suppressed rather than made up.
CPUS=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 0)
SERVER_HOST="127.0.0.1"
[ "$REMOTE_TARGET" -eq 1 ] && SERVER_HOST="$TARGET_HOST"
BASE="http://${SERVER_HOST}:${HOST_PORT}"
TLS_BASE="https://${SERVER_HOST}:${HOST_PORT}"
URL="${BASE}${REQ_PATH}"
TLS_URL="${TLS_BASE}${REQ_PATH}"

if [ "$DO_BUILD" -eq 1 ]; then
    echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    make production >&2
fi

if [ "$REMOTE_TARGET" -eq 0 ] && [ ! -x "./sarm" ]; then
    echo "$0: './sarm' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

SERVER_PID=""
cleanup() {
    set +e
    # Nothing was started here under --target, and killing something on
    # the strength of a pgrep pattern would be reaching onto a machine
    # whose processes are not ours.
    [ "$REMOTE_TARGET" -eq 1 ] && return 0
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    local leftover
    leftover=$(pgrep -f "sarm $HOST_PORT" 2>/dev/null)
    if [ -n "$leftover" ]; then
        sleep 0.5
        leftover=$(pgrep -f "sarm $HOST_PORT" 2>/dev/null)
        # shellcheck disable=SC2086
        [ -n "$leftover" ] && kill -9 $leftover 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

if [ "$REMOTE_TARGET" -eq 1 ]; then
    # Somebody else's server: prove it answers before spending a load
    # window on it, and give it longer than a local start would need,
    # because a remote box may still be finishing its own boot.
    echo -n "waiting for ${SERVER_HOST}:${HOST_PORT} …" >&2
    ready=0
    deadline=$((SECONDS + 60))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "${BASE}/" 2>/dev/null; then
            ready=1
            echo " ready" >&2
            break
        fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
        echo " UNREACHABLE" >&2
        echo "$0: nothing answered HTTP on ${BASE}/ within 60s." >&2
        echo "    Check that sarm is running there, that it is bound to an" >&2
        echo "    address other than 127.0.0.1, and that the security group" >&2
        echo "    lets this machine reach that port." >&2
        exit 1
    fi
else
    # --workers 1 is the pre-Phase-3 single accepting process; the flag is
    # passed either way so the two cases differ only in the count.
    # --workers auto reads the affinity mask, so SERVER_PIN also decides
    # how many workers 'auto' would spawn.
    ${SERVER_PIN[@]+"${SERVER_PIN[@]}"} ./sarm "$HOST_PORT" --workers "$WORKERS" >/dev/null 2>&1 3>&- 4>&- &
    SERVER_PID=$!

    echo -n "waiting for server (pid ${SERVER_PID}) on port ${HOST_PORT} …" >&2
    ready=0
    deadline=$((SECONDS + 10))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "${BASE}/" 2>/dev/null; then
            ready=1
            echo " ready" >&2
            break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo " DIED" >&2
            exit 1
        fi
        sleep 0.1
    done
    if [ "$ready" -ne 1 ]; then
        echo " TIMED OUT" >&2
        exit 1
    fi
fi

# req/s extraction: h2load's "finished in ..., N req/s, ..." summary
# line, tokenized on runs of comma/space so the number just before the
# "req/s" token is picked out.
extract_h2_rps() {
    awk -F'[, ]+' '/^finished in/ {for(i=1;i<=NF;i++) if ($i ~ /req\/s/) {print $(i-1); exit}}'
}

# Mean request latency in microseconds. h2load's latency table has had
# two shapes in the wild and the suite meets both -- nghttp2 on the EC2
# runner prints
#      min         max         mean         sd        +/- sd
#   time for request:   42us   607us   189us   34us   64.18%
# while newer builds (homebrew) print
#      min    max    median   p95    p99    mean    sd    +/- sd
#   request     :   42us  1.34ms  494us  693us  796us  495us  119us  69.81%
# so "mean" is field 6 in one and field 8 in the other. Rather than
# matching a label, locate "mean" in the header and index the data row
# from the right: the header's trailing "+/- sd" is two tokens but one
# column, so there are (header tokens - 1) value columns.
#
# Units are per value (us/ms/s) and converted, never assumed -- a run
# slow enough to report "1.23ms" would otherwise read as 1.23us and make
# the server look a thousand times faster than it is.
to_us() {
    awk -v v="$1" 'BEGIN {
        if (v ~ /ms$/)      { sub(/ms$/, "", v); print v * 1000 }
        else if (v ~ /us$/) { sub(/us$/, "", v); print v + 0 }
        else if (v ~ /s$/)  { sub(/s$/,  "", v); print v * 1000000 }
        else                { print v + 0 }
    }'
}
extract_h2_latency_us() {
    local raw
    raw=$(awk '
        /(^| )min +max +/ && /mean/ {
            cols = NF - 1
            for (i = 1; i <= NF; i++) if ($i == "mean") want = i
            next
        }
        want && /^(time for request:|request +:)/ {
            print $(NF - cols + want)
            exit
        }' || true)
    [ -n "$raw" ] || return 0
    to_us "$raw"
}

# wrk prints "Latency  22.48us  14.36us  680.00us  94.70%" (avg sd max).
extract_h1_latency_us() {
    local raw
    raw=$(awk '/^ *Latency/ {print $2; exit}' || true)
    [ -n "$raw" ] || return 0
    to_us "$raw"
}

# Little's Law: in-flight = rps * latency. Reported against the ceiling
# the client's own flags impose, because that ratio is what says whether
# the number above it is a throughput measurement or a latency one.
# Prints NOTHING when it has nothing to say, rather than "? ?": these two
# values go straight into the --json line, where a literal ? is not JSON,
# and into the text summary, where ${x:-?} restores the question mark. A
# protocol that --only skipped has no samples at all and takes this path.
saturation() {  # saturation <rps> <latency_us> <ceiling>
    awk -v r="$1" -v l="$2" -v c="$3" 'BEGIN {
        if (r == "" || l == "" || c + 0 == 0) { exit }
        inflight = r * l / 1000000.0
        printf "%.1f %.1f", inflight, inflight / c * 100.0
    }'
}

# median and full spread of the values on stdin, as "median spread%"
median_spread() {
    sort -n | awk '{v[NR]=$1} END {
        if (NR == 0) { exit }
        m = (NR % 2) ? v[(NR+1)/2] : (v[NR/2] + v[NR/2+1]) / 2
        printf "%.2f %.1f", m, (m > 0 ? (v[NR] - v[1]) / m * 100 : 0)
    }'
}

H1_SAMPLES=""; H2_SAMPLES=""; H2TLS_SAMPLES=""; H1_LAT_AVG=""
H1_LAT_SAMPLES=""; H2_LAT_SAMPLES=""; H2TLS_LAT_SAMPLES=""

# h2load only accepts --warm-up-time when it is non-zero; passing 0 is
# harmless but noisy in the echoed command line, so build the flag list.
H2LOAD_COMMON=(-t"$THREADS" -c"$CONNECTIONS" -m"$MAX_STREAMS" -D"$DURATION")
[ "$WARMUP" -gt 0 ] && H2LOAD_COMMON+=(--warm-up-time="$WARMUP")

for pass in $(seq 1 "$REPEAT"); do
    if [ "$REPEAT" -gt 1 ]; then
        echo "━━━ PASS ${pass}/${REPEAT} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    fi

    # ── HTTP/1.1 via wrk ──────────────────────────────────────────────
    # wrk has no warm-up flag; it is given the extra seconds instead and
    # its own steady-state averaging absorbs them.
    if [ "$RUN_H1" = 1 ]; then
    echo "━━━ HTTP/1.1 (wrk, ${THREADS} threads, ${CONNECTIONS} conns, $((DURATION + WARMUP))s${PIPE_NOTE}) ━━━" >&2
    WRK_OUT=$(${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNECTIONS" -d"$((DURATION + WARMUP))s" \
        --latency ${WRK_SCRIPT[@]+"${WRK_SCRIPT[@]}"} "$URL" ${WRK_SCRIPT_ARGS[@]+"${WRK_SCRIPT_ARGS[@]}"})
    echo "$WRK_OUT" >&2
    H1_SAMPLES="$H1_SAMPLES$(echo "$WRK_OUT" | awk '/^Requests\/sec:/ {print $2}')
"
    H1_LAT_SAMPLES="$H1_LAT_SAMPLES$(echo "$WRK_OUT" | extract_h1_latency_us)
"
    H1_LAT_AVG=$(echo "$WRK_OUT" | awk '/Latency/ {print $2; exit}')
    fi

    # ── HTTP/2 (h2c, prior knowledge) via h2load ─────────────────────
    if [ "$RUN_H2C" = 1 ]; then
    echo "━━━ HTTP/2 (h2load, h2c prior-knowledge, ${THREADS} threads, ${CONNECTIONS} conns, -m${MAX_STREAMS}, ${DURATION}s) ━━━" >&2
    H2LOAD_OUT=$(${LOAD_PIN[@]+"${LOAD_PIN[@]}"} h2load --no-tls-proto=h2c "${H2LOAD_COMMON[@]}" "$URL")
    echo "$H2LOAD_OUT" >&2
    H2_SAMPLES="$H2_SAMPLES$(echo "$H2LOAD_OUT" | extract_h2_rps)
"
    H2_LAT_SAMPLES="$H2_LAT_SAMPLES$(echo "$H2LOAD_OUT" | extract_h2_latency_us)
"
    fi

    # ── HTTP/2 over TLS (TLS 1.3, ALPN h2) via h2load ────────────────
    if [ "$RUN_H2TLS" = 1 ]; then
    echo "━━━ HTTP/2 + TLS (h2load, TLS 1.3, ${THREADS} threads, ${CONNECTIONS} conns, -m${MAX_STREAMS}, ${DURATION}s) ━━━" >&2
    H2LOAD_TLS_OUT=$(${LOAD_PIN[@]+"${LOAD_PIN[@]}"} h2load "${H2LOAD_COMMON[@]}" "$TLS_URL")
    echo "$H2LOAD_TLS_OUT" >&2
    H2TLS_SAMPLES="$H2TLS_SAMPLES$(echo "$H2LOAD_TLS_OUT" | extract_h2_rps)
"
    H2TLS_LAT_SAMPLES="$H2TLS_LAT_SAMPLES$(echo "$H2LOAD_TLS_OUT" | extract_h2_latency_us)
"
    fi
done

read -r H1_RPS H1_SPREAD <<< "$(printf '%s' "$H1_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_RPS H2_SPREAD <<< "$(printf '%s' "$H2_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_TLS_RPS H2TLS_SPREAD <<< "$(printf '%s' "$H2TLS_SAMPLES" | grep -v '^$' | median_spread)"
read -r H1_LAT_US _ <<< "$(printf '%s' "$H1_LAT_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_LAT_US _ <<< "$(printf '%s' "$H2_LAT_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2TLS_LAT_US _ <<< "$(printf '%s' "$H2TLS_LAT_SAMPLES" | grep -v '^$' | median_spread)"

# wrk does not multiplex, so its ceiling is the connection count; h2load
# may have --max-streams outstanding on each connection.
H1_CEIL=$((CONNECTIONS * PIPELINE))

# The server advertises SETTINGS_MAX_CONCURRENT_STREAMS in its opening
# SETTINGS frame and h2load obeys it, so a --max-streams above that value
# buys no concurrency at all: the ceiling is connections x min(the two).
# Left unclamped this arithmetic runs the block at the top of this file
# backwards -- -c6 -m80 reported 30.9% saturation against a ceiling of
# 480 the server would never have granted, when the real ceiling was 192
# and the real saturation 77% -- i.e. it makes a pinned run look like it
# has headroom, which is the one direction this number must never lie in.
#
# Read from the source of truth rather than hardcoding a second copy of
# 32 here. Anchored on `.equ MAX_CONCURRENT_STREAMS` at the start of the
# line, because H2C_SETTINGS_MAX_CONCURRENT_STREAMS is a struct field
# OFFSET that happens to also be 32 and would match a looser pattern.
# Under --target this is the local checkout's value; correct when the
# other box runs this same tree (rps_two_box_ec2.sh deploys it), and the
# summary names the value and its source whenever it clamps.
H2_ADVERTISED=$(awk '/^[[:space:]]*\.equ[[:space:]]+MAX_CONCURRENT_STREAMS[[:space:]]*,/ {
        if (match($0, /,[[:space:]]*[0-9]+/)) {
            v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v)
            if (v != "") { print v; exit }
        } }' src/defs.S 2>/dev/null)
case "$H2_ADVERTISED" in ''|*[!0-9]*) H2_ADVERTISED="" ;; esac

# No fallback guess when that read fails (src/defs.S renamed, moved, or
# unreadable): fall back to --max-streams, which is exactly the behaviour
# this script had before the clamp, rather than substituting a constant
# that might not be this build's. The saturation note reverts with it.
H2_STREAMS_EFF=$MAX_STREAMS
H2_CLAMPED=0
if [ -n "$H2_ADVERTISED" ] && [ "$MAX_STREAMS" -gt "$H2_ADVERTISED" ]; then
    H2_STREAMS_EFF=$H2_ADVERTISED
    H2_CLAMPED=1
fi
H2_CEIL=$(( CONNECTIONS * H2_STREAMS_EFF ))
read -r H1_INFLIGHT H1_SAT       <<< "$(saturation "$H1_RPS"     "$H1_LAT_US"     "$H1_CEIL")"
read -r H2_INFLIGHT H2_SAT       <<< "$(saturation "$H2_RPS"     "$H2_LAT_US"     "$H2_CEIL")"
read -r H2TLS_INFLIGHT H2TLS_SAT <<< "$(saturation "$H2_TLS_RPS" "$H2TLS_LAT_US"  "$H2_CEIL")"

if [ "$JSON" -eq 1 ]; then
    printf '{"http1_rps": %s, "http2_h2c_rps": %s, "http2_tls_rps": %s, "http1_spread_pct": %s, "http2_h2c_spread_pct": %s, "http2_tls_spread_pct": %s, "http1_latency_avg": "%s", "http1_latency_us": %s, "http2_h2c_latency_us": %s, "http2_tls_latency_us": %s, "http1_inflight": %s, "http2_h2c_inflight": %s, "http2_tls_inflight": %s, "http1_ceiling": %s, "http2_ceiling": %s, "http1_saturation_pct": %s, "http2_h2c_saturation_pct": %s, "http2_tls_saturation_pct": %s, "duration_s": %s, "warmup_s": %s, "repeat": %s, "connections": %s, "threads": %s, "max_streams": %s, "advertised_max_streams": %s, "workers": %s, "path": "%s", "server_host": "%s", "remote_target": %s}\n' \
        "${H1_RPS:-null}" "${H2_RPS:-null}" "${H2_TLS_RPS:-null}" \
        "${H1_SPREAD:-0}" "${H2_SPREAD:-0}" "${H2TLS_SPREAD:-0}" "${H1_LAT_AVG:-?}" \
        "${H1_LAT_US:-null}" "${H2_LAT_US:-null}" "${H2TLS_LAT_US:-null}" \
        "${H1_INFLIGHT:-null}" "${H2_INFLIGHT:-null}" "${H2TLS_INFLIGHT:-null}" \
        "$H1_CEIL" "$H2_CEIL" \
        "${H1_SAT:-null}" "${H2_SAT:-null}" "${H2TLS_SAT:-null}" \
        "$DURATION" "$WARMUP" "$REPEAT" "$CONNECTIONS" "$THREADS" "$MAX_STREAMS" "${H2_ADVERTISED:-null}" "$WORKERS" "$REQ_PATH" \
        "$SERVER_HOST" "$REMOTE_TARGET"
else
    echo ""
    if [ "$REMOTE_TARGET" -eq 1 ]; then
        echo "━━━ SUMMARY (server on ${SERVER_HOST}:${HOST_PORT}) ━━━━━━━━━━━━━━━━━"
    else
        echo "━━━ SUMMARY (${WORKERS} worker(s)) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
    if [ "$REPEAT" -gt 1 ]; then
        echo "median of ${REPEAT} passes, ± full spread"
    fi
    if [ "$RUN_H1" = 1 ]; then
        printf 'HTTP/1.1%-6s: %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% — wrk is always at its ceiling)\n' \
            "$([ "$PIPELINE" -gt 1 ] && printf ' x%s' "$PIPELINE")" \
            "${H1_RPS:-?}" "${H1_SPREAD:-0}" "${H1_LAT_US:-?}" "${H1_INFLIGHT:-?}" "$H1_CEIL" "${H1_SAT:-?}"
    fi
    if [ "$RUN_H1" = 1 ] && [ "$PIPELINE" -gt 1 ]; then
        echo "                (pipelined ${PIPELINE} deep: req/s is comparable across depths, the latency figure is not —"
        echo "                 it counts the queueing behind the ${PIPELINE} requests written together)"
    fi
    if [ "$RUN_H2C" = 1 ]; then
        printf 'HTTP/2 (h2c)  : %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% of ceiling)\n' \
            "${H2_RPS:-?}" "${H2_SPREAD:-0}" "${H2_LAT_US:-?}" "${H2_INFLIGHT:-?}" "$H2_CEIL" "${H2_SAT:-?}"
    fi
    if [ "$RUN_H2TLS" = 1 ]; then
        printf 'HTTP/2 + TLS  : %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% of ceiling)\n' \
            "${H2_TLS_RPS:-?}" "${H2TLS_SPREAD:-0}" "${H2TLS_LAT_US:-?}" "${H2TLS_INFLIGHT:-?}" "$H2_CEIL" "${H2TLS_SAT:-?}"
    fi

    # The warning that matters more than the numbers above it.
    #
    # Only the h2 rows are judged. wrk does not multiplex, so HTTP/1.1
    # holds exactly --connections requests in flight at all times and its
    # saturation is ~100% by construction, carrying no information and
    # answering to no flag: --max-streams does nothing for wrk, and more
    # connections oversubscribe the one-process-per-connection server.
    # (It can read slightly over 100% because wrk derives req/s and mean
    # latency separately.) Including it would fire this note on every
    # run and train the reader to ignore it.
    #
    # Once --max-streams is at the advertised limit, "raise --max-streams"
    # is no longer the advice -- the flag is capped and raising it moves
    # nothing but the arithmetic. Say what actually applies instead.
    awk -v h2="${H2_SAT:-0}" -v tls="${H2TLS_SAT:-0}" -v m="$MAX_STREAMS" \
        -v adv="${H2_ADVERTISED:-0}" -v clamped="$H2_CLAMPED" 'BEGIN {
        worst = h2 + 0; name = "HTTP/2 (h2c)"
        if (tls + 0 > worst) { worst = tls + 0; name = "HTTP/2 + TLS" }
        if (worst >= 85) {
            printf "\nNOTE: %s is at %.1f%% of its concurrency ceiling. This is a\n", name, worst
            print  "      closed-loop benchmark, so at that saturation req/s is just"
            print  "      concurrency/latency and is NOT a measure of server capacity."
            if (adv + 0 > 0 && m + 0 >= adv + 0) {
                printf "      --max-streams is already at the advertised limit of the\n"
                printf "      server, %d (MAX_CONCURRENT_STREAMS in src/defs.S), so raising\n", adv
                print  "      it does nothing. To lift this ceiling you must raise"
                print  "      that constant and rebuild, or add connections -- and those"
                print  "      past the core count oversubscribe the server, so prefer the"
                print  "      constant, or move the load to another box with --target."
            } else {
                printf "      Raise --max-streams above %d (not --connections, which\n", m
                print  "      oversubscribes the one-process-per-connection server) until"
                print  "      saturation falls or req/s stops rising."
            }
        }
        if (clamped + 0 == 1) {
            printf "\nNOTE: --max-streams %d exceeds the advertised server limit of %d\n", m, adv
            print  "      (MAX_CONCURRENT_STREAMS in src/defs.S). h2load obeys SETTINGS, so"
            printf "      the ceiling above is computed against %d, not the flag.\n", adv
        }
    }'
    # Only when the server is this machine. Under --target the server's
    # core count belongs to another box and is not ours to read; the
    # connection count there is deliberately far above this box's cores,
    # because this box is only the client.
    if [ "$REMOTE_TARGET" -eq 0 ] && [ "$CONNECTIONS" -gt "$CPUS" ]; then
        echo ""
        echo "NOTE: -c${CONNECTIONS} exceeds this machine's ${CPUS} logical CPUs, and sarm"
        echo "      runs one process per connection. Past the core count this measures"
        echo "      oversubscription rather than the server, and the result goes bimodal."
        echo "      Compare builds at -c$((CPUS / 2)) or below, with --repeat."
    fi
fi
