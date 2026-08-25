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
#   ./scripts/benchmarks/rps_bench.sh --repeat 5    # median of 5, with the spread
#   ./scripts/benchmarks/rps_bench.sh --max-streams 64  # h2 concurrency per conn
#   ./scripts/benchmarks/rps_bench.sh --warm-up 3   # discard the first 3s
#   ./scripts/benchmarks/rps_bench.sh --json           # machine-readable summary
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

set -euo pipefail

cd "$(dirname "$0")/../.."

DO_BUILD=1
HOST_PORT=0
DURATION=10
CONNECTIONS=50
THREADS=4
REQ_PATH=/
WORKERS=1
REPEAT=1
JSON=0
MAX_STREAMS=10
WARMUP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)      DO_BUILD=0 ;;
        --port)          HOST_PORT="$2"; shift ;;
        --duration)      DURATION="$2"; shift ;;
        --connections)   CONNECTIONS="$2"; shift ;;
        --threads)       THREADS="$2"; shift ;;
        --max-streams)   MAX_STREAMS="$2"; shift ;;
        --warm-up)       WARMUP="$2"; shift ;;
        --path)          REQ_PATH="$2"; shift ;;
        --workers)       WORKERS="$2"; shift ;;
        --repeat)        REPEAT="$2"; shift ;;
        --json)          JSON=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

for cmd in wrk h2load curl make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for this benchmark" >&2
        exit 2
    fi
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8080 + ($$ % 200) ))
fi

# logical CPUs, for the oversubscription warning in the summary
CPUS=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 0)
BASE="http://127.0.0.1:${HOST_PORT}"
TLS_BASE="https://127.0.0.1:${HOST_PORT}"
URL="${BASE}${REQ_PATH}"
TLS_URL="${TLS_BASE}${REQ_PATH}"

if [ "$DO_BUILD" -eq 1 ]; then
    echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    make production >&2
fi

if [ ! -x "./sarm" ]; then
    echo "$0: './sarm' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

SERVER_PID=""
cleanup() {
    set +e
    # SIGTERM the forking process; it signals its workers (Phase 3, Step
    # 16). SIGKILL only mops up a worker that somehow outlived that.
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

# --workers 1 is the pre-Phase-3 single accepting process; the flag is
# passed either way so the two cases differ only in the count.
./sarm "$HOST_PORT" --workers "$WORKERS" >/dev/null 2>&1 &
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
saturation() {  # saturation <rps> <latency_us> <ceiling>
    awk -v r="$1" -v l="$2" -v c="$3" 'BEGIN {
        if (r == "" || l == "" || c + 0 == 0) { print "? ?"; exit }
        inflight = r * l / 1000000.0
        printf "%.1f %.1f", inflight, inflight / c * 100.0
    }'
}

# median and full spread of the values on stdin, as "median spread%"
median_spread() {
    sort -n | awk '{v[NR]=$1} END {
        if (NR == 0) { print "? ?"; exit }
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
    echo "━━━ HTTP/1.1 (wrk, ${THREADS} threads, ${CONNECTIONS} conns, $((DURATION + WARMUP))s) ━━━" >&2
    WRK_OUT=$(wrk -t"$THREADS" -c"$CONNECTIONS" -d"$((DURATION + WARMUP))s" --latency "$URL")
    echo "$WRK_OUT" >&2
    H1_SAMPLES="$H1_SAMPLES$(echo "$WRK_OUT" | awk '/^Requests\/sec:/ {print $2}')
"
    H1_LAT_SAMPLES="$H1_LAT_SAMPLES$(echo "$WRK_OUT" | extract_h1_latency_us)
"
    H1_LAT_AVG=$(echo "$WRK_OUT" | awk '/Latency/ {print $2; exit}')

    # ── HTTP/2 (h2c, prior knowledge) via h2load ─────────────────────
    echo "━━━ HTTP/2 (h2load, h2c prior-knowledge, ${THREADS} threads, ${CONNECTIONS} conns, -m${MAX_STREAMS}, ${DURATION}s) ━━━" >&2
    H2LOAD_OUT=$(h2load --no-tls-proto=h2c "${H2LOAD_COMMON[@]}" "$URL")
    echo "$H2LOAD_OUT" >&2
    H2_SAMPLES="$H2_SAMPLES$(echo "$H2LOAD_OUT" | extract_h2_rps)
"
    H2_LAT_SAMPLES="$H2_LAT_SAMPLES$(echo "$H2LOAD_OUT" | extract_h2_latency_us)
"

    # ── HTTP/2 over TLS (TLS 1.3, ALPN h2) via h2load ────────────────
    echo "━━━ HTTP/2 + TLS (h2load, TLS 1.3, ${THREADS} threads, ${CONNECTIONS} conns, -m${MAX_STREAMS}, ${DURATION}s) ━━━" >&2
    H2LOAD_TLS_OUT=$(h2load "${H2LOAD_COMMON[@]}" "$TLS_URL")
    echo "$H2LOAD_TLS_OUT" >&2
    H2TLS_SAMPLES="$H2TLS_SAMPLES$(echo "$H2LOAD_TLS_OUT" | extract_h2_rps)
"
    H2TLS_LAT_SAMPLES="$H2TLS_LAT_SAMPLES$(echo "$H2LOAD_TLS_OUT" | extract_h2_latency_us)
"
done

read -r H1_RPS H1_SPREAD <<< "$(printf '%s' "$H1_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_RPS H2_SPREAD <<< "$(printf '%s' "$H2_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_TLS_RPS H2TLS_SPREAD <<< "$(printf '%s' "$H2TLS_SAMPLES" | grep -v '^$' | median_spread)"
read -r H1_LAT_US _ <<< "$(printf '%s' "$H1_LAT_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2_LAT_US _ <<< "$(printf '%s' "$H2_LAT_SAMPLES" | grep -v '^$' | median_spread)"
read -r H2TLS_LAT_US _ <<< "$(printf '%s' "$H2TLS_LAT_SAMPLES" | grep -v '^$' | median_spread)"

# wrk does not multiplex, so its ceiling is the connection count; h2load
# may have --max-streams outstanding on each connection.
H1_CEIL=$CONNECTIONS
H2_CEIL=$(( CONNECTIONS * MAX_STREAMS ))
read -r H1_INFLIGHT H1_SAT       <<< "$(saturation "$H1_RPS"     "$H1_LAT_US"     "$H1_CEIL")"
read -r H2_INFLIGHT H2_SAT       <<< "$(saturation "$H2_RPS"     "$H2_LAT_US"     "$H2_CEIL")"
read -r H2TLS_INFLIGHT H2TLS_SAT <<< "$(saturation "$H2_TLS_RPS" "$H2TLS_LAT_US"  "$H2_CEIL")"

if [ "$JSON" -eq 1 ]; then
    printf '{"http1_rps": %s, "http2_h2c_rps": %s, "http2_tls_rps": %s, "http1_spread_pct": %s, "http2_h2c_spread_pct": %s, "http2_tls_spread_pct": %s, "http1_latency_avg": "%s", "http1_latency_us": %s, "http2_h2c_latency_us": %s, "http2_tls_latency_us": %s, "http1_inflight": %s, "http2_h2c_inflight": %s, "http2_tls_inflight": %s, "http1_ceiling": %s, "http2_ceiling": %s, "http1_saturation_pct": %s, "http2_h2c_saturation_pct": %s, "http2_tls_saturation_pct": %s, "duration_s": %s, "warmup_s": %s, "repeat": %s, "connections": %s, "threads": %s, "max_streams": %s, "workers": %s, "path": "%s"}\n' \
        "${H1_RPS:-null}" "${H2_RPS:-null}" "${H2_TLS_RPS:-null}" \
        "${H1_SPREAD:-0}" "${H2_SPREAD:-0}" "${H2TLS_SPREAD:-0}" "${H1_LAT_AVG:-?}" \
        "${H1_LAT_US:-null}" "${H2_LAT_US:-null}" "${H2TLS_LAT_US:-null}" \
        "${H1_INFLIGHT:-null}" "${H2_INFLIGHT:-null}" "${H2TLS_INFLIGHT:-null}" \
        "$H1_CEIL" "$H2_CEIL" \
        "${H1_SAT:-null}" "${H2_SAT:-null}" "${H2TLS_SAT:-null}" \
        "$DURATION" "$WARMUP" "$REPEAT" "$CONNECTIONS" "$THREADS" "$MAX_STREAMS" "$WORKERS" "$REQ_PATH"
else
    echo ""
    echo "━━━ SUMMARY (${WORKERS} worker(s)) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$REPEAT" -gt 1 ]; then
        echo "median of ${REPEAT} passes, ± full spread"
    fi
    printf 'HTTP/1.1      : %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% — wrk is always at its ceiling)\n' \
        "${H1_RPS:-?}" "${H1_SPREAD:-0}" "${H1_LAT_US:-?}" "${H1_INFLIGHT:-?}" "$H1_CEIL" "${H1_SAT:-?}"
    printf 'HTTP/2 (h2c)  : %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% of ceiling)\n' \
        "${H2_RPS:-?}" "${H2_SPREAD:-0}" "${H2_LAT_US:-?}" "${H2_INFLIGHT:-?}" "$H2_CEIL" "${H2_SAT:-?}"
    printf 'HTTP/2 + TLS  : %s req/s (±%s%%)  %sus mean  %s/%s in flight (%s%% of ceiling)\n' \
        "${H2_TLS_RPS:-?}" "${H2TLS_SPREAD:-0}" "${H2TLS_LAT_US:-?}" "${H2TLS_INFLIGHT:-?}" "$H2_CEIL" "${H2TLS_SAT:-?}"

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
    awk -v h2="${H2_SAT:-0}" -v tls="${H2TLS_SAT:-0}" -v m="$MAX_STREAMS" 'BEGIN {
        worst = h2 + 0; name = "HTTP/2 (h2c)"
        if (tls + 0 > worst) { worst = tls + 0; name = "HTTP/2 + TLS" }
        if (worst >= 85) {
            printf "\nNOTE: %s is at %.1f%% of its concurrency ceiling. This is a\n", name, worst
            print  "      closed-loop benchmark, so at that saturation req/s is just"
            print  "      concurrency/latency and is NOT a measure of server capacity."
            printf "      Raise --max-streams above %d (not --connections, which\n", m
            print  "      oversubscribes the one-process-per-connection server) until"
            print  "      saturation falls or req/s stops rising."
        }
    }'
    if [ "$CONNECTIONS" -gt "$CPUS" ]; then
        echo ""
        echo "NOTE: -c${CONNECTIONS} exceeds this machine's ${CPUS} logical CPUs, and sarm"
        echo "      runs one process per connection. Past the core count this measures"
        echo "      oversubscription rather than the server, and the result goes bimodal."
        echo "      Compare builds at -c$((CPUS / 2)) or below, with --repeat."
    fi
fi
