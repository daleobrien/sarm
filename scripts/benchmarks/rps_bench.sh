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
#   ./scripts/benchmarks/rps_bench.sh --json           # machine-readable summary

set -euo pipefail

cd "$(dirname "$0")/../.."

DO_BUILD=1
HOST_PORT=0
DURATION=10
CONNECTIONS=50
THREADS=4
REQ_PATH=/
JSON=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)      DO_BUILD=0 ;;
        --port)          HOST_PORT="$2"; shift ;;
        --duration)      DURATION="$2"; shift ;;
        --connections)   CONNECTIONS="$2"; shift ;;
        --threads)       THREADS="$2"; shift ;;
        --path)          REQ_PATH="$2"; shift ;;
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
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

./sarm "$HOST_PORT" >/dev/null 2>&1 &
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

# ── HTTP/1.1 via wrk ──────────────────────────────────────────────
echo "━━━ HTTP/1.1 (wrk, ${THREADS} threads, ${CONNECTIONS} conns, ${DURATION}s) ━━━" >&2
WRK_OUT=$(wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" --latency "$URL")
echo "$WRK_OUT" >&2
H1_RPS=$(echo "$WRK_OUT" | awk '/^Requests\/sec:/ {print $2}')
H1_LAT_AVG=$(echo "$WRK_OUT" | awk '/Latency/ {print $2; exit}')

# req/s extraction: h2load's "finished in ..., N req/s, ..." summary
# line, tokenized on runs of comma/space so the number just before the
# "req/s" token is picked out.
extract_h2_rps() {
    awk -F'[, ]+' '/^finished in/ {for(i=1;i<=NF;i++) if ($i ~ /req\/s/) {print $(i-1); exit}}'
}

# ── HTTP/2 (h2c, prior knowledge) via h2load ─────────────────────
echo "━━━ HTTP/2 (h2load, h2c prior-knowledge, ${THREADS} threads, ${CONNECTIONS} conns, ${DURATION}s) ━━━" >&2
H2LOAD_OUT=$(h2load \
    --no-tls-proto=h2c \
    -t"$THREADS" \
    -c"$CONNECTIONS" \
    -m10 \
    -D"$DURATION" \
    "$URL")
echo "$H2LOAD_OUT" >&2
H2_RPS=$(echo "$H2LOAD_OUT" | extract_h2_rps)

# ── HTTP/2 over TLS (TLS 1.3, ALPN h2) via h2load ────────────────
echo "━━━ HTTP/2 + TLS (h2load, TLS 1.3, ${THREADS} threads, ${CONNECTIONS} conns, ${DURATION}s) ━━━" >&2
H2LOAD_TLS_OUT=$(h2load \
    -t"$THREADS" \
    -c"$CONNECTIONS" \
    -m10 \
    -D"$DURATION" \
    "$TLS_URL")
echo "$H2LOAD_TLS_OUT" >&2
H2_TLS_RPS=$(echo "$H2LOAD_TLS_OUT" | extract_h2_rps)

if [ "$JSON" -eq 1 ]; then
    printf '{"http1_rps": %s, "http2_h2c_rps": %s, "http2_tls_rps": %s, "duration_s": %s, "connections": %s, "threads": %s, "path": "%s"}\n' \
        "${H1_RPS:-null}" "${H2_RPS:-null}" "${H2_TLS_RPS:-null}" "$DURATION" "$CONNECTIONS" "$THREADS" "$REQ_PATH"
else
    echo ""
    echo "━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "HTTP/1.1      : ${H1_RPS:-?} req/s (avg latency ${H1_LAT_AVG:-?})"
    echo "HTTP/2 (h2c)  : ${H2_RPS:-?} req/s"
    echo "HTTP/2 + TLS  : ${H2_TLS_RPS:-?} req/s"
fi
