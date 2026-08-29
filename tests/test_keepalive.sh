#!/usr/bin/env bash
# sarm HTTP/1 keep-alive test harness (Plan.md Phase 1, Steps 5-6)
#
# Exercises pipelining, split-write fragmentation, sequential keep-alive,
# the request budget, and concurrent connections -- the correctness
# properties that don't fit in the assembly unit tests (tests/unit/) since
# they need real sockets and real timing. The heavy lifting is a Python
# script (raw sockets are far less fragile there than in bash/nc); this
# file just builds, starts the server, runs it, and reports results in
# the same ok/nope/skip style as the other tests/*.sh scripts.
#
# Usage:
#   ./test_keepalive.sh              # build + test
#   ./test_keepalive.sh --no-build   # skip make, test existing binary
#   ./test_keepalive.sh --port 8090  # use a specific port

set -euo pipefail

# ── helpers ─────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CLR='\033[0m'

PASS=0
FAIL=0
QUIET=0

LOG=""

_log() { printf -v _tmp "%s\n" "$*"; LOG+="$_tmp"; }

ok()   { local _s; printf -v _s "  ${GRN}✓${CLR} %s" "$*"; PASS=$((PASS + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
nope() { local _s; printf -v _s "  ${RED}✗${CLR} %s" "$*"; FAIL=$((FAIL + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }

# ── args ────────────────────────────────────────────────────────
DO_BUILD=1
HOST_PORT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --port)     HOST_PORT="$2"; shift ;;
        --quiet)    QUIET=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8080 + ($$ % 200) ))
fi

# ── prerequisites ────────────────────────────────────────────────
for cmd in python3 make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

# ── cleanup trap ─────────────────────────────────────────────────
SERVER_PID=""
cleanup() {
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    # sarm pre-forks workers and forks again per connection, so killing
    # the parent can leave those behind — still holding the listening
    # socket, and still holding every descriptor they inherited from this
    # script. Under a parallel `make` that includes its jobserver pipe,
    # and make then blocks forever waiting to reclaim job tokens an
    # orphan is sitting on. Sweep the family this run owns, by its port.
    # (rps_bench.sh and test_multicore.sh have done this for a while.)
    [ -n "${HOST_PORT:-}" ] && pkill -f "sarm ${HOST_PORT}( |\$)" 2>/dev/null
    true
}
trap cleanup EXIT INT TERM

# ── build ────────────────────────────────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
    if [ $QUIET -eq 1 ]; then
        make >/dev/null 2>&1
    else
        echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        make
        echo ""
    fi
fi

if [ ! -x "./sarm" ]; then
    echo "$0: './sarm' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

# ── start ────────────────────────────────────────────────────────
if [ $QUIET -eq 0 ]; then echo "━━━ STARTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; fi
if [ $QUIET -eq 1 ]; then
    ./sarm "$HOST_PORT" >/dev/null 2>&1 3>&- 4>&- &
else
    ./sarm "$HOST_PORT" 3>&- 4>&- &
fi
SERVER_PID=$!

ready=0
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
    if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${HOST_PORT}/" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        nope "server process exited unexpectedly"
        exit 1
    fi
    sleep 0.25
done
if [ "$ready" -ne 1 ]; then
    nope "server did not start within 10 seconds"
    cleanup; exit 1
fi

# ══════════════════════════════════════════════════════════════════
#   the actual checks, in Python (raw sockets)
# ══════════════════════════════════════════════════════════════════
PY_OUT=$(python3 "$(dirname "$0")/keepalive_checks.py" "$HOST_PORT" 2>&1) || true

while IFS= read -r line; do
    case "$line" in
        OK:*)   ok "${line#OK: }" ;;
        FAIL:*) nope "${line#FAIL: }" ;;
        *)      if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi ;;
    esac
done <<< "$PY_OUT"

# ── summary ──────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        printf '%s\n' "$LOG"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
        printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "${RED}Some tests failed!${CLR}"
        exit 1
    else
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "keep-alive" "$PASS"
        exit 0
    fi
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
    echo "═══════════════════════════════════════════════════════════════"
    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "${RED}Some tests failed!${CLR}"
        exit 1
    else
        echo ""
        echo "${GRN}All keep-alive tests passed.${CLR}"
        exit 0
    fi
fi
