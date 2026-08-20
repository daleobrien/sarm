#!/usr/bin/env bash
# sarm multicore stress harness (Plan.md Phase 4, Steps 17-18)
#
# Everything here needs several connections in flight at once across
# several worker processes, which is what neither tests/unit/ (one
# function at a time) nor the other tests/*.sh (one request at a time)
# can see:
#
#   Step 17 — concurrent clients over HTTP/1.1 (single, keep-alive,
#     pipelined, split-write), h2c and HTTP/2-over-TLS, every response
#     compared byte-for-byte with a reference taken up front. Repeated
#     for --iterations rounds; any difference is truncation or
#     cross-connection leakage.
#   Step 18 — a randomised mixture of the same protocols plus HEAD,
#     range requests and missing files, run for --stress-seconds with
#     slow clients and long-lived HTTP/2 connections alongside the short
#     ones, while a probe thread times a fresh connection twice a second
#     to prove a busy worker does not block accepts.
#
# Then the server is shut down with SIGTERM and checked for orphans, so
# a run also exercises Phase 3's Step 16 path under real load.
#
# Usage:
#   ./test_multicore.sh                        # build + test, 4 workers
#   ./test_multicore.sh --no-build             # reuse the existing binary
#   ./test_multicore.sh --workers 2            # a specific worker count
#   ./test_multicore.sh --iterations 50        # the Step 17 soak
#   ./test_multicore.sh --stress-seconds 60    # the Step 18 soak
#   ./test_multicore.sh --stress-seconds 0     # correctness rounds only

set -uo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
CLR='\033[0m'

PASS=0
FAIL=0
QUIET=0
LOG=""

_log() { printf -v _tmp "%s\n" "$*"; LOG+="$_tmp"; }

ok()   { local _s; printf -v _s "  ${GRN}✓${CLR} %s" "$*"; PASS=$((PASS + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
nope() { local _s; printf -v _s "  ${RED}✗${CLR} %s" "$*"; FAIL=$((FAIL + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }

DO_BUILD=1
HOST_PORT=0
WORKERS=4
ITERATIONS=3
STRESS_SECONDS=10
CONCURRENCY=8

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)       DO_BUILD=0 ;;
        --port)           HOST_PORT="$2"; shift ;;
        --workers)        WORKERS="$2"; shift ;;
        --iterations)     ITERATIONS="$2"; shift ;;
        --stress-seconds) STRESS_SECONDS="$2"; shift ;;
        --concurrency)    CONCURRENCY="$2"; shift ;;
        --quiet)          QUIET=1 ;;
        -h|--help)        sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8500 + ($$ % 200) ))
fi

for cmd in python3 curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

CHECKS="$(dirname "$0")/multicore_checks.py"

SERVER_PID=""
server_pids() { pgrep -f "sarm $HOST_PORT" 2>/dev/null || true; }

cleanup() {
    local pids
    pids=$(server_pids)
    if [ -n "$pids" ]; then
        # shellcheck disable=SC2086
        kill -TERM $pids 2>/dev/null || true
        sleep 0.4
        pids=$(server_pids)
        # shellcheck disable=SC2086
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    fi
    if [ -n "$SERVER_PID" ]; then
        { wait "$SERVER_PID"; } 2>/dev/null
        SERVER_PID=""
    fi
    return 0
}
trap cleanup EXIT INT TERM

if [ "$DO_BUILD" -eq 1 ]; then
    if [ $QUIET -eq 1 ]; then
        make >/dev/null 2>&1
    else
        echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        make
        echo ""
    fi
fi

if [ ! -x "./sarm" ]; then
    echo "$0: './sarm' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

# ── start ────────────────────────────────────────────────────────
./sarm "$HOST_PORT" --workers "$WORKERS" >/dev/null 2>&1 &
SERVER_PID=$!
ready=0
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
    if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${HOST_PORT}/" 2>/dev/null; then
        ready=1; break
    fi
    sleep 0.25
done
if [ "$ready" -ne 1 ]; then
    nope "server did not start with --workers $WORKERS"
    exit 1
fi

started_procs=$(server_pids | grep -c .)
if [ "$started_procs" -eq "$WORKERS" ]; then
    ok "$WORKERS workers accepting on one port"
else
    nope "expected $WORKERS worker processes, saw $started_procs"
fi

run_checks() {
    local out
    out=$(python3 "$CHECKS" "$@" 2>&1)
    while IFS= read -r line; do
        case "$line" in
            OK:*)   ok "${line#OK: }" ;;
            FAIL:*) nope "${line#FAIL: }" ;;
            *)      if [ -n "$line" ]; then if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi; fi ;;
        esac
    done <<< "$out"
}

# ── Step 17 — concurrent multi-protocol correctness ──────────────
# One verify call per iteration rather than one call with many rounds:
# an intermittent failure is what this is looking for, so each iteration
# builds its references and its connections from scratch.
iter_failed=0
for i in $(seq 1 "$ITERATIONS"); do
    before=$FAIL
    if [ "$ITERATIONS" -le 5 ] || [ $QUIET -eq 1 ]; then
        run_checks verify "$HOST_PORT" "$CONCURRENCY" 1
    else
        # a long soak reports once at the end instead of 50 identical lines
        out=$(python3 "$CHECKS" verify "$HOST_PORT" "$CONCURRENCY" 1 2>&1)
        case "$out" in
            OK:*) : ;;
            *)    printf '%s\n' "$out" | while IFS= read -r l; do echo "  iteration $i: $l"; done
                  iter_failed=$((iter_failed + 1)) ;;
        esac
    fi
    [ "$FAIL" -gt "$before" ] && iter_failed=$((iter_failed + 1))
done

if [ "$ITERATIONS" -gt 5 ] && [ $QUIET -eq 0 ]; then
    if [ "$iter_failed" -eq 0 ]; then
        ok "$ITERATIONS iterations of the concurrent multi-protocol check, no intermittent failure"
    else
        nope "$iter_failed of $ITERATIONS iterations failed"
    fi
fi

# ── Step 18 — randomised mixed workload ──────────────────────────
if [ "$STRESS_SECONDS" -gt 0 ]; then
    run_checks stress "$HOST_PORT" "$CONCURRENCY" "$STRESS_SECONDS"
fi

# ── the server must still be healthy, and shut down cleanly ──────
if [ "$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/")" = "200" ]; then
    ok "server still serving after the load"
else
    nope "server stopped serving after the load"
fi

zombies=$(ps -eo ppid=,stat= | awk -v p="$(server_pids | tr '\n' ' ')" '
    BEGIN { split(p, a, " "); for (i in a) w[a[i]] = 1 }
    $2 ~ /^Z/ && ($1 in w) { n++ } END { print n + 0 }')
if [ "$zombies" -eq 0 ]; then
    ok "no unreaped children left by any worker"
else
    nope "$zombies zombie children left behind by the workers"
fi

parent=$(server_pids | head -1)
kill -TERM "$parent" 2>/dev/null
left=1
deadline=$((SECONDS + 5))
while [ $SECONDS -lt $deadline ]; do
    if [ "$(server_pids | grep -c .)" -eq 0 ]; then left=0; break; fi
    sleep 0.25
done
if [ "$left" -eq 0 ]; then
    ok "SIGTERM after the load shut every worker down"
else
    nope "SIGTERM after the load left $(server_pids | grep -c .) worker(s) behind"
fi
cleanup

# ── summary ──────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        printf '%s\n' "$LOG"
        echo ""
        printf "  Passed:  ${GRN}%d${CLR}\n  Failed:  ${RED}%d${CLR}\n" "$PASS" "$FAIL"
        printf "\n${RED}Some tests failed!${CLR}\n"
        exit 1
    fi
    printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "multicore (${WORKERS} workers)" "$PASS"
    exit 0
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
echo "═══════════════════════════════════════════════════════════════"
if [ "$FAIL" -gt 0 ]; then
    printf "\n${RED}Some tests failed!${CLR}\n"
    exit 1
fi
printf "\n${GRN}All multicore tests passed.${CLR}\n"
exit 0
