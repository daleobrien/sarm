#!/usr/bin/env bash
# sarm pre-forked accept worker tests (Plan.md Phase 3, Steps 14-16)
#
# Covers the three things the assembly unit tests can't see, because they
# are properties of processes rather than of functions:
#
#   * --workers parsing: valid counts, the MAX_WORKERS clamp, `auto`, and
#     the arguments that must be rejected (Step 14)
#   * the workers actually exist and actually all accept (Step 15)
#   * SIGTERM/SIGINT shut every worker down, leave in-flight connections
#     alone, and free the port immediately (Step 16) — including the
#     single-worker and no_fork modes, which fork nothing but still have
#     to die on the signal so the Docker container answers Ctrl-C
#
# The socket-level halves live in tests/worker_checks.py; this file starts
# and stops servers and reports in the same ok/nope style as the other
# tests/*.sh scripts.
#
# Usage:
#   ./test_workers.sh              # build + test
#   ./test_workers.sh --no-build   # skip make, test existing binary
#   ./test_workers.sh --port 8090  # use a specific base port

set -uo pipefail

# ── helpers ─────────────────────────────────────────────────────
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

# ── args ────────────────────────────────────────────────────────
DO_BUILD=1
HOST_PORT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --port)     HOST_PORT="$2"; shift ;;
        --quiet)    QUIET=1 ;;
        -h|--help)  sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8300 + ($$ % 200) ))
fi

for cmd in python3 curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

# MAX_WORKERS, read from config.S so the clamp test can't drift from it
MAX_WORKERS=$(grep -E '^\.equ[[:space:]]+MAX_WORKERS' src/config.S | tr -d ' ' | cut -d, -f2)
: "${MAX_WORKERS:=64}"

# ── process helpers ─────────────────────────────────────────────
# Every server this script starts is given $HOST_PORT on the command line,
# so the port is what identifies its processes.
worker_pids() { pgrep -f "sarm $HOST_PORT" 2>/dev/null || true; }
worker_count() { worker_pids | grep -c . ; }

# SIGTERM first -- that is the documented way to stop a multi-worker
# server, and using it here means every teardown in this file exercises
# the Step 16 path. SIGKILL only mops up whatever ignored it.
kill_all() {
    local pids
    pids=$(worker_pids)
    if [ -n "$pids" ]; then
        # shellcheck disable=SC2086
        kill -TERM $pids 2>/dev/null || true
        sleep 0.4
        pids=$(worker_pids)
        # shellcheck disable=SC2086
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null
    fi
    # consume the job so bash does not print its own "Terminated:"/"Killed:"
    # notice in the middle of the test output
    if [ -n "${SERVER_PID:-}" ]; then
        { wait "$SERVER_PID"; } 2>/dev/null
        SERVER_PID=""
    fi
    sleep 0.2
    return 0
}

SERVER_PID=""
trap kill_all EXIT INT TERM

# start_server <args...> -> sets SERVER_PID, waits until it answers
start_server() {
    ./sarm "$HOST_PORT" "$@" >/dev/null 2>&1 3>&- 4>&- &
    SERVER_PID=$!
    local deadline=$((SECONDS + 10))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${HOST_PORT}/" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

serves_200() {
    [ "$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}/")" = "200" ]
}

# ── build ────────────────────────────────────────────────────────
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

# ══════════════════════════════════════════════════════════════════
#   Step 14 — argument parsing
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 0 ]; then echo "━━━ STEP 14: --workers parsing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; fi

# rejected arguments must exit non-zero rather than start a server
for bad in "0" "abc" "-1"; do
    if ./sarm "$HOST_PORT" --workers "$bad" >/dev/null 2>&1; then
        nope "--workers $bad should be rejected"
        kill_all
    else
        ok "--workers $bad rejected"
    fi
done

if ./sarm "$HOST_PORT" --workers >/dev/null 2>&1; then
    nope "--workers with no value should be rejected"
    kill_all
else
    ok "--workers with no value rejected"
fi

# ── -help prints the usage to stdout and exits 0, without listening ──
for flag in "-help" "--help" "-h"; do
    out=$(./sarm "$flag" 2>/dev/null)
    rc=$?
    if [ $rc -ne 0 ]; then
        nope "$flag exited $rc, expected 0"
    elif ! printf '%s' "$out" | grep -q "^Usage: sarm "; then
        nope "$flag printed no usage line"
    else
        ok "$flag prints usage and exits 0"
    fi
done

# a longer argument sharing the prefix is not the flag
if ./sarm "$HOST_PORT" -helpful >/dev/null 2>&1; then
    nope "-helpful should be rejected, not treated as -help"
else
    ok "-helpful rejected (no prefix match)"
fi

# an unflagged server is unchanged: exactly one process
if start_server; then
    n=$(worker_count)
    if [ "$n" -eq 1 ]; then ok "no --workers flag → 1 process (unchanged)"; else nope "no --workers flag → $n processes, expected 1"; fi
else
    nope "server with no --workers flag did not start"
fi
kill_all

if start_server --workers 1; then
    n=$(worker_count)
    if [ "$n" -eq 1 ]; then ok "--workers 1 → 1 process (forks nothing)"; else nope "--workers 1 → $n processes, expected 1"; fi
else
    nope "--workers 1 did not start"
fi
kill_all

if start_server --workers 4; then
    n=$(worker_count)
    if [ "$n" -eq 4 ]; then ok "--workers 4 → 4 processes"; else nope "--workers 4 → $n processes, expected 4"; fi
    if serves_200; then ok "4 workers serve a 200"; else nope "4 workers did not serve a 200"; fi
else
    nope "--workers 4 did not start"
fi
kill_all

if start_server --workers auto; then
    n=$(worker_count)
    if [ "$n" -ge 1 ] && [ "$n" -le "$MAX_WORKERS" ]; then
        ok "--workers auto → $n processes (within [1, $MAX_WORKERS])"
    else
        nope "--workers auto → $n processes, outside [1, $MAX_WORKERS]"
    fi
    if serves_200; then ok "auto workers serve a 200"; else nope "auto workers did not serve a 200"; fi

    # `auto` should agree with an independent count of the CPUs this
    # process may run on: sysctl hw.logicalcpu on macOS, nproc on Linux
    # (which reads the same sched_getaffinity mask detect_cpus does, so
    # under taskset or a cpuset both follow the restriction together).
    cpus=""
    if command -v nproc >/dev/null 2>&1; then
        cpus=$(nproc 2>/dev/null)
    elif command -v sysctl >/dev/null 2>&1; then
        cpus=$(sysctl -n hw.logicalcpu 2>/dev/null)
    fi
    if [ -n "$cpus" ] && [ "$cpus" -ge 1 ] 2>/dev/null; then
        want=$cpus
        [ "$want" -gt "$MAX_WORKERS" ] && want=$MAX_WORKERS
        if [ "$n" -eq "$want" ]; then
            ok "--workers auto → $n, matches the $cpus CPU(s) available"
        else
            nope "--workers auto → $n, expected $want for $cpus CPU(s)"
        fi
    else
        ok "--workers auto CPU-count cross-check skipped (no counter)"
    fi
else
    nope "--workers auto did not start"
fi
kill_all

if start_server --workers 9999; then
    n=$(worker_count)
    if [ "$n" -eq "$MAX_WORKERS" ]; then
        ok "--workers 9999 clamped to MAX_WORKERS ($MAX_WORKERS)"
    else
        nope "--workers 9999 → $n processes, expected the clamp at $MAX_WORKERS"
    fi
else
    nope "--workers 9999 did not start"
fi
kill_all

# the port argument must still work alongside the flag, in either order
if start_server --workers 2 && serves_200; then
    ok "port positional and --workers coexist"
else
    nope "port positional and --workers did not coexist"
fi
kill_all

# ══════════════════════════════════════════════════════════════════
#   Step 15 — every worker accepts
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 0 ]; then echo "━━━ STEP 15: shared listening socket ━━━━━━━━━━━━━━━━━━━━━━━━"; fi

if start_server --workers 3; then
    PY_OUT=$(python3 "$(dirname "$0")/worker_checks.py" spread "$HOST_PORT" 3 45 2>&1)
    while IFS= read -r line; do
        case "$line" in
            OK:*)   ok "${line#OK: }" ;;
            FAIL:*) nope "${line#FAIL: }" ;;
            *)      if [ -n "$line" ]; then if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi; fi ;;
        esac
    done <<< "$PY_OUT"
else
    nope "--workers 3 did not start (spread check skipped)"
fi
kill_all

# ══════════════════════════════════════════════════════════════════
#   Step 16 — shutdown
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 0 ]; then echo "━━━ STEP 16: shutdown ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; fi

for sig in TERM INT; do
    if start_server --workers 4; then
        parent=$(worker_pids | head -1)
        kill -"$sig" "$parent" 2>/dev/null
        left=1
        deadline=$((SECONDS + 5))
        while [ $SECONDS -lt $deadline ]; do
            if [ "$(worker_count)" -eq 0 ]; then left=0; break; fi
            sleep 0.25
        done
        if [ "$left" -eq 0 ]; then
            ok "SIG$sig on the forking process left no worker behind"
        else
            nope "SIG$sig left $(worker_count) worker(s) behind"
            kill_all
        fi

        # the port must be usable again straight away
        if start_server --workers 2 && serves_200; then
            ok "port rebindable immediately after SIG$sig"
        else
            nope "port not rebindable after SIG$sig"
        fi
        kill_all
    else
        nope "--workers 4 did not start (SIG$sig check skipped)"
    fi
done

# The default (single-worker) server must answer SIGINT/SIGTERM too. It
# forks no workers, so before the handler was installed unconditionally it
# ran with the DEFAULT disposition — fine under a shell, fatal in a
# container: the kernel discards a SIG_DFL signal aimed at pid 1, so
# `ENTRYPOINT ["/sarm", "8443"]` on a scratch image ignored both Ctrl-C
# and `docker stop` and only died to the SIGKILL that followed.
for sig in TERM INT; do
    if start_server; then
        parent=$(worker_pids | head -1)
        kill -"$sig" "$parent" 2>/dev/null
        left=1
        deadline=$((SECONDS + 5))
        while [ $SECONDS -lt $deadline ]; do
            if [ "$(worker_count)" -eq 0 ]; then left=0; break; fi
            sleep 0.25
        done
        if [ "$left" -eq 0 ]; then
            ok "SIG$sig stops the default single-worker server (pid-1 safe)"
        else
            nope "SIG$sig did not stop the single-worker server"
            kill_all
        fi
    else
        nope "default server did not start (single-worker SIG$sig skipped)"
    fi
    kill_all
done

# ...and so must the no_fork debug mode, for the same reason.
if start_server d; then
    parent=$(worker_pids | head -1)
    kill -INT "$parent" 2>/dev/null
    left=1
    deadline=$((SECONDS + 5))
    while [ $SECONDS -lt $deadline ]; do
        if [ "$(worker_count)" -eq 0 ]; then left=0; break; fi
        sleep 0.25
    done
    if [ "$left" -eq 0 ]; then
        ok "SIGINT stops the no_fork debug server"
    else
        nope "SIGINT did not stop the no_fork debug server"
    fi
else
    nope "no_fork server did not start (SIGINT check skipped)"
fi
kill_all

# in-flight connections must survive the shutdown
if start_server --workers 3; then
    parent=$(worker_pids | head -1)
    PY_OUT=$(python3 "$(dirname "$0")/worker_checks.py" inflight "$HOST_PORT" "$parent" 2>&1)
    while IFS= read -r line; do
        case "$line" in
            OK:*)   ok "${line#OK: }" ;;
            FAIL:*) nope "${line#FAIL: }" ;;
            *)      if [ -n "$line" ]; then if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi; fi ;;
        esac
    done <<< "$PY_OUT"
else
    nope "--workers 3 did not start (in-flight check skipped)"
fi
kill_all

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
        printf "${RED}Some tests failed!${CLR}\n"
        exit 1
    else
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "workers" "$PASS"
        exit 0
    fi
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
    echo "═══════════════════════════════════════════════════════════════"
    if [ "$FAIL" -gt 0 ]; then
        printf "\n${RED}Some tests failed!${CLR}\n"
        exit 1
    else
        printf "\n${GRN}All worker tests passed.${CLR}\n"
        exit 0
    fi
fi
