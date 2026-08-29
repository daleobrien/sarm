#!/usr/bin/env bash
# sarm secret-leak regression harness (docs/SECURITY.md §4.5, Step 10)
#
# Step 10: fire malformed and fuzzed traffic at a running server, capture
# every byte it sends back, and assert that nothing secret is in it. The
# traffic is tests/hostile_workload.py, the needles and the scan are
# tests/leak_checks.py; this script is the part that has to run the
# server, and it adds the three checks that are about the *process*
# rather than about its responses:
#
#   1. the server writes nothing to stdout or stderr, ever. sarm has no
#      logging at all (docs/SECURITY.md §4.5) and that is a security
#      property, not an oversight — a log line is the cheapest way for a
#      secret to escape, and the only way to keep the property is to
#      assert it. Any byte on either descriptor fails the run.
#
#   2. the server leaves no core dump behind. A crash dump is a complete
#      memory disclosure including the private key (SECURITY.md §13.2), so
#      the run sets `ulimit -c 0`, and then checks that nothing appeared
#      in the working directory or in /cores anyway.
#
#   3. the server is still alive at the end and never died on a signal.
#      A crashed worker is a memory-safety finding whatever the response
#      scan says.
#
# The workload runs twice, against two different server modes, because
# they have genuinely different exposure:
#
#   fork      the production shape. Every connection is served by a fresh
#             child, so one client cannot see another's buffers even if
#             the server wanted it to — the .bss the child dirties dies
#             with the child.
#   no_fork   the debug/profiling mode (`./sarm PORT d`), where one
#             process serves connection after connection over the *same*
#             globals. This is the only configuration in which a
#             cross-connection leak is possible at all, which makes it
#             the one worth pointing a canary at.
#
# Usage:
#   ./test_leak.sh                  # build + test
#   ./test_leak.sh --no-build       # test existing binary
#   ./test_leak.sh --cases 2000     # a longer run (default 150 per mode)
#   ./test_leak.sh --port 8090

set -euo pipefail

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

# ── args ────────────────────────────────────────────────────────────
DO_BUILD=1
HOST_PORT=0
CASES=${SARM_LEAK_CASES:-150}
SEED=${SARM_LEAK_SEED:-0x5A524D}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --port)     HOST_PORT="$2"; shift ;;
        --cases)    CASES="$2"; shift ;;
        --seed)     SEED="$2"; shift ;;
        --quiet)    QUIET=1 ;;
        -h|--help)  sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8680 + ($$ % 200) ))
fi

for cmd in python3 make curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sarm-leak.XXXXXX")
# A stamp whose mtime stays at "start of run". $WORK itself will not do:
# writing the per-mode capture files into it moves its mtime forward, and
# a core written before the last of them would then look older than the
# run and be missed.
STAMP="$WORK/.started"
: > "$STAMP"

SERVER_PID=""
SERVER_PORT=""
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
    [ -n "${SERVER_PORT:-}" ] && pkill -f "sarm ${SERVER_PORT}( |\$)" 2>/dev/null
    true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── build ───────────────────────────────────────────────────────────
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

# A crash must not be able to write the key to disk while this runs.
ulimit -c 0 2>/dev/null || true

# ── one run: start a server, drive it, scan what came back ──────────
run_mode() {
    local label="$1"; shift
    local port="$1"; shift
    local out="$WORK/${label}.out"
    local err="$WORK/${label}.err"

    ./sarm "$port" "$@" >"$out" 2>"$err" 3>&- 4>&- &
    SERVER_PID=$!
    SERVER_PORT="$port"

    local ready=0
    local deadline=$((SECONDS + 10))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
            ready=1; break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            nope "[$label] server exited before the workload started"
            SERVER_PID=""; return
        fi
        sleep 0.25
    done
    if [ "$ready" -ne 1 ]; then
        nope "[$label] server did not start within 10 seconds"
        kill "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; return
    fi

    # ── the responses ──
    local py_out
    py_out=$(python3 "$HERE/leak_checks.py" "$port" --cases "$CASES" \
                     --seed "$SEED" --label "$label" 2>&1) || true
    while IFS= read -r line; do
        case "$line" in
            OK:*)   ok "${line#OK: }" ;;
            FAIL:*) nope "${line#FAIL: }" ;;
            *)      if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi ;;
        esac
    done <<< "$py_out"

    # ── the process ──
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        ok "[$label] server survived the workload"
    else
        nope "[$label] server died during the workload"
    fi

    kill "$SERVER_PID" 2>/dev/null || true
    local status=0
    wait "$SERVER_PID" 2>/dev/null || status=$?
    SERVER_PID=""
    # 143 = SIGTERM, which is how this script stops it. Any other
    # signal termination is a crash.
    if [ "$status" -gt 128 ] && [ "$status" -ne 143 ] && [ "$status" -ne 130 ]; then
        nope "[$label] server terminated on signal $((status - 128))"
    fi

    # ── the descriptors ──
    local nout nerr
    nout=$(wc -c <"$out" | tr -d ' ')
    nerr=$(wc -c <"$err" | tr -d ' ')
    if [ "$nout" -eq 0 ] && [ "$nerr" -eq 0 ]; then
        ok "[$label] server wrote nothing to stdout or stderr"
    else
        nope "[$label] server wrote ${nout} bytes to stdout and ${nerr} to stderr"
        if [ $QUIET -eq 0 ]; then head -c 400 "$out" "$err"; fi
    fi
}

# ── the two modes ───────────────────────────────────────────────────
if [ $QUIET -eq 0 ]; then
    echo "━━━ LEAK PROBE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ${CASES} hostile connections per mode, seed ${SEED}"
    echo ""
fi

# ── the scanner's own test ──────────────────────────────────────────
# Before trusting a clean scan, check the scanner can fail: synthetic
# responses carrying each needle must be caught, and a clean one must
# not be.
SELF_OUT=$(python3 "$HERE/leak_checks.py" --self-test 2>&1) || true
while IFS= read -r line; do
    case "$line" in
        OK:*)   ok "${line#OK: }" ;;
        FAIL:*) nope "${line#FAIL: }" ;;
        *)      if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi ;;
    esac
done <<< "$SELF_OUT"

run_mode "fork" "$HOST_PORT"
run_mode "no-fork" "$((HOST_PORT + 1))" d

# ── core dumps ──────────────────────────────────────────────────────
# Checked once, at the end, in the two places this platform writes
# them. `find -newer` against a stamp created at startup keeps a core
# from an unrelated earlier crash from failing an innocent run.
CORES=$(find . /cores -maxdepth 1 -name 'core*' -newer "$STAMP" 2>/dev/null | head -5 || true)
if [ -z "$CORES" ]; then
    ok "no core dump was produced"
else
    nope "core dump(s) written during the run: $CORES"
fi

# ── summary ─────────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        printf '%s\n' "$LOG"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
        printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        printf "${RED}Secret-leak checks failed!${CLR}\n"
        exit 1
    else
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "secret leak" "$PASS"
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
        printf "${RED}Secret-leak checks failed!${CLR}\n"
        exit 1
    fi
    echo ""
    printf "${GRN}No secret material reached the wire.${CLR}\n"
    exit 0
fi
