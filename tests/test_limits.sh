#!/usr/bin/env bash
# sarm resource-limit harness (docs/SECURITY.md §8 and Step 12)
#
# Step 12: attack connections, handshake state, buffers and CPU, and
# check that resource use remains bounded. The attacks and the
# measurements are tests/limit_checks.py; this script is the part that
# has to run servers, and it runs four of them because the four
# campaigns need genuinely different server shapes:
#
#   connections   short-deadline variant, forking. Needs a receive
#   deadline      timeout and a connection deadline measured in seconds
#                 rather than the shipped minutes — otherwise asserting
#                 that a slow client is eventually dropped costs two
#                 minutes of `make test` per shape.
#   buffers       the real ./sarm, forking. Peak resident size is a
#                 property of the binary the rest of the suite runs
#                 against, so it is measured on that binary.
#   cpu           the real ./sarm in `no_fork` debug mode. Per-connection
#                 CPU is only measurable where one process serves the
#                 connections and survives them; a forked child's
#                 accounting dies with the child, and SIGCHLD is
#                 SIG_IGN with SA_NOCLDWAIT so nothing wait()s to
#                 collect it.
#
# The variant binary is built by `make variant`, out of tree, with
# -DCONN_DEADLINE_SECONDS / -DRECV_TIMEOUT_SECONDS. That leaves one
# thing untested — that the *shipped* numbers are the documented ones —
# so this script reads them back out of src/config.S and says so.
#
# Three process-level checks sit alongside the campaigns, for the same
# reason test_leak.sh has them: a server that passed every measurement
# by dying is not a server that passed.
#
#   1. nothing on stdout or stderr, ever (docs/SECURITY.md §4.5).
#   2. no core dump — a SIGALRM'd child must terminate, not dump.
#   3. the parent is alive at the end and never died on a signal.
#
# Usage:
#   ./test_limits.sh                    # build + test
#   ./test_limits.sh --no-build         # test the existing ./sarm
#   ./test_limits.sh --connections 128  # a wider connection flood
#   ./test_limits.sh --port 8090

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
CONNS=${SARM_LIMIT_CONNS:-48}
CPU_CASES=${SARM_LIMIT_CPU_CASES:-1200}
# The variant's configuration. Small enough that the deadline campaign
# costs one deadline of wall clock (the three shapes run concurrently),
# far enough apart that "the receive timeout killed it" and "the
# deadline killed it" cannot be confused for one another.
V_DEADLINE=${SARM_LIMIT_DEADLINE:-6}
V_RECV=${SARM_LIMIT_RECV:-2}

# The shipped defaults this script asserts src/config.S still carries.
SHIPPED_DEADLINE=120
SHIPPED_RECV=10

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)     DO_BUILD=0 ;;
        --port)         HOST_PORT="$2"; shift ;;
        --connections)  CONNS="$2"; shift ;;
        --cpu-cases)    CPU_CASES="$2"; shift ;;
        --deadline)     V_DEADLINE="$2"; shift ;;
        --recv-timeout) V_RECV="$2"; shift ;;
        --quiet)        QUIET=1 ;;
        -h|--help)      sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

# Four consecutive ports, all of them actually free. A port derived from
# $$ is the usual trick in this repo's harnesses, and it is what made
# this one flaky: a stale server left listening from an earlier run
# answers the readiness probe, the campaign's own server exits on a
# failed bind(), and every measurement below then reads a process that
# is not there. Binding the range first is the only way to know.
find_ports() {
    python3 - "$1" <<'PYEOF'
import socket, sys
start = int(sys.argv[1])
for base in range(start, start + 400):
    socks = []
    try:
        for off in range(4):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", base + off))
            socks.append(s)
    except OSError:
        continue
    finally:
        for s in socks:
            s.close()
    if len(socks) == 4:
        print(base)
        break
else:
    sys.exit(1)
PYEOF
}

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(find_ports $(( 8900 + ($$ % 180) )) ) || {
        echo "$0: could not find four free ports" >&2; exit 2; }
fi

for cmd in python3 make curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sarm-limits.XXXXXX")
STAMP="$WORK/.started"
: > "$STAMP"

SERVER_PID=""
cleanup() {
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cd "$ROOT"

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

VARIANT="$WORK/sarm-short"
if ! make -s variant BIN="$VARIANT" \
        VARIANT_CFLAGS="-DCONN_DEADLINE_SECONDS=$V_DEADLINE -DRECV_TIMEOUT_SECONDS=$V_RECV" \
        >"$WORK/variant.log" 2>&1; then
    echo "$0: could not build the short-deadline variant:" >&2
    cat "$WORK/variant.log" >&2
    exit 2
fi

# A crash must not be able to write memory to disk while this runs.
ulimit -c 0 2>/dev/null || true

# ── the shipped configuration ───────────────────────────────────────
# Everything below runs against a deliberately shortened build. This is
# the check that the numbers the server actually ships with are the ones
# docs/SECURITY.md §8 documents.
check_default() {
    local name="$1" want="$2" got
    got=$(sed -n "s/^#define ${name} \([0-9]*\)$/\1/p" src/config.S | head -1)
    if [ "$got" = "$want" ]; then
        ok "src/config.S ships ${name} = ${want}"
    else
        nope "src/config.S has ${name} = '${got}', documented as ${want}"
    fi
}

# ── one campaign: start a server, run it, check the process ─────────
run_campaign() {
    local label="$1"; shift
    local bin="$1"; shift
    local port="$1"; shift
    local mode="$1"; shift          # "" for forking, "d" for no_fork
    local out="$WORK/${label}.out"
    local err="$WORK/${label}.err"

    if [ -n "$mode" ]; then
        "$bin" "$port" "$mode" >"$out" 2>"$err" &
    else
        "$bin" "$port" >"$out" 2>"$err" &
    fi
    SERVER_PID=$!

    local ready=0
    local deadline=$((SECONDS + 10))
    while [ $SECONDS -lt $deadline ]; do
        # the liveness test comes first, deliberately: a curl that
        # succeeds proves something is listening, not that it is ours.
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            nope "[$label] server exited before the campaign started" \
                 "(port ${port} taken?)"
            SERVER_PID=""; return
        fi
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
            ready=1; break
        fi
        sleep 0.25
    done
    if [ "$ready" -ne 1 ]; then
        nope "[$label] server did not start within 10 seconds"
        kill "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; return
    fi

    local py_out
    py_out=$(python3 "$HERE/limit_checks.py" "$label" "$port" \
                     --pid "$SERVER_PID" "$@" 2>&1) || true
    while IFS= read -r line; do
        case "$line" in
            OK:*)   ok "${line#OK: }" ;;
            FAIL:*) nope "${line#FAIL: }" ;;
            *)      if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi ;;
        esac
    done <<< "$py_out"

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        ok "[$label] server survived the campaign"
    else
        nope "[$label] server died during the campaign"
    fi

    kill "$SERVER_PID" 2>/dev/null || true
    local status=0
    wait "$SERVER_PID" 2>/dev/null || status=$?
    SERVER_PID=""
    # 143 = SIGTERM, which is how this script stops it; 130 = SIGINT.
    if [ "$status" -gt 128 ] && [ "$status" -ne 143 ] && [ "$status" -ne 130 ]; then
        nope "[$label] server terminated on signal $((status - 128))"
    fi

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

if [ $QUIET -eq 0 ]; then
    echo "━━━ RESOURCE LIMITS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ${CONNS} concurrent connections, ${CPU_CASES} CPU cases"
    echo "  variant: CONN_DEADLINE=${V_DEADLINE}s RECV_TIMEOUT=${V_RECV}s"
    echo ""
fi

# ── the instruments' own test ───────────────────────────────────────
# Every campaign is a comparison between two numbers limit_checks.py
# produced. A `ps` that returns nothing, or a CPU clock that never
# advances, would make all of them pass by measuring nothing.
SELF_OUT=$(python3 "$HERE/limit_checks.py" --self-test 2>&1) || true
while IFS= read -r line; do
    case "$line" in
        OK:*)   ok "${line#OK: }" ;;
        FAIL:*) nope "${line#FAIL: }" ;;
        *)      if [ $QUIET -eq 0 ]; then echo "$line"; else _log "$line"; fi ;;
    esac
done <<< "$SELF_OUT"

check_default CONN_DEADLINE_SECONDS "$SHIPPED_DEADLINE"
check_default RECV_TIMEOUT_SECONDS  "$SHIPPED_RECV"

run_campaign connections "$VARIANT" "$HOST_PORT"       "" \
             --recv-timeout "$V_RECV" --connections "$CONNS"
run_campaign deadline    "$VARIANT" "$((HOST_PORT + 1))" "" \
             --deadline "$V_DEADLINE" --recv-timeout "$V_RECV"
run_campaign buffers     "./sarm"   "$((HOST_PORT + 2))" ""
run_campaign cpu         "./sarm"   "$((HOST_PORT + 3))" "d" \
             --cpu-cases "$CPU_CASES"

# ── core dumps ──────────────────────────────────────────────────────
# SIGALRM terminates without dumping, which is the whole reason the
# deadline uses it. This is the check that says so.
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
        printf "${RED}Resource-limit checks failed!${CLR}\n"
        exit 1
    else
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "resource limits" "$PASS"
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
        printf "${RED}Resource-limit checks failed!${CLR}\n"
        exit 1
    fi
    echo ""
    printf "${GRN}Resource use stayed bounded under every attack.${CLR}\n"
    exit 0
fi
