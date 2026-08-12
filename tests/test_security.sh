#!/usr/bin/env bash
# ymawky security test harness
#
# Tests the most important security properties by starting the server and
# probing it with curl, verifying that:
#
#   1. Path traversal via ".."  is rejected  (HTTP 400)
#   2. Path traversal via "%2e%2e%2f" is rejected (HTTP 400)
#   3. Normal file access succeeds (HTTP 200)
#   4. Null byte in path (%00) is rejected (HTTP 400)
#   5. Non-printable chars (%01) are rejected (HTTP 400)
#
# Usage:
#   bash tests/test_security.sh              # build + test
#   bash tests/test_security.sh --no-build   # test existing binary

set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────
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

# ── check_http ───────────────────────────────────────────────────────
# Usage: check_http  EXPECTED_CODE  DESCRIPTION  CURL_ARGS...
check_http() {
    local expected="$1"
    local desc="$2"
    shift 2

    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true

    if [ "$code" = "$expected" ]; then
        ok "${desc} — ${expected}"
    else
        nope "${desc} — expected ${expected}, got ${code}"
    fi
}

# ── parse flags ──────────────────────────────────────────────────────
DO_BUILD=1
HOST_PORT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --port)     HOST_PORT="$2"; shift ;;
        --quiet)    QUIET=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1"; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8080 + ($$ % 200) ))
fi

BASE="http://127.0.0.1:${HOST_PORT}"

# ── prerequisites ────────────────────────────────────────────────────
for cmd in curl make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

# ── cleanup trap ─────────────────────────────────────────────────────
SERVER_PID=""
cleanup() {
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ── build ────────────────────────────────────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
    if [ $QUIET -eq 1 ]; then
        make >/dev/null 2>&1
    else
        echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        make
        echo ""
    fi
fi

if [ ! -x "./ymawky" ]; then
    echo "$0: './ymawky' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

# ── start ────────────────────────────────────────────────────────────
if [ $QUIET -eq 0 ]; then echo "━━━ STARTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; fi
if [ $QUIET -eq 1 ]; then
    ./ymawky "$HOST_PORT" >/dev/null 2>&1 &
else
    ./ymawky "$HOST_PORT" &
fi
SERVER_PID=$!

if [ $QUIET -eq 0 ]; then echo -n "waiting for server (pid ${SERVER_PID}) …"; fi
for i in $(seq 1 40); do
    if curl -s -o /dev/null "${BASE}/" 2>/dev/null; then
        if [ $QUIET -eq 0 ]; then echo " ready"; fi
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        if [ $QUIET -eq 0 ]; then echo " DIED"; fi
        nope "server process exited unexpectedly"
        exit 1
    fi
    if [ "$i" -eq 40 ]; then
        if [ $QUIET -eq 0 ]; then echo " TIMEOUT"; fi
        nope "server did not start within 10 seconds"
        cleanup; exit 1
    fi
    if [ $QUIET -eq 0 ]; then echo -n .; fi
    sleep 0.25
done
if [ $QUIET -eq 0 ]; then echo ""; fi

# ══════════════════════════════════════════════════════════════════════
#   SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════

if [ $QUIET -eq 1 ]; then _log "── Path traversal ──"; else echo "── Path traversal ──"; fi

# Test 1: literal ".." traversal → 400
# --path-as-is is needed to prevent curl from normalizing .. client-side
check_http 400 \
    "literal .. in path" \
    --path-as-is "${BASE}/../etc/passwd"

# Test 2: percent-encoded traversal "%2e%2e%2f" → 400
check_http 400 \
    "percent-encoded .." \
    --path-as-is "${BASE}/%2e%2e%2f"

if [ $QUIET -eq 1 ]; then _log ""; _log "── Normal access ──"; else echo ""; echo "── Normal access ──"; fi

# Test 3: normal file access → 200
check_http 200 \
    "normal root access" \
    "${BASE}/"

if [ $QUIET -eq 1 ]; then _log ""; _log "── Dangerous bytes ──"; else echo ""; echo "── Dangerous bytes ──"; fi

# Test 4: null byte %00 → 400
check_http 400 \
    "null byte in path" \
    --path-as-is "${BASE}/%00"

# Test 5: non-printable %01 → 400
check_http 400 \
    "control char in path" \
    --path-as-is "${BASE}/%01test"

# ══════════════════════════════════════════════════════════════════════

if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        echo ""
        printf '%s' "$LOG"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
        printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "${RED}Some security tests failed!${CLR}"
        exit 1
    else
        printf "  ${GRN}✓${CLR} all security tests passed (%d tests)\n" "$PASS"
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
        echo "${RED}Some security tests failed!${CLR}"
        exit 1
    else
        echo ""
        echo "${GRN}All security tests passed.${CLR}"
        exit 0
    fi
fi
