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

ok()   { printf "  ${GRN}✓${CLR} %s\n" "$*";   PASS=$((PASS + 1)); }
nope() { printf "  ${RED}✗${CLR} %s\n" "$*";   FAIL=$((FAIL + 1)); }

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
    echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    make
    echo ""
fi

if [ ! -x "./ymawky" ]; then
    echo "$0: './ymawky' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

# ── start ────────────────────────────────────────────────────────────
echo "━━━ STARTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./ymawky "$HOST_PORT" &
SERVER_PID=$!

echo -n "waiting for server (pid ${SERVER_PID}) …"
for i in $(seq 1 40); do
    if curl -s -o /dev/null "${BASE}/" 2>/dev/null; then
        echo " ready"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo " DIED"
        nope "server process exited unexpectedly"
        exit 1
    fi
    if [ "$i" -eq 40 ]; then
        echo " TIMEOUT"
        nope "server did not start within 10 seconds"
        cleanup; exit 1
    fi
    echo -n .
    sleep 0.25
done
echo ""

# ══════════════════════════════════════════════════════════════════════
#   SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════

echo "── Path traversal ──"

# Test 1: literal ".." traversal → 400
# --path-as-is is needed to prevent curl from normalizing .. client-side
check_http 400 \
    "literal .. in path" \
    --path-as-is "${BASE}/../etc/passwd"

# Test 2: percent-encoded traversal "%2e%2e%2f" → 400
check_http 400 \
    "percent-encoded .." \
    --path-as-is "${BASE}/%2e%2e%2f"

echo ""
echo "── Normal access ──"

# Test 3: normal file access → 200
check_http 200 \
    "normal root access" \
    "${BASE}/"

echo ""
echo "── Dangerous bytes ──"

# Test 4: null byte %00 → 400
check_http 400 \
    "null byte in path" \
    --path-as-is "${BASE}/%00"

# Test 5: non-printable %01 → 400
check_http 400 \
    "control char in path" \
    --path-as-is "${BASE}/%01test"

# ══════════════════════════════════════════════════════════════════════

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
