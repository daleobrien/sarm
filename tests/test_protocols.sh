#!/usr/bin/env bash
# ymawky protocol-detection test harness (Stage 14)
#
# Proves that HTTP/1 and HTTP/2 share ONE port (RFC 9113 §3.4 prior
# knowledge, detected from the "PRI * HTTP/2.0" client connection
# preface):
#
#   14.1 — HTTP/2 detected: a curl --http2-prior-knowledge request is
#         served as HTTP/2 (http_version=2, 200, body intact).
#   14.2 — HTTP/1 bytes preserved: HTTP/1.1 requests still work and the
#         probe never consumes request bytes — a request trickled in
#         two fragments produces a byte-for-byte identical response to
#         a single-write request, and the body matches the on-disk file.
#   14.3 — both protocols on one port: HTTP/1.1 and HTTP/2 requests
#         interleaved on the same port all succeed, and the same
#         resource is served byte-for-byte identically over both.
#
# Usage:
#   ./test_protocols.sh              # build + test
#   ./test_protocols.sh --no-build   # skip make, test existing binary
#   ./test_protocols.sh --port 8090  # use a specific port

set -euo pipefail

# ── helpers ─────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CLR='\033[0m'

PASS=0
FAIL=0
SKIP=0
QUIET=0

LOG=""

_log() { printf -v _tmp "%s\n" "$*"; LOG+="$_tmp"; }

ok()   { local _s; printf -v _s "  ${GRN}✓${CLR} %s" "$*"; PASS=$((PASS + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
nope() { local _s; printf -v _s "  ${RED}✗${CLR} %s" "$*"; FAIL=$((FAIL + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
skip() { local _s; printf -v _s "  ${YLW}—${CLR} %s (skipped)" "$*"; SKIP=$((SKIP + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }

# Fetch PATH over PROTO_ARGS and report "code version".
check_http() {
    local proto_args="$1"
    local path="$2"
    local code ver
    code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' $proto_args "${BASE}${path}" 2>/dev/null) || true
    ver=$(curl -s --max-time 5 -o /dev/null -w '%{http_version}' $proto_args "${BASE}${path}" 2>/dev/null) || true
    printf '%s %s' "$code" "$ver"
}

# Fetch PATH over PROTO_ARGS and compare the body with DISK_PATH,
# transparently gunzipping a Content-Encoding: gzip response
# (mirrors tests/test_files.sh).
check_body() {
    local proto_args="$1"
    local path="$2"
    local disk_path="$3"

    local tmp head
    tmp=$(mktemp "/tmp/ymawky_proto_body_XXXXXX")
    head=$(mktemp "/tmp/ymawky_proto_head_XXXXXX")
    curl -s --max-time 5 -o "$tmp" -D "$head" $proto_args "${BASE}${path}" 2>/dev/null || true

    local has_gzip
    has_gzip=$(grep -ci '^Content-Encoding:.*gzip' "$head" 2>/dev/null) || true

    local rc=1
    if [ "$has_gzip" -gt 0 ]; then
        local ungz
        ungz=$(mktemp "/tmp/ymawky_proto_ungz_XXXXXX")
        if gzip -d -c "$tmp" > "$ungz" 2>/dev/null && diff -q "$ungz" "$disk_path" >/dev/null 2>&1; then
            rc=0
        fi
        rm -f "$ungz"
    else
        if diff -q "$tmp" "$disk_path" >/dev/null 2>&1; then
            rc=0
        fi
    fi
    rm -f "$tmp" "$head"
    return $rc
}

# ── parse flags ─────────────────────────────────────────────────
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

# ── prerequisites ────────────────────────────────────────────────
for cmd in curl diff gzip make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

# HTTP/2 (prior knowledge) needs a curl built with HTTP/2 support.
CURL_H2=0
if curl --version 2>/dev/null | grep -q 'HTTP2'; then
    CURL_H2=1
fi

# The fragmented-request test writes raw bytes with nc.
NC_AVAILABLE=0
if command -v nc >/dev/null 2>&1; then
    NC_AVAILABLE=1
fi

# ── cleanup trap ─────────────────────────────────────────────────
SERVER_PID=""
cleanup() {
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
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

if [ ! -x "./ymawky" ]; then
    echo "$0: './ymawky' binary not found or not executable — run 'make' first" >&2
    exit 2
fi

# ── start ────────────────────────────────────────────────────────
if [ $QUIET -eq 0 ]; then echo "━━━ STARTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; fi
if [ $QUIET -eq 1 ]; then
    ./ymawky "$HOST_PORT" >/dev/null 2>&1 &
else
    ./ymawky "$HOST_PORT" &
fi
SERVER_PID=$!

if [ $QUIET -eq 0 ]; then echo -n "waiting for server (pid ${SERVER_PID}) …"; fi
ready=0
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
    if curl -s --max-time 2 -o /dev/null "${BASE}/" 2>/dev/null; then
        ready=1
        if [ $QUIET -eq 0 ]; then echo " ready"; fi
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        if [ $QUIET -eq 0 ]; then echo " DIED"; fi
        nope "server process exited unexpectedly"
        exit 1
    fi
    if [ $QUIET -eq 0 ]; then echo -n .; fi
    sleep 0.25
done
if [ "$ready" -ne 1 ]; then
    if [ $QUIET -eq 0 ]; then echo " TIMEOUT"; fi
    nope "server did not start within 10 seconds"
    cleanup; exit 1
fi
if [ $QUIET -eq 0 ]; then echo ""; fi

# ══════════════════════════════════════════════════════════════════
#   14.1 — the probe: HTTP/2 is detected from the connection preface
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 1 ]; then _log "── 14.1 HTTP/2 detected ──"; else echo "── 14.1 HTTP/2 detected ──"; fi

if [ "$CURL_H2" -eq 1 ]; then
    r=$(check_http "--http2-prior-knowledge" "/")
    if [ "$r" = "200 2" ]; then
        ok "GET / over HTTP/2 (prior knowledge) → 200, http_version=2"
    else
        nope "GET / over HTTP/2 (prior knowledge) — expected 200 2, got ${r}"
    fi

    if check_body "--http2-prior-knowledge" "/index.html" "www/index.html"; then
        ok "GET /index.html over HTTP/2 — body matches source (gzip-aware)"
    else
        nope "GET /index.html over HTTP/2 — body does NOT match source"
    fi

    # a fresh connection still speaks HTTP/2 — detection is stable
    r=$(check_http "--http2-prior-knowledge" "/")
    if [ "$r" = "200 2" ]; then
        ok "second fresh HTTP/2 connection still detected"
    else
        nope "second fresh HTTP/2 connection — expected 200 2, got ${r}"
    fi
else
    skip "HTTP/2 tests (curl built without HTTP/2 support)"
fi

# ══════════════════════════════════════════════════════════════════
#   14.2 — the probe preserves HTTP/1 bytes
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 1 ]; then _log ""; _log "── 14.2 HTTP/1 bytes preserved ──"; else echo ""; echo "── 14.2 HTTP/1 bytes preserved ──"; fi

r=$(check_http "--http1.1" "/")
if [ "$r" = "200 1.1" ]; then
    ok "GET / over HTTP/1.1 → 200, http_version=1.1"
else
    nope "GET / over HTTP/1.1 — expected 200 1.1, got ${r}"
fi

if check_body "--http1.1" "/index.html" "www/index.html"; then
    ok "GET /index.html over HTTP/1.1 — body matches source (gzip-aware)"
else
    nope "GET /index.html over HTTP/1.1 — body does NOT match source"
fi

# A request trickled in two fragments (request line, 0.2s pause, then
# the headers) must be served byte-for-byte identically to a request
# written in a single burst — the probe never consumes HTTP/1 bytes.
if [ "$NC_AVAILABLE" -eq 1 ]; then
    frag=$(mktemp "/tmp/ymawky_proto_frag_XXXXXX")
    whole=$(mktemp "/tmp/ymawky_proto_whole_XXXXXX")

    # logo.png is not gzip-eligible, so the raw body is comparable
    ( printf 'GET /logo.png HTTP/1.1\r\n'; sleep 0.2; printf 'Host: 127.0.0.1\r\n\r\n' ) \
        | nc -w 5 127.0.0.1 "$HOST_PORT" > "$frag" 2>/dev/null || true
    printf 'GET /logo.png HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n' \
        | nc -w 5 127.0.0.1 "$HOST_PORT" > "$whole" 2>/dev/null || true

    status=$(head -1 "$frag" | tr -d '\r')
    if [ "$status" = "HTTP/1.1 200 OK" ]; then
        ok "fragmented HTTP/1 request — status line intact"
    else
        nope "fragmented HTTP/1 request — expected 'HTTP/1.1 200 OK', got '${status}'"
    fi

    if cmp -s "$frag" "$whole"; then
        ok "fragmented response byte-for-byte identical to whole-request response"
    else
        nope "fragmented response differs from whole-request response"
    fi

    # the body is the last Content-Length bytes of the response
    total=$(wc -c < "$frag" 2>/dev/null || echo 0)
    clen=$(LC_ALL=C grep -a -i '^Content-Length:' "$frag" 2>/dev/null | head -1 | tr -d '\r' | awk '{print $2}')
    frag_body=$(mktemp "/tmp/ymawky_proto_fragbody_XXXXXX")
    if [ -n "$clen" ] && [ "$total" -ge "$clen" ] 2>/dev/null; then
        dd if="$frag" of="$frag_body" bs=1 skip=$((total - clen)) 2>/dev/null
        if cmp -s "$frag_body" "www/logo.png"; then
            ok "fragmented HTTP/1 response body matches www/logo.png byte-for-byte"
        else
            nope "fragmented HTTP/1 response body does NOT match www/logo.png"
        fi
    else
        nope "fragmented HTTP/1 response — could not extract body (Content-Length missing?)"
    fi
    rm -f "$frag" "$whole" "$frag_body"
else
    skip "fragmented HTTP/1 request test (netcat not available)"
fi

# ══════════════════════════════════════════════════════════════════
#   14.3 — both protocols on one port
# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 1 ]; then _log ""; _log "── 14.3 both protocols on one port ──"; else echo ""; echo "── 14.3 both protocols on one port ──"; fi

# Interleave HTTP/1.1 and HTTP/2 requests against the same port.
r=$(check_http "--http1.1" "/")
if [ "$r" = "200 1.1" ]; then
    ok "interleave [1] HTTP/1.1 → 200, http_version=1.1"
else
    nope "interleave [1] HTTP/1.1 — expected 200 1.1, got ${r}"
fi

if [ "$CURL_H2" -eq 1 ]; then
    r=$(check_http "--http2-prior-knowledge" "/")
    if [ "$r" = "200 2" ]; then
        ok "interleave [2] HTTP/2 → 200, http_version=2"
    else
        nope "interleave [2] HTTP/2 — expected 200 2, got ${r}"
    fi
fi

r=$(check_http "--http1.1" "/logo.png")
if [ "$r" = "200 1.1" ]; then
    ok "interleave [3] HTTP/1.1 /logo.png → 200, http_version=1.1"
else
    nope "interleave [3] HTTP/1.1 /logo.png — expected 200 1.1, got ${r}"
fi

if [ "$CURL_H2" -eq 1 ]; then
    r=$(check_http "--http2-prior-knowledge" "/favicon.svg")
    if [ "$r" = "200 2" ]; then
        ok "interleave [4] HTTP/2 /favicon.svg → 200, http_version=2"
    else
        nope "interleave [4] HTTP/2 /favicon.svg — expected 200 2, got ${r}"
    fi

    # the same resource is byte-for-byte identical over both protocols
    if check_body "--http1.1" "/index.html" "www/index.html" \
        && check_body "--http2-prior-knowledge" "/index.html" "www/index.html"; then
        ok "HTTP/1.1 and HTTP/2 serve /index.html byte-for-byte identically"
    else
        nope "HTTP/1.1 and HTTP/2 /index.html bodies differ"
    fi
fi

# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        printf '%s\n' "── test (protocol detection) ──"
        echo ""
        printf '%s' "$LOG"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
        printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
        printf "  Skipped: ${YLW}%d${CLR}\n" "$SKIP"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "${RED}Some protocol tests failed!${CLR}"
        exit 1
    else
        printf "── test (%-25s ... (%3d tests) ${GRN}✓${CLR}\n" "protocol detection)" "$PASS"
        exit 0
    fi
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
    printf "  Skipped: ${YLW}%d${CLR}\n" "$SKIP"
    echo "═══════════════════════════════════════════════════════════════"

    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "${RED}Some protocol tests failed!${CLR}"
        exit 1
    else
        echo ""
        echo "${GRN}All protocol tests passed.${CLR}"
        exit 0
    fi
fi
