#!/usr/bin/env bash
# ymawky file-integrity test harness (local build)
#
# Builds ymawky via 'make', starts the local executable, then downloads
# every file from www/ and verifies each one matches the on-disk source
# byte-for-byte.  Accounts for transparent gzip Content-Encoding.
#
# Usage:
#   ./test_files.sh              # build + test
#   ./test_files.sh --no-build   # skip make, test existing binary
#   ./test_files.sh --port 8090  # use a specific port

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

# ── MIME-type map (must match embed_www.sh / src/file.S) ────────
mime_type() {
    case "$1" in
        .html)  echo "text/html; charset=utf-8" ;;
        .htm)   echo "text/html; charset=utf-8" ;;
        .css)   echo "text/css; charset=utf-8" ;;
        .csv)   echo "text/csv; charset=utf-8" ;;
        .xml)   echo "text/xml; charset=utf-8" ;;
        .js)    echo "text/javascript; charset=utf-8" ;;
        .json)  echo "application/json" ;;
        .wasm)  echo "application/wasm" ;;
        .mjs)   echo "text/javascript; charset=utf-8" ;;
        .map)   echo "application/json" ;;
        .png)   echo "image/png" ;;
        .jpg)   echo "image/jpeg" ;;
        .jpeg)  echo "image/jpeg" ;;
        .gif)   echo "image/gif" ;;
        .svg)   echo "image/svg+xml" ;;
        .ico)   echo "image/x-icon" ;;
        .webp)  echo "image/webp" ;;
        .avif)  echo "image/avif" ;;
        .bmp)   echo "image/bmp" ;;
        .tiff)  echo "image/tiff" ;;
        .apng)  echo "image/apng" ;;
        .woff)  echo "font/woff" ;;
        .woff2) echo "font/woff2" ;;
        .ttf)   echo "font/ttf" ;;
        .otf)   echo "font/otf" ;;
        .txt)   echo "text/plain; charset=utf-8" ;;
        .pdf)   echo "application/pdf" ;;
        .doc)   echo "application/msword" ;;
        .docx)  echo "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ;;
        .epub)  echo "application/epub+zip" ;;
        .rtf)   echo "application/rtf" ;;
        .mp4)   echo "video/mp4" ;;
        .webm)  echo "video/webm" ;;
        .mkv)   echo "video/x-matroska" ;;
        .avi)   echo "video/x-msvideo" ;;
        .mov)   echo "video/quicktime" ;;
        .mp3)   echo "audio/mpeg" ;;
        .ogg)   echo "audio/ogg" ;;
        .wav)   echo "audio/wav" ;;
        .flac)  echo "audio/flac" ;;
        .aac)   echo "audio/aac" ;;
        .m4a)   echo "audio/mp4" ;;
        .opus)  echo "audio/opus" ;;
        .zip)   echo "application/zip" ;;
        .gz)    echo "application/gzip" ;;
        .tar)   echo "application/x-tar" ;;
        .7z)    echo "application/x-7z-compressed" ;;
        .bz2)   echo "application/x-bzip2" ;;
        .rar)   echo "application/vnd.rar" ;;
        *)      echo "text/plain; charset=utf-8" ;;
    esac
}

# ── Determine whether the server is expected to gzip a file ─────
# Mirrors the should_gzip() logic in embed_www.sh
should_gzip() {
    case "$1" in
        .html|.htm|.css|.csv|.xml|.js|.json|.mjs|.map|.svg|.txt|.ttf|.otf)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# ── Test a single served file against its on-disk source ────────
# Usage: check_file  HTTP_PATH  DISK_PATH
check_file() {
    local url_path="$1"
    local disk_path="$2"
    local ext="${disk_path##*.}"
    # Handle dotfiles / no extension
    if [ "$ext" = "$disk_path" ] || [ "$ext" = "" ]; then
        ext=""
    else
        ext=".${ext}"
    fi

    local expected_ct
    expected_ct=$(mime_type "$ext")

    local tmpfile
    tmpfile=$(mktemp "/tmp/ymawky_file_test_XXXXXX")
    local tmphead
    tmphead=$(mktemp "/tmp/ymawky_file_head_XXXXXX")

    # Fetch file and response headers in one go.
    # --max-time keeps a single request from hanging the whole suite if
    # the server stops responding.
    local http_code
    http_code=$(curl -s --max-time 5 -o "$tmpfile" -w '%{http_code}' \
        -D "$tmphead" "${BASE}${url_path}" 2>/dev/null) || true

    # 1. HTTP status must be 200
    if [ "$http_code" != "200" ]; then
        nope "GET ${url_path} — expected 200, got ${http_code}"
        rm -f "$tmpfile" "$tmphead"
        return
    fi

    # 2. Content-Type must match
    local actual_ct
    actual_ct=$(grep -i '^Content-Type:' "$tmphead" 2>/dev/null \
        | sed 's/^[Cc]ontent-[Tt]ype: *//;s/\r$//') || true
    if [ "$actual_ct" != "$expected_ct" ]; then
        nope "GET ${url_path} — Content-Type: expected \"${expected_ct}\", got \"${actual_ct}\""
        rm -f "$tmpfile" "$tmphead"
        return
    fi

    # 3. Check Content-Encoding and compare body
    local has_gzip
    has_gzip=$(grep -ci '^Content-Encoding:.*gzip' "$tmphead" 2>/dev/null) || true

    if [ "$has_gzip" -gt 0 ]; then
        # Server sent gzip — decompress and compare
        local ungz
        ungz=$(mktemp "/tmp/ymawky_file_ungz_XXXXXX")
        if ! gzip -d -c "$tmpfile" > "$ungz" 2>/dev/null; then
            nope "GET ${url_path} — failed to decompress gzip body"
            rm -f "$tmpfile" "$tmphead" "$ungz"
            return
        fi

        if diff -q "$ungz" "$disk_path" >/dev/null 2>&1; then
            if should_gzip "$ext"; then
                ok "GET ${url_path} — gzip, matches source"
            else
                nope "GET ${url_path} — gzip Content-Encoding unexpected for \"${ext}\" (body matches though)"
            fi
        else
            nope "GET ${url_path} — gzip body does NOT match source"
        fi
        rm -f "$ungz"
    else
        # No gzip — compare directly
        if diff -q "$tmpfile" "$disk_path" >/dev/null 2>&1; then
            if should_gzip "$ext"; then
                # Text-like file that was expected to be gzipped but wasn't.
                # This can happen legitimately if the gzip didn't reduce size.
                ok "GET ${url_path} — raw, matches source (expected gzip but server served raw)"
            else
                ok "GET ${url_path} — raw, matches source"
            fi
        else
            nope "GET ${url_path} — raw body does NOT match source"
        fi
    fi

    rm -f "$tmpfile" "$tmphead"
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

# Wait up to 10s for the server. Every probe curl is bounded with
# --max-time so a server that accepts connections but never answers
# (a stuck request handler) can't hang the suite forever.
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
#   TESTS
# ══════════════════════════════════════════════════════════════════

WWW_DIR="www"

if [ ! -d "$WWW_DIR" ]; then
    echo "$0: '$WWW_DIR' directory not found" >&2
    exit 2
fi

# Collect all files under www/ (recursive, sorted for determinism)
# Use a temp file to avoid subshell losing PASS/FAIL counts
FILE_LIST=$(mktemp "/tmp/ymawky_file_list_XXXXXX")
find "$WWW_DIR" -type f -not -name '.DS_Store' | sort > "$FILE_LIST"
file_count=0
while IFS= read -r disk_path; do
    # Derive the HTTP path: strip "www" prefix → "/assets/foo.js", "/index.html", etc.
    url_path="${disk_path#$WWW_DIR}"
    # Ensure it starts with /
    url_path="/${url_path#/}"

    if [ $QUIET -eq 0 ]; then echo -n "  ${url_path} … "; fi
    check_file "$url_path" "$disk_path"
    file_count=$((file_count + 1))
done < "$FILE_LIST"
rm -f "$FILE_LIST"

# Also test that the root path ("/") resolves to index.html
if [ $QUIET -eq 1 ]; then _log "── Root path → index.html ──"; else echo ""; echo "── Root path → index.html ──"; fi
check_file "/" "$WWW_DIR/index.html"

# Also test index.html explicitly
check_file "/index.html" "$WWW_DIR/index.html"

# ══════════════════════════════════════════════════════════════════
if [ $QUIET -eq 1 ]; then
    if [ "$FAIL" -gt 0 ]; then
        echo ""
        printf '%s' "$LOG"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
        printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
        printf "  Skipped: ${YLW}%d${CLR}\n" "$SKIP"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "${RED}Some tests failed!${CLR}"
        exit 1
    else
        printf "  ${GRN}✓${CLR} all file-integrity tests passed (%d files)\n" "$PASS"
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
        echo "${RED}Some tests failed!${CLR}"
        exit 1
    else
        echo ""
        echo "${GRN}All file-integrity tests passed.${CLR}"
        exit 0
    fi
fi
