#!/usr/bin/env bash
# sarm fail-closed entropy harness (docs/SECURITY.md §4.4, §14 A4)
#
# §2's P0 row is "ECDSA nonce/randomness failure → private-key
# compromise". §4.4 answers it by construction — every caller of
# crypto_random_bytes checks the carry and aborts the handshake — and
# until this harness existed, said so with the caveat "asserted by
# construction and still not by a test". The kernel CSPRNG does not
# fail on request, so the path had never run.
#
# It runs now. src/crypto/random.S grows a -DSARM_RNG_FAIL_NTH=n block,
# on the -DSARM_NO_RODATA precedent (src/defs.S), and `make variant`
# builds servers whose n-th entropy draw of the connection fails. A
# TLS 1.3 connection makes exactly three:
#
#   1  server_random            ─┬─ both abort inside
#   2  ephemeral X25519 scalar  ─┘  tls_build_server_hello
#   3  the ECDSA nonce k           aborts inside
#                                  tls_certificate_verify_write
#
# and they fail differently, which is the point of testing each. The
# first two abort before a single byte is written, so the correct
# observation is that the client saw *nothing at all*. The third aborts
# with ServerHello, EncryptedExtensions and Certificate already on the
# wire, so the correct observation is that exactly those three records
# arrived and the fourth — the signature — never did.
#
# The measurement is tests/rng_fail_checks.py, which drives the
# handshake over a MemoryBIO so it can count wire bytes rather than
# only ask the library whether it worked.
#
# Six groups:
#
#   shipped     the default build carries no trace of the injection
#   control     an uninjected server completes the handshake — without
#               this the four failing cases below prove only that the
#               client cannot talk to this server at all
#   draw 1/2/3  each abort, observed on the wire
#   callers     every bl crypto_random_bytes in the tree is followed by
#               a carry check (the walk §14 A4 asks for, done by the
#               build rather than by a person, so it stays done)
#   process     nothing on stdout or stderr, no core, parents alive
#
# Usage: tests/test_rng_fail.sh [--quiet] [--no-build] [--port N]

set -u

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; CLR=$'\033[0m'
PASS=0; FAIL=0; QUIET=0; LOG=""

_log() { printf -v _tmp "%s\n" "$*"; LOG+="$_tmp"; }
ok()   { local _s; printf -v _s "  ${GRN}✓${CLR} %s" "$*"; PASS=$((PASS + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
nope() { local _s; printf -v _s "  ${RED}✗${CLR} %s" "$*"; FAIL=$((FAIL + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
head_() { if [ $QUIET -eq 0 ]; then echo ""; echo "── $* ──"; fi; }

DO_BUILD=1
BASE_PORT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --quiet)    QUIET=1 ;;
        --no-build) DO_BUILD=0 ;;
        --port)     BASE_PORT="$2"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT" || exit 2

[ "$BASE_PORT" -eq 0 ] && BASE_PORT=$(( 8500 + ($$ % 300) ))

WORK="$(mktemp -d)"
SERVERS=""
# `kill` on a background job makes bash announce "Terminated" on
# stderr when it reaps it, which would land in the middle of the
# output. Waiting for the job inside the redirection swallows the
# notice without swallowing anything else.
stop() { { kill "$1" && wait "$1"; } 2>/dev/null; }

cleanup() {
    for pid in $SERVERS; do stop "$pid"; done
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$DO_BUILD" -eq 1 ]; then
    make >/dev/null 2>&1
fi
if [ ! -x ./sarm ]; then
    echo "$0: './sarm' not found — run 'make' first" >&2
    exit 2
fi

# A crash must not be able to write memory to disk while this runs.
ulimit -c 0 2>/dev/null || true

# ── the injection does not ship ─────────────────────────────────────
# The whole mechanism lives inside #ifdef, so the shipped binary should
# not contain its symbols. Checked on the linked binary rather than by
# re-reading the #ifdef, for the same reason test_hardening.sh inspects
# the binary rather than trusting the flags.
head_ "shipped"

if nm ./sarm 2>/dev/null | grep -q crypto_random_fail; then
    nope "./sarm carries the failure-injection symbols — it must not"
else
    ok "./sarm carries no failure-injection symbol"
fi

# ── build the variants ──────────────────────────────────────────────
# One per draw. There is no control *variant*: `make variant` with no
# VARIANT_CFLAGS compiles the same sources with the same flags as the
# default target, so ./sarm already is that binary, and using it makes
# the control a statement about the server the rest of the suite runs
# against rather than about a copy of it.
build_variant() {
    local name="$1" flags="$2"
    if ! make -s variant BIN="$WORK/$name" VARIANT_CFLAGS="$flags" \
            >"$WORK/$name.build" 2>&1; then
        nope "could not build the '$name' variant:"
        sed 's/^/      /' "$WORK/$name.build" >&2
        return 1
    fi
    return 0
}

build_variant rng1 "-DSARM_RNG_FAIL_NTH=1" || exit 1
build_variant rng2 "-DSARM_RNG_FAIL_NTH=2" || exit 1
build_variant rng3 "-DSARM_RNG_FAIL_NTH=3" || exit 1

if nm "$WORK/rng1" 2>/dev/null | grep -q crypto_random_fail; then
    ok "an injected variant does carry them (so the check above can fail)"
else
    nope "the injected variant has no failure-injection symbol either — " \
         "the -D did not reach the build, and every case below is vacuous"
fi

# ── run one server and take one handshake off it ────────────────────
# Sets REPORT (the JSON) and leaves the server running long enough to
# check its output streams.
PORT_N=0
probe() {
    local bin="$1" label="$2"
    local port=$(( BASE_PORT + PORT_N )); PORT_N=$((PORT_N + 1))
    local out="$WORK/$label.out" err="$WORK/$label.err"

    "$bin" "$port" >"$out" 2>"$err" &
    local pid=$!
    SERVERS="$SERVERS $pid"

    # Wait for the listener. A plaintext request is the liveness test
    # even for the injected servers: nothing on the plaintext path
    # draws entropy, so they all serve HTTP/1 perfectly well and only
    # fall over on TLS. That is itself worth knowing — the injection is
    # narrow.
    local ready=0 deadline=$((SECONDS + 10))
    while [ $SECONDS -lt $deadline ]; do
        kill -0 "$pid" 2>/dev/null || break
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
            ready=1; break
        fi
        sleep 0.25
    done
    if [ "$ready" -ne 1 ]; then
        nope "[$label] server did not start (port ${port} taken?)"
        stop "$pid"
        REPORT=""
        return 1
    fi

    REPORT=$(python3 "$HERE/rng_fail_checks.py" --port "$port" 2>"$WORK/$label.pyerr")
    if [ -z "$REPORT" ]; then
        nope "[$label] the handshake probe produced nothing:"
        sed 's/^/      /' "$WORK/$label.pyerr" >&2
        stop "$pid"
        return 1
    fi

    # Process-level, the same three test_limits.sh asks: a server that
    # passed a measurement by dying has not passed it.
    if [ -s "$out" ] || [ -s "$err" ]; then
        nope "[$label] wrote to stdout/stderr (docs/SECURITY.md §4.5)"
    else
        ok "[$label] nothing on stdout or stderr"
    fi
    if kill -0 "$pid" 2>/dev/null; then
        ok "[$label] the server is still alive after the aborted handshake"
    else
        nope "[$label] the server died"
    fi
    stop "$pid"
    return 0
}

# field <json> <key> — a scalar out of the probe's JSON
field() {
    python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' \
            "$1" "$2" 2>/dev/null
}

# ── control: the same client, against an uninjected server ──────────
head_ "control"

if probe ./sarm control; then
    [ "$(field "$REPORT" ok)" = "True" ] \
        && ok "[control] the handshake completes" \
        || nope "[control] the handshake failed ($(field "$REPORT" error)) — " \
                "every case below would 'pass' for the wrong reason"
    [ "$(field "$REPORT" app_bytes)" -gt 0 ] 2>/dev/null \
        && ok "[control] and application data flows over it" \
        || nope "[control] no application data after the handshake"
fi

# ── draw 1 and 2: nothing reaches the wire ──────────────────────────
head_ "the ServerHello draws"

for n in 1 2; do
    case $n in
        1) what="server_random" ;;
        2) what="the ephemeral X25519 scalar" ;;
    esac
    if probe "$WORK/rng$n" "rng$n"; then
        [ "$(field "$REPORT" ok)" = "False" ] \
            && ok "[draw $n: $what] the handshake is refused" \
            || nope "[draw $n: $what] the handshake COMPLETED — fail-closed did not hold"
        [ "$(field "$REPORT" server_bytes)" = "0" ] \
            && ok "[draw $n] not one byte reached the client" \
            || nope "[draw $n] the server sent $(field "$REPORT" server_bytes) byte(s) " \
                    "before giving up; it should send none"
        [ "$(field "$REPORT" server_hello)" = "False" ] \
            && ok "[draw $n] no ServerHello was written" \
            || nope "[draw $n] a ServerHello reached the wire"
    fi
done

# ── draw 3: three records, and no signature ─────────────────────────
# The P0 case. By the time k is drawn, ServerHello, EncryptedExtensions
# and Certificate are already sent and cannot be unsent — so the
# assertion is about the record that must not follow them.
head_ "the ECDSA nonce draw"

if probe "$WORK/rng3" rng3; then
    [ "$(field "$REPORT" ok)" = "False" ] \
        && ok "[draw 3: the ECDSA nonce] the handshake is refused" \
        || nope "[draw 3] the handshake COMPLETED — something signed without a fresh k"
    [ "$(field "$REPORT" server_hello)" = "True" ] \
        && ok "[draw 3] the flight had already started (ServerHello sent)" \
        || nope "[draw 3] no ServerHello — this is not the draw it claims to be"
    nrec=$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])["records"]))' "$REPORT")
    [ "$nrec" = "3" ] \
        && ok "[draw 3] exactly 3 records — SH, EE, Certificate, and nothing after" \
        || nope "[draw 3] $nrec record(s) reached the client, expected 3 " \
                "(a 4th would be the CertificateVerify that must not exist)"
    [ "$(field "$REPORT" app_bytes)" = "0" ] \
        && ok "[draw 3] no application data" \
        || nope "[draw 3] application data flowed over an unfinished handshake"
fi

# ── every caller checks the return ──────────────────────────────────
# §14 A4 asks for a walk of every crypto_random_bytes caller. Doing it
# here rather than in a paragraph means it is still done after the next
# call site is added.
head_ "callers"

CALLERS=$(grep -rn 'bl[[:space:]]\+crypto_random_bytes' src --include='*.S' | wc -l | tr -d ' ')
UNCHECKED=$(awk '
    /bl[[:space:]]+crypto_random_bytes/ { pending = 1; site = FILENAME ":" FNR; next }
    pending {
        line = $0
        sub(/\/\/.*/, "", line)
        if (line ~ /^[[:space:]]*$/) next          # blank or comment-only
        if (line !~ /^[[:space:]]*b\.cs[[:space:]]/) print site
        pending = 0
    }
' $(find src -name '*.S'))

if [ "$CALLERS" -lt 1 ]; then
    nope "no call sites found at all — the sweep is not looking at anything"
elif [ -n "$UNCHECKED" ]; then
    nope "a crypto_random_bytes result is not checked for carry:"
    printf '      %s\n' $UNCHECKED
else
    ok "all $CALLERS crypto_random_bytes call site(s) branch on carry immediately"
fi

# ── no core dumps ───────────────────────────────────────────────────
head_ "process"

if ls core* /cores/core.* >/dev/null 2>&1; then
    nope "a core dump was produced"
else
    ok "no core dump"
fi

# ── summary ─────────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ $FAIL -eq 0 ]; then
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "fail-closed entropy" "$PASS"
    else
        printf '%s' "$LOG"
        printf "── %-37s ... (%3d failed) ${RED}✗${CLR}\n" "fail-closed entropy" "$FAIL"
    fi
else
    echo ""
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
fi

[ $FAIL -eq 0 ]
