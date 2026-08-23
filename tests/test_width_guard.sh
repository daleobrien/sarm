#!/usr/bin/env bash
# sarm width-premise guard (docs/SECURITY.md §3.5 item 3, §14 A3)
#
# §3.5 gives most of the tree's ~120 length sites a **width** verdict:
# the arithmetic cannot wrap because the operands are 8/16/24-bit wire
# fields in a wider register. The section is candid that this is "a
# human reading two functions", and that nothing in the build re-derives
# it when a field changes size. scripts/width_guard.py is that
# something. It proves no sum; it asserts the premises the verdicts were
# written under, so widening a field fails a check instead of silently
# invalidating a paragraph.
#
# Three checks, and two of them are controls. A guard that has only ever
# been seen to pass is exactly what §12 says is not evidence, so this
# script breaks the tree on purpose — in a scratch copy, never in place
# — and requires the guard to notice.
#
#   guard     the tree as committed: every premise holds
#   control   a 2-octet field widened to 3 must be caught
#   control   a field composed in a 64-bit register must be caught
#
# Usage: tests/test_width_guard.sh [--quiet] [--no-build]

set -u

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; CLR=$'\033[0m'
PASS=0; FAIL=0; QUIET=0; LOG=""

_log() { printf -v _tmp "%s\n" "$*"; LOG+="$_tmp"; }
ok()   { local _s; printf -v _s "  ${GRN}✓${CLR} %s" "$*"; PASS=$((PASS + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
nope() { local _s; printf -v _s "  ${RED}✗${CLR} %s" "$*"; FAIL=$((FAIL + 1)); if [ $QUIET -eq 1 ]; then _log "$_s"; else printf '%s\n' "$_s"; fi; }
head_() { if [ $QUIET -eq 0 ]; then echo ""; echo "── $* ──"; fi; }

for arg in "$@"; do
    case "$arg" in
        --quiet)    QUIET=1 ;;
        --no-build) ;;   # nothing to build; accepted so `make test` can pass it
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.." || exit 2
GUARD=scripts/width_guard.py

# ── the tree as committed ───────────────────────────────────────────
head_ "guard"

if python3 "$GUARD" >/dev/null 2>&1; then
    ok "every §3.5 width premise holds in the tree as committed"
else
    nope "the guard fails on the committed tree:"
    python3 "$GUARD" 2>&1 | sed 's/^/      /'
fi

# ── controls ────────────────────────────────────────────────────────
# Each runs against a full scratch copy of the tree, so nothing here can
# leave a damaged working directory behind, even on an interrupt.
head_ "controls"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

control() {
    local label="$1" file="$2" old="$3" new="$4"
    local dir="$SCRATCH/$(echo "$label" | tr -c 'a-zA-Z0-9' '_')"
    rm -rf "$dir"; mkdir -p "$dir"
    # scripts/ and src/ are all the guard reads
    cp -R scripts "$dir/scripts"
    cp -R src "$dir/src"

    if ! python3 - "$dir/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"anchor found {s.count(old)} times, expected 1")
open(path, "w").write(s.replace(old, new))
PY
    then
        nope "$label — could not set the control up (the anchor moved)"
        return
    fi

    if python3 "$dir/scripts/width_guard.py" >/dev/null 2>&1; then
        nope "$label — the guard did NOT notice"
    else
        ok "$label — caught"
    fi
}

control "a 2-octet field widened to 3 octets" \
    "src/tls/record/parse.S" \
'    ldrb    w6, [x9, #3]
    ldrb    w7, [x9, #4]
    orr     w6, w7, w6, lsl #8      // fragment length (big-endian)' \
'    ldrb    w6, [x9, #3]
    ldrb    w7, [x9, #4]
    lsl     w6, w6, #16
    orr     w6, w7, w6, lsl #8      // fragment length (big-endian)'

control "a field composed in a 64-bit register" \
    "src/tls/handshake/client_hello.S" \
'    orr     w14, w15, w14, lsl #8    // extensions length' \
'    orr     x14, x15, x14, lsl #8    // extensions length'

# ── summary ─────────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ $FAIL -eq 0 ]; then
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "width premises" "$PASS"
    else
        printf '%s' "$LOG"
        printf "── %-37s ... (%3d failed) ${RED}✗${CLR}\n" "width premises" "$FAIL"
    fi
else
    echo ""
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
fi

[ $FAIL -eq 0 ]
