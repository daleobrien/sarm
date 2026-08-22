#!/usr/bin/env bash
# sarm production-hardening harness (docs/SECURITY.md §13, Step 13)
#
# Step 13 asks for the platform protections to be turned on and for the
# *final binary* to be inspected to confirm they are there. Flags in a
# Makefile are a claim; a segment table is evidence. Everything here
# reads the binary, or the running process, and nothing takes the build
# system's word for anything.
#
# Four groups:
#
#   binary   tests/hardening_checks.py: PIE, no writable-and-executable
#            mapping, the constants (certificate, private scalar,
#            embedded assets, crypto tables, both indirect-branch
#            tables) in a read-only region, the mutable globals outside
#            it, and no load-time relocations at all. On ELF it also
#            checks PT_GNU_STACK and that .rodata gets its own r--
#            segment.
#
#   process  the same claims about the process rather than the file: the
#            read-only region is mapped r-- in a running server, no
#            mapping is rwx, and (Linux) the core-dump limit is zero.
#            A file can be marked however it likes; what matters is what
#            the kernel did with it.
#
#   cores    a crashing connection child leaves no core, with a control
#            program proving that this machine does dump cores when
#            nothing stops it — otherwise the check would pass on a
#            machine where nothing ever dumps and mean nothing. Plus the
#            static half, which holds on any platform: the built binary
#            really does contain the RLIMIT_CORE call.
#
#   controls binaries built deliberately unhardened, to show the checks
#            above can fail. `-DSARM_NO_RODATA` puts every constant back
#            in writable .data; on Linux, linking without the hardening
#            flags gives a fixed-address image with an executable stack.
#            arm64 macOS cannot produce a non-PIE executable at all, so
#            that control is reported as skipped there rather than
#            quietly not run.
#
# Usage:
#   ./test_hardening.sh                 # build + test
#   ./test_hardening.sh --no-build      # test the existing ./sarm
#   ./test_hardening.sh --no-controls   # skip the control builds
#   ./test_hardening.sh --docker        # also inspect the container's
#                                       #   Linux binary (needs docker)
#   ./test_hardening.sh --port 8090

set -euo pipefail

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
head_() { if [ $QUIET -eq 0 ]; then echo ""; echo "── $* ──"; fi; }

# ── args ────────────────────────────────────────────────────────────
DO_BUILD=1
DO_CONTROLS=1
DO_DOCKER=0
HOST_PORT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)    DO_BUILD=0 ;;
        --no-controls) DO_CONTROLS=0 ;;
        --docker)      DO_DOCKER=1 ;;
        --port)        HOST_PORT="$2"; shift ;;
        --quiet)       QUIET=1 ;;
        -h|--help)     sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8960 + ($$ % 200) ))
fi

for cmd in python3 make curl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "$0: '$cmd' not found" >&2; exit 2; }
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sarm-harden.XXXXXX")
OS="$(uname -s)"

SERVER_PID=""
cleanup() {
    set +e
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── build ───────────────────────────────────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
    if [ $QUIET -eq 1 ]; then
        (cd "$ROOT" && make >/dev/null 2>&1)
    else
        echo "━━━ BUILDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        (cd "$ROOT" && make)
        echo ""
    fi
fi

[ -x "$ROOT/sarm" ] || { echo "$0: '$ROOT/sarm' not found — run 'make' first" >&2; exit 2; }

# ══════════════════════════════════════════════════════════════════════
#   1. the binary
# ══════════════════════════════════════════════════════════════════════
head_ "binary: what the linker actually produced"

# Runs the inspector and prints its "status<TAB>name<TAB>detail" lines.
# Its own stderr goes to a file rather than into the results: a
# traceback parsed as a check result is a check that neither passed nor
# failed, and the caller needs to be able to tell those apart.
CHECKER_ERR="$WORK/checker.err"
run_checks() {   # <binary> [extra flags]
    local bin="$1"; shift
    python3 "$HERE/hardening_checks.py" "$bin" "$@" 2>"$CHECKER_ERR" || true
}

CHECKS="$WORK/checks.txt"
run_checks "$ROOT/sarm" > "$CHECKS"
if [ -s "$CHECKER_ERR" ]; then
    nope "hardening_checks.py wrote to stderr: $(head -1 "$CHECKER_ERR")"
fi
while IFS=$'\t' read -r status name detail; do
    case "$status" in
        ok)   ok "$name — $detail" ;;
        fail) nope "$name — $detail" ;;
        skip) skip "$name — $detail" ;;
        *)    nope "unreadable check output: $status $name $detail" ;;
    esac
done < "$CHECKS"

# Vacuity: a checker that printed nothing would have reported no
# failures either.
if [ "$(wc -l < "$CHECKS")" -lt 5 ]; then
    nope "hardening_checks.py produced $(wc -l < "$CHECKS") line(s) — expected at least 5"
fi

# ══════════════════════════════════════════════════════════════════════
#   2. the process
# ══════════════════════════════════════════════════════════════════════
head_ "process: what the kernel did with it"

# The server runs inside a subshell, because it needs a working
# directory of its own and a core-dump limit set before exec. That makes
# $! the subshell rather than the server on some shells, so SPID is
# resolved separately — and stop_server kills both. Killing only the
# subshell leaves an orphaned server holding the port, which the next
# readiness probe then answers: every later check would be reading a
# process this script no longer has a handle on.
SPID=""
start_server() {   # <core-limit> — the `ulimit -c` value for the server
    ( cd "$WORK" && ulimit -c "${1:-0}" 2>/dev/null; \
      "$ROOT/sarm" "$HOST_PORT" >/dev/null 2>&1 ) &
    SERVER_PID=$!
    local deadline=$((SECONDS + 15))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${HOST_PORT}/"; then
            SPID=$(pgrep -P "$SERVER_PID" -x sarm 2>/dev/null | head -1 || true)
            [ -n "$SPID" ] || SPID="$SERVER_PID"
            return 0
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || return 1
        sleep 0.25
    done
    return 1
}

stop_server() {
    [ -n "$SPID" ] && kill "$SPID" 2>/dev/null || true
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
    SPID=""
    # Give the listening socket time to go away before the next bind().
    sleep 0.3
}

if start_server 0; then
    if [ "$OS" = "Darwin" ]; then
        MAPS="$WORK/vmmap.txt"
        if vmmap "$SPID" > "$MAPS" 2>/dev/null; then
            SELF=$(grep -F "$ROOT/sarm" "$MAPS" || true)
            DC=$(echo "$SELF" | grep '__DATA_CONST' | head -1)
            if [ -z "$DC" ]; then
                nope "no __DATA_CONST mapping in the running server"
            elif echo "$DC" | grep -q 'r--/'; then
                ok "__DATA_CONST is mapped read-only in the running server"
            else
                nope "__DATA_CONST is mapped $(echo "$DC" | grep -oE '[rwx-]{3}/[rwx-]{3}' | head -1)"
            fi
            if echo "$SELF" | grep -qE 'rwx/'; then
                nope "the server has a writable+executable mapping"
            else
                ok "no writable+executable mapping in the running server"
            fi
        else
            skip "process mappings (vmmap could not read pid $SPID)"
            skip "writable+executable mapping check"
        fi
        # macOS gives no way to read another process's rlimits, so the
        # core-dump limit is checked statically below and by the crash
        # test that follows it.
    else
        MAPS="/proc/$SPID/maps"
        if [ -r "$MAPS" ]; then
            if grep -q "r--p .*sarm" "$MAPS"; then
                ok "the read-only segment is mapped r--p in the running server"
            else
                nope "no r--p mapping of the binary in the running server"
            fi
            if grep -qE 'rwx' "$MAPS"; then
                nope "the server has a writable+executable mapping"
            else
                ok "no writable+executable mapping in the running server"
            fi
            if grep -qE '^[0-9a-f]+-[0-9a-f]+ rw-p .*\[stack\]' "$MAPS"; then
                ok "the stack is mapped non-executable"
            else
                nope "the stack mapping is not rw-p: $(grep '\[stack\]' "$MAPS" || echo 'not found')"
            fi
        else
            skip "process mappings (cannot read $MAPS)"
        fi
        if [ -r "/proc/$SPID/limits" ]; then
            CORE=$(awk '/Max core file size/ {print $6}' "/proc/$SPID/limits")
            if [ "$CORE" = "0" ]; then
                ok "the running server's core-dump limit is zero"
            else
                nope "the running server's core-dump limit is $CORE"
            fi
        else
            skip "core-dump limit (cannot read /proc/$SPID/limits)"
        fi
    fi
    stop_server
else
    stop_server
    nope "the server did not come up on port $HOST_PORT — no process checks ran"
fi

# ══════════════════════════════════════════════════════════════════════
#   3. cores
# ══════════════════════════════════════════════════════════════════════
head_ "cores: a crash discloses nothing"

# The static half first: it holds on every platform and for every
# workload, because the syscall number is an immediate in the binary.
AUDIT_JSON="$WORK/audit.json"
if python3 "$ROOT/scripts/syscall_audit.py" --binary "$ROOT/sarm" --json \
        > "$AUDIT_JSON" 2>/dev/null; then
    if python3 - "$AUDIT_JSON" <<'PYEOF'
import json, sys
made = set(json.load(open(sys.argv[1])).get("binary", {}))
sys.exit(0 if made & {"setrlimit", "prlimit64"} else 1)
PYEOF
    then
        ok "the built binary contains the RLIMIT_CORE call"
    else
        nope "the built binary makes no setrlimit/prlimit64 call — nothing sets RLIMIT_CORE"
    fi
else
    skip "RLIMIT_CORE call site (the syscall audit did not run)"
fi

# The dynamic half. Does this machine dump cores at all? A control that
# should dump decides whether the server's not dumping means anything.
CORE_DIR="$WORK/cores"
mkdir -p "$CORE_DIR"
CTL_SRC="$WORK/crasher.c"
cat > "$CTL_SRC" <<'EOF'
int main(void) { volatile int *p = 0; *p = 1; return 0; }
EOF
CONTROL_DUMPED=0
if cc "$CTL_SRC" -o "$WORK/crasher" >/dev/null 2>&1; then
    # Run it from a shell of its own: the "Segmentation fault (core
    # dumped)" line is the *parent* shell reporting a job's death, so
    # only a separate shell's stderr can be redirected away from ours.
    bash -c "cd '$CORE_DIR' && ulimit -c unlimited 2>/dev/null; '$WORK/crasher'; exit 0" \
        >/dev/null 2>&1 || true
    sleep 0.5
    if ls "$CORE_DIR"/core* >/dev/null 2>&1 || \
       ls /cores/core.* >/dev/null 2>&1; then
        CONTROL_DUMPED=1
    fi
fi

if [ "$CONTROL_DUMPED" -eq 0 ]; then
    skip "crashing child leaves no core (this machine dumps no cores even without a limit, so the check would prove nothing)"
else
    # /cores is where macOS puts them; Linux's default core_pattern
    # writes into the process's working directory, which is $WORK.
    BEFORE=$( { ls /cores 2>/dev/null || true; } | wc -l | tr -d ' ')
    if start_server unlimited; then
        # Hold a connection open so there is a forked child to crash.
        ( exec 3<>"/dev/tcp/127.0.0.1/$HOST_PORT"; printf 'GET /' >&3; sleep 3 ) &
        HOLDER=$!
        sleep 0.7
        CHILD=$(pgrep -P "$SPID" -x sarm 2>/dev/null | head -1 || true)
        if [ -n "$CHILD" ]; then
            kill -SEGV "$CHILD" 2>/dev/null || true
            sleep 1
            AFTER=$( { ls /cores 2>/dev/null || true; } | wc -l | tr -d ' ')
            DUMPED=$(find "$WORK" -maxdepth 1 -type f -name 'core*' | head -1)
            if [ -n "$DUMPED" ] || [ "$AFTER" != "$BEFORE" ]; then
                nope "a SIGSEGV'd connection child dumped core"
            else
                ok "a SIGSEGV'd connection child left no core (control: cores are enabled here)"
            fi
        else
            skip "crashing child (no forked connection child to signal)"
        fi
        kill "$HOLDER" 2>/dev/null || true
        stop_server
    else
        stop_server
        nope "the server did not come up for the core-dump check"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
#   4. controls
# ══════════════════════════════════════════════════════════════════════
if [ "$DO_CONTROLS" -eq 1 ]; then
    head_ "controls: the checks above can fail"

    # A binary whose constants are back in writable .data.
    NORO="$WORK/sarm-no-rodata"
    if (cd "$ROOT" && make -s variant BIN="$NORO" \
            VARIANT_CFLAGS=-DSARM_NO_RODATA >/dev/null 2>&1); then
        OUT=$(run_checks "$NORO")
        if echo "$OUT" | grep -q "^fail	rodata-const"; then
            ok "constants in writable .data are caught (rodata-const fails)"
        else
            nope "a binary with every constant in writable .data passed rodata-const"
        fi
        if echo "$OUT" | grep -q "^ok	wx"; then
            ok "the unrelated checks still pass on that control (wx)"
        else
            nope "the rodata control failed a check it should not have (wx)"
        fi
    else
        skip "writable-constants control (the variant build failed)"
    fi

    # A binary linked without the hardening flags.
    if [ "$OS" = "Darwin" ]; then
        # ld64 ignores -no_pie on arm64 — there is no such thing as a
        # non-PIE arm64 macOS executable, so the pie check cannot be
        # made to fail here. It is checked against the ELF control on
        # Linux (and by --docker below), where it can be.
        skip "unhardened-link control (arm64 macOS cannot link a non-PIE executable)"
    else
        UNH="$WORK/sarm-unhardened"
        if (cd "$ROOT" && make -s variant BIN="$UNH" LDFLAGS="" >/dev/null 2>&1); then
            OUT=$(run_checks "$UNH")
            MISSED=""
            for name in pie noexecstack rodata-segment; do
                echo "$OUT" | grep -q "^fail	$name" || MISSED="$MISSED $name"
            done
            if [ -z "$MISSED" ]; then
                ok "a binary linked without the hardening flags fails pie, noexecstack and rodata-segment"
            else
                nope "the unhardened control passed:$MISSED"
            fi
        else
            skip "unhardened-link control (the variant build failed)"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════
#   5. the container's binary
# ══════════════════════════════════════════════════════════════════════
if [ "$DO_DOCKER" -eq 1 ]; then
    head_ "container: the Linux binary that ships"

    if ! command -v docker >/dev/null 2>&1; then
        skip "container binary (docker not installed)"
    elif ! docker info >/dev/null 2>&1; then
        skip "container binary (docker is installed but not running)"
    else
        IMG="sarm-hardening-check"
        if (cd "$ROOT" && docker build -q -t "$IMG" . >/dev/null 2>&1); then
            CID=$(docker create "$IMG")
            docker cp "$CID:/sarm" "$WORK/sarm-linux" >/dev/null 2>&1 || true
            docker rm "$CID" >/dev/null 2>&1 || true
            if [ -f "$WORK/sarm-linux" ]; then
                # The shipped binary is `make production`, i.e. stripped
                # of local symbols, so the symbol-placement checks have
                # less to work with than on the unstripped host build.
                # Everything else applies unchanged.
                run_checks "$WORK/sarm-linux" --allow-missing-symbols \
                    > "$WORK/container.txt"
                if [ -s "$CHECKER_ERR" ]; then
                    nope "container: the inspector failed: $(head -1 "$CHECKER_ERR")"
                fi
                SEEN=0
                while IFS=$'\t' read -r status name detail; do
                    SEEN=$((SEEN + 1))
                    case "$status" in
                        ok)   ok "container: $name — $detail" ;;
                        fail) nope "container: $name — $detail" ;;
                        skip) skip "container: $name — $detail" ;;
                        *)    nope "container: unreadable result: $status $name" ;;
                    esac
                done < "$WORK/container.txt"
                [ "$SEEN" -ge 7 ] || \
                    nope "container: only $SEEN check(s) ran on the shipped binary"
            else
                nope "could not extract /sarm from the container image"
            fi
        else
            nope "docker build failed — the container's binary was not inspected"
        fi
    fi
fi

# ── summary ─────────────────────────────────────────────────────────
if [ $QUIET -eq 1 ]; then
    if [ $FAIL -eq 0 ]; then
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" "hardening" "$PASS"
    else
        printf '%s' "$LOG"
        printf "── %-37s ... (%3d failed) ${RED}✗${CLR}\n" "hardening" "$FAIL"
    fi
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    printf "  Passed:  ${GRN}%d${CLR}\n" "$PASS"
    printf "  Failed:  ${RED}%d${CLR}\n" "$FAIL"
    printf "  Skipped: ${YLW}%d${CLR}\n" "$SKIP"
    echo "═══════════════════════════════════════════════════════════════"
fi

[ $FAIL -eq 0 ] || exit 1
exit 0
