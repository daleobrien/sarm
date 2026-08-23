#!/usr/bin/env bash
# sarm syscall allowlist harness (docs/SECURITY.md §6, Step 11)
#
# Step 11 asks for a syscall allowlist and a test that a traced workload
# never successfully opens a file. This runs that test twice over, at two
# different strengths, because sarm can support the stronger claim and
# the stronger claim is the one worth having:
#
#   static   scripts/syscall_audit.py reads every `svc` site out of the
#            built binary and every `SCWINUM SYS_x` out of src/, and
#            checks both against tests/syscall_allowlist.txt. Every
#            syscall number in this tree is a compile-time immediate
#            (the SCWINUM macro in src/defs.S), there is no libc and no
#            dynamic linking, so the set of syscalls the binary *can*
#            make is decidable by reading it. That is a statement about
#            all possible workloads, not about the one that ran:
#
#              a remote attacker cannot trick the server into reading a
#              file, because the binary contains no instruction that
#              asks the kernel to open one.
#
#            Always runs, on any platform.
#
#   dynamic  the same claim, checked the way Step 11 describes it: run
#            the server under a syscall tracer, drive normal and
#            malformed traffic through it (tests/hostile_workload.py —
#            the same traffic the Step 10 leak probe uses), and assert
#            that no open/openat/execve/unlink appears in the trace, and
#            that every syscall that does appear is on the allowlist.
#
#            Needs a tracer that can follow forks: strace on Linux,
#            dtruss (and hence root, with SIP allowing it) on macOS.
#            Where none is available the check is reported as skipped
#            rather than passed — a check that cannot run has not run.
#
# Filesystem non-access (§15) is checked alongside: the server is
# started in an empty directory with no readable files in it, so a code
# path that tried to open something relative would fail visibly rather
# than quietly finding the repo's own files.
#
# Usage:
#   ./test_syscalls.sh                # build + test
#   ./test_syscalls.sh --no-build
#   ./test_syscalls.sh --cases 500    # longer traced workload
#   ./test_syscalls.sh --port 8090

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

# ── args ────────────────────────────────────────────────────────────
DO_BUILD=1
HOST_PORT=0
CASES=${SARM_SYSCALL_CASES:-120}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --port)     HOST_PORT="$2"; shift ;;
        --cases)    CASES="$2"; shift ;;
        --quiet)    QUIET=1 ;;
        -h|--help)  sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$HOST_PORT" -eq 0 ]; then
    HOST_PORT=$(( 8880 + ($$ % 200) ))
fi

for cmd in python3 make curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "$0: '$cmd' not found — needed for the test harness" >&2
        exit 2
    fi
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sarm-syscall.XXXXXX")

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

if [ ! -x "$ROOT/sarm" ]; then
    echo "$0: '$ROOT/sarm' not found or not executable — run 'make' first" >&2
    exit 2
fi

# ══════════════════════════════════════════════════════════════════════
#   1. the static audit
# ══════════════════════════════════════════════════════════════════════
if [ $QUIET -eq 0 ]; then
    echo "── static: every svc site in the binary ──"
fi

AUDIT_OUT="$WORK/audit.txt"
if python3 "$ROOT/scripts/syscall_audit.py" --binary "$ROOT/sarm" \
        --quiet >"$AUDIT_OUT" 2>&1; then
    ok "$(sed -e 's/^ *//' -e 's/\x1b\[[0-9;]*m//g' "$AUDIT_OUT" | grep -v '^$' | tail -1 | sed 's/^✓ //')"
else
    nope "static syscall audit failed:"
    while IFS= read -r line; do
        if [ $QUIET -eq 0 ]; then echo "      $line"; else _log "      $line"; fi
    done < "$AUDIT_OUT"
fi

# The audit's own negative control: a binary that does call open must be
# rejected. Without it a broken parser — one that finds no svc sites at
# all, or resolves none of them — reports a clean audit for a server
# that opens whatever it likes.
SELFTEST_SRC="$WORK/opens_a_file.S"
SELFTEST_BIN="$WORK/opens_a_file"
if [ "$(uname -s)" = "Darwin" ]; then
    cat > "$SELFTEST_SRC" <<'EOF'
.global _main
.align 2
_main:
    mov x16, #5          // SYS_open
    svc #0x80
    mov x16, #1          // SYS_exit
    svc #0x80
EOF
else
    cat > "$SELFTEST_SRC" <<'EOF'
.global main
.align 2
main:
    mov x8, #56          // SYS_openat
    svc #0
    mov x8, #93          // SYS_exit
    svc #0
EOF
fi
# An object file, not a linked executable: the audit disassembles what
# it is given, and an object needs no C runtime — which keeps the
# control working on a toolchain that has an assembler but no libc
# (Alpine without musl-dev, the container this project builds in).
if cc -c "$SELFTEST_SRC" -o "$SELFTEST_BIN" >/dev/null 2>&1; then
    if python3 "$ROOT/scripts/syscall_audit.py" --binary "$SELFTEST_BIN" \
            --quiet >"$WORK/selftest.txt" 2>&1; then
        nope "the audit passed a binary that calls open — it cannot detect one"
    else
        if grep -q "forbidden syscall" "$WORK/selftest.txt"; then
            ok "the audit rejects a binary that calls open (negative control)"
        else
            nope "the audit rejected the control binary, but not for calling open"
        fi
    fi
else
    skip "audit negative control (no working C toolchain)"
fi

# ══════════════════════════════════════════════════════════════════════
#   2. the traced workload
# ══════════════════════════════════════════════════════════════════════
if [ $QUIET -eq 0 ]; then
    echo ""
    echo "── dynamic: a traced normal and malformed workload ──"
fi

# An empty directory with nothing in it to find (SECURITY.md §6): if
# some path did try to open a file by relative name, it would fail here
# rather than quietly succeeding against the repo.
RUNDIR="$WORK/empty"
mkdir -p "$RUNDIR"

TRACER=""
TRACE_LOG="$WORK/trace.txt"
if command -v strace >/dev/null 2>&1; then
    TRACER="strace"
elif [ "$(uname -s)" = "Darwin" ] && command -v dtruss >/dev/null 2>&1 \
        && [ "$(id -u)" = "0" ]; then
    TRACER="dtruss"
fi

run_workload() {
    local port="$1"
    local ready=0
    local deadline=$((SECONDS + 15))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
            ready=1; break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then return 1; fi
        sleep 0.25
    done
    [ "$ready" -eq 1 ] || return 1
    python3 "$HERE/hostile_workload.py" "$port" --cases "$CASES" --quiet \
        >/dev/null 2>&1 || true
    return 0
}

case "$TRACER" in
strace)
    (cd "$RUNDIR" && strace -f -qq -e trace=all -o "$TRACE_LOG" \
        "$ROOT/sarm" "$HOST_PORT" >/dev/null 2>&1) &
    SERVER_PID=$!
    if run_workload "$HOST_PORT"; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        sleep 0.5
        if [ -s "$TRACE_LOG" ]; then
            # The exec of the server binary itself is the tracer
            # launching it, not the server calling execve — it happens
            # before a single instruction of sarm has run. Every other
            # execve, of anything at all, stays a finding.
            grep -vE 'execve\("[^"]*sarm"' "$TRACE_LOG" > "$WORK/trace.f" || true
            # Names as strace prints them, at the start of a line after
            # the pid: `1234  openat(AT_FDCWD, ...`.
            sed -E 's/^[0-9]+ +//' "$WORK/trace.f" \
                | grep -oE '^[a-z_0-9]+\(' | tr -d '(' | sort -u \
                > "$WORK/seen.txt"
            BAD=$(grep -E '^(open|openat|execve|execveat|unlink|unlinkat|rename|renameat|mkdir|mkdirat|creat|getdents64|chdir|chroot|statx|newfstatat)$' "$WORK/seen.txt" || true)
            if [ -z "$BAD" ]; then
                ok "traced workload: no filesystem-opening syscall at all"
            else
                nope "traced workload opened files: $(echo "$BAD" | tr '\n' ' ')"
            fi
            # Vacuity: a trace that never got as far as accepting a
            # connection would pass both checks above by having nothing
            # in it. The workload is hundreds of connections, so the
            # accept/read/write triple must be there.
            MISSING=""
            for want in accept accept4 read write; do
                grep -qx "$want" "$WORK/seen.txt" || MISSING="$MISSING $want"
            done
            case "$MISSING" in
                *read*|*write*)
                    nope "the trace is missing$MISSING — the workload never "\
"reached the server, so the checks above proved nothing" ;;
                *)
                    ok "traced workload: the server accepted, read and wrote "\
"under the tracer" ;;
            esac

            OFF=$(python3 "$HERE/trace_check.py" \
                     "$ROOT/tests/syscall_allowlist.txt" "$WORK/seen.txt")
            if [ -z "$OFF" ]; then
                ok "traced workload: every syscall seen is on the allowlist"
            else
                nope "traced workload used syscalls that are not allowlisted: $OFF"
            fi
        else
            nope "strace produced no output"
        fi
    else
        nope "server did not come up under strace"
        kill "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""
    fi
    ;;
dtruss)
    (cd "$RUNDIR" && dtruss -f "$ROOT/sarm" "$HOST_PORT" >/dev/null 2>"$TRACE_LOG") &
    SERVER_PID=$!
    if run_workload "$HOST_PORT"; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        sleep 0.5
        BAD=$(grep -oE '\b(open|openat|open_nocancel|execve|unlink|rename|mkdir)\(' \
              "$TRACE_LOG" 2>/dev/null | tr -d '(' | sort -u || true)
        if [ -z "$BAD" ]; then
            ok "traced workload: no filesystem-opening syscall at all"
        else
            nope "traced workload opened files: $(echo "$BAD" | tr '\n' ' ')"
        fi
    else
        nope "server did not come up under dtruss"
        kill "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""
    fi
    ;;
*)
    if [ "$(uname -s)" = "Darwin" ]; then
        skip "syscall trace — macOS needs dtruss as root (and SIP allowing dtrace); the static audit above covers the same claim for every workload, not just this one"
    else
        skip "syscall trace — no strace on PATH"
    fi
    ;;
esac

# ══════════════════════════════════════════════════════════════════════
#   3. filesystem non-access, without a tracer (SECURITY.md §6)
# ══════════════════════════════════════════════════════════════════════
# Even where no tracer is available, one observable consequence of "the
# server never opens a file" is testable directly: start it in an empty
# read-only directory, serve the whole hostile workload out of it, and
# check that it worked and that nothing appeared on disk.
if [ $QUIET -eq 0 ]; then
    echo ""
    echo "── filesystem: an empty read-only working directory ──"
fi

RO="$WORK/readonly"
mkdir -p "$RO"
chmod 500 "$RO"
PORT2=$((HOST_PORT + 1))
(cd "$RO" && "$ROOT/sarm" "$PORT2" >/dev/null 2>&1) &
SERVER_PID=$!
if run_workload "$PORT2"; then
    if curl -s --max-time 3 -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:${PORT2}/" | grep -q 200; then
        ok "served its embedded assets from an empty read-only directory"
    else
        nope "could not serve / from an empty read-only directory"
    fi
    LEFT=$(ls -A "$RO" 2>/dev/null || true)
    if [ -z "$LEFT" ]; then
        ok "created no files while serving the hostile workload"
    else
        nope "files appeared in the working directory: $LEFT"
    fi
else
    nope "server did not start in an empty read-only directory"
fi
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
chmod 700 "$RO" 2>/dev/null || true

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
        printf "${RED}Syscall allowlist checks failed!${CLR}\n"
        exit 1
    else
        printf "── %-37s ... (%3d checks) ${GRN}✓${CLR}\n" \
               "syscall allowlist" "$PASS"
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
        printf "${RED}Syscall allowlist checks failed!${CLR}\n"
        exit 1
    fi
    echo ""
    printf "${GRN}The server can only make allowlisted syscalls, and opens no files.${CLR}\n"
    exit 0
fi
