#!/usr/bin/env bash
# build_sarm.sh — get the sources, generate the untracked build inputs,
# build, and prove the binary serves all three protocols.
#
# Environment overrides:
#   SARM_REPO=<git url>     default https://github.com/daleobrien/sarm.git
#   SARM_BRANCH=<branch>    default main
#   SARM_DIR=<path>         default $HOME/sarm
#
# Run on the instance. Safe to re-run.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

REPO_URL="${SARM_REPO:-https://github.com/daleobrien/sarm.git}"
BRANCH="${SARM_BRANCH:-main}"
DEST="$SARM_DEST"

# ── sources ───────────────────────────────────────────────────────────
say "Fetching sarm"
if [ -d "$DEST" ] && [ ! -d "$DEST/.git" ] && [ -f "$DEST/Makefile" ]; then
    # An uploaded working tree rather than a checkout — this is how the
    # orchestration scripts deliver the sources, local edits included.
    # There is nothing to fetch; use what is there.
    info "using the existing (non-git) tree at $DEST"
elif [ -d "$DEST/.git" ]; then
    info "updating existing checkout at $DEST"
    git -C "$DEST" fetch --quiet origin
    git -C "$DEST" checkout --quiet "$BRANCH"
    git -C "$DEST" pull --quiet --ff-only origin "$BRANCH" || warn "could not fast-forward; leaving the checkout as-is"
else
    info "cloning $REPO_URL -> $DEST"
    if ! git clone --quiet --branch "$BRANCH" "$REPO_URL" "$DEST"; then
        die "clone failed. If the repository is private, set up credentials first
        (gh auth login, or a deploy key in ~/.ssh) and re-run with
        SARM_REPO=git@github.com:daleobrien/sarm.git"
    fi
fi
info "HEAD: $(git -C "$DEST" log --oneline -1 2>/dev/null || echo 'uploaded working tree, no git history')"

# A fresh clone is missing two generated inputs, both gitignored: the TLS
# test certificate (certs/*.pem, *.der — the Makefile's cert_data.S rule
# depends on them, so the build fails outright without it) and the
# rendered error pages under www/err/, which get embedded into the binary.
say "Generating the untracked build inputs"
if [ -f "$DEST/certs/cert.pem" ] && [ -f "$DEST/certs/cert.der" ]; then
    info "certificate already present"
else
    ( cd "$DEST/certs" && ./generate.sh -f ) >/dev/null 2>&1 \
        || die "certs/generate.sh failed — it needs OpenSSL 3.x (genpkey -algorithm EC, -addext)"
    info "generated certs/key.pem, cert.pem, cert.der (self-signed P-256, CN=localhost)"
fi
if [ -f "$DEST/err/template.html" ]; then
    ( cd "$DEST" && sh build_err_pages.sh ) >/dev/null 2>&1 \
        && info "rendered www/err/*.html" \
        || warn "build_err_pages.sh failed — the server will build but serve no styled error pages"
fi

# ── build ─────────────────────────────────────────────────────────────
say "Building"
# `make production`, which is `make` followed by `strip -x`. That is both
# the shipped artifact and, on Linux, the better thing to profile:
#
#   * `strip -x` is --discard-all, which removes non-global symbols and
#     KEEPS the ~170 global function symbols perf attributes samples to.
#   * The sources write ~180 internal branch targets as `Lfoo:` rather
#     than `.Lfoo:`. GNU as drops the dotted form but emits the undotted
#     one as a real local symbol, and since no function carries a `.size`
#     directive, each of those labels swallows the address range after it
#     — fragmenting a function's self time across `Lloop`, `Lbyte_loop`
#     and friends. Stripping discards exactly those, folding the samples
#     back into the enclosing function.
#
# Stripping changes no instruction and no load-segment layout, so it costs
# nothing in throughput. If a future strip ever takes the globals too, the
# check below catches it and the fallback rebuilds unstripped.
make -C "$DEST" clean >/dev/null 2>&1 || true
make -C "$DEST" production 2>&1 | tail -20
[ -x "$DEST/sarm" ] || die "build produced no ./sarm binary"

# `|| true`, not `|| echo 0`: grep -c PRINTS 0 on no match and ALSO
# exits 1, so the echo appends a second line and the test below sees
# "0\n0" -- "integer expected", and the rebuild this guard exists to
# trigger is then silently skipped. grep -c always prints exactly one
# number, including on empty input, so nothing needs to supply a default.
SYMS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' T ' || true)
if [ "$SYMS" -lt 50 ]; then
    warn "the production build left only ${SYMS} global symbols — perf could not"
    warn "attribute samples. Rebuilding unstripped instead."
    make -C "$DEST" clean >/dev/null 2>&1 || true
    make -C "$DEST" 2>&1 | tail -5
    SYMS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' T ' || true)
fi
# Zero is the EXPECTED answer here -- a clean `strip -x` leaves no local
# labels at all -- so this is the one that actually fired.
LOCALS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' t ' || true)
info "binary: $DEST/sarm ($(stat -c %s "$DEST/sarm") bytes)"
info "symbols: ${SYMS} global text, ${LOCALS} local"
if [ "$LOCALS" -gt 0 ]; then
    warn "${LOCALS} local labels survive and will fragment per-function attribution"
fi

# ── smoke test ────────────────────────────────────────────────────────
say "Smoke test"
PORT="${SARM_SMOKE_PORT:-8099}"
"$DEST/sarm" "$PORT" >/dev/null 2>&1 3>&- 4>&- &
SMOKE_PID=$!
trap 'kill "$SMOKE_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
    curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null && break
    sleep 0.1
done
if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:${PORT}/"; then
    info "HTTP/1.1 OK"
else
    die "the server did not answer on 127.0.0.1:${PORT}"
fi
if command -v h2load >/dev/null 2>&1; then
    h2load --no-tls-proto=h2c -n2 -c1 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 \
        && info "HTTP/2 (h2c) OK" || warn "h2c smoke test failed"
    h2load -n2 -c1 "https://127.0.0.1:${PORT}/" >/dev/null 2>&1 \
        && info "HTTP/2 + TLS OK" || warn "TLS smoke test failed"
fi
kill "$SMOKE_PID" 2>/dev/null || true
trap - EXIT
