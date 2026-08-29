#!/usr/bin/env bash
# loadgen.sh — make sure this box can actually generate load.
#
# h2load comes from nghttp2-client (installed by packages.sh). wrk is in
# universe on some releases and absent on others, so it is built here when
# the archive did not have it.
#
# Run on the instance. Safe to re-run.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

# ── wrk (HTTP/1.1 load) ───────────────────────────────────────────────
if command -v wrk >/dev/null 2>&1; then
    info "wrk: $(command -v wrk)"
else
    say "Building wrk from source"
    info "not packaged for this release"
    # Everything else on the box is already provisioned by this point, so
    # a wrk that will not build costs the HTTP/1.1 load generator, not the
    # run.
    WRK_LOG=/tmp/sarm-wrk-build.log
    if { rm -rf /tmp/wrk-build &&
         git clone --depth 1 -q https://github.com/wg/wrk.git /tmp/wrk-build &&
         make -C /tmp/wrk-build &&
         sudo install -m 0755 /tmp/wrk-build/wrk /usr/local/bin/wrk
       } >"$WRK_LOG" 2>&1; then
        rm -rf /tmp/wrk-build
        info "installed to /usr/local/bin/wrk"
    else
        sed 's/^/     /' "$WRK_LOG" | tail -15
        warn "wrk failed to build — see $WRK_LOG. h2load still covers HTTP/2;"
        warn "the HTTP/1.1 leg of rps_bench.sh will not run without wrk."
    fi
fi

# ── h2load (HTTP/2, with and without TLS) ─────────────────────────────
if command -v h2load >/dev/null 2>&1; then
    info "h2load: $(h2load --version 2>&1 | head -1)"
else
    warn "h2load is missing — install nghttp2-client. Both HTTP/2 legs of"
    warn "rps_bench.sh need it, and they are the interesting ones."
fi
