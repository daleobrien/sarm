#!/usr/bin/env bash
# packages.sh <role> — install the toolchain this box's job needs.
#
#   server   build and run sarm: compiler, OpenSSL headers, the smoke-test
#            clients. No profiler — a small VM has no PMU to profile with.
#   load     drive load at something else: wrk, h2load, and enough of a
#            toolchain to build wrk when the release does not package it.
#   metal    everything, including the profiling stack. This is the
#            c6g.metal box that run_perf_suite.sh measures on.
#
# The split exists because provisioning is billed wall-clock: a two-box
# RPS run needs no bpftrace on either side and no compiler-plus-OpenSSL on
# the load generator, and every package skipped is download time that is
# not paid twice.
#
# Run on the instance. Safe to re-run.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROLE="${1:-metal}"
case "$ROLE" in server|load|metal) ;; *) die "unknown role '$ROLE' (server|load|metal)" ;; esac

quiesce_background_updates
wait_for_apt_lock
apt_bootstrap

say "Installing packages ($ROLE)"
apt_run update || { apt_log_tail; die "apt update failed — see $APT_LOG"; }

# Split into "must have" and "nice to have" so one unavailable package in
# a fresh release does not abort the provisioning run.
#
# BASE is what every role needs: something to build with, something to
# fetch with, and the process tools the benchmark scripts call by name
# (taskset, pgrep, fuser).
REQUIRED=(
    build-essential binutils make git curl ca-certificates pkg-config
    openssl gzip jq
    util-linux procps psmisc  # taskset, pgrep, fuser
)
OPTIONAL=()
# Package names that may or may not exist in this release. Every one of
# these is filtered against the archive before it is offered to apt.
CANDIDATES=()

case "$ROLE" in
    server|metal)
        # sarm's own build inputs, and the clients its smoke test uses.
        REQUIRED+=(python3 python3-pip libssl-dev zlib1g-dev nghttp2-client)
        ;;
esac
case "$ROLE" in
    load|metal)
        # h2load is the HTTP/2 load generator; unzip is wrk's Makefile
        # unpacking LuaJIT.
        REQUIRED+=(nghttp2-client unzip)
        # wrk is in universe on some releases and absent on others; the
        # fallback is to build it, which is what loadgen.sh does.
        CANDIDATES+=(wrk)
        CANDIDATES+=(numactl sysstat)
        ;;
esac
case "$ROLE" in
    metal)
        OPTIONAL+=(
            bpftrace bpfcc-tools   # uprobe call counts, off-CPU
            valgrind               # cachegrind/callgrind: deterministic A/B of two .S variants
            gdb lldb
            numactl sysstat linux-tools-common
            hyperfine
        )
        # perf is packaged per kernel flavour and the names drift between
        # releases — EC2 Ubuntu runs the -aws kernel, so the tools may be
        # in linux-tools-aws, or in the version-pinned package, or in
        # neither. Every plausible name is listed and the archive decides
        # which exist.
        CANDIDATES+=(
            "linux-tools-$(uname -r)" linux-tools-aws
            linux-tools-generic linux-aws-tools-common
        )
        ;;
esac

# One apt call for the lot. The obstacle to that is that a single name the
# archive has never heard of fails the entire batch, and the perf and wrk
# lists are deliberately full of names that may not exist — which is why
# they used to be installed one at a time, each paying a full round of apt
# startup and a serialised download.
#
# apt-cache answers "does this exist" from the local index, with no
# network and no privileges, so the batch can be filtered before it is
# ever submitted. REQUIRED is deliberately NOT filtered: a required
# package missing from the archive is a failure worth stopping on, not
# something to quietly drop.
#
# The probe itself is checked against a package that must exist before its
# answers are trusted — it has been wrong once. If it cannot see that one,
# the filter is broken rather than the archive being empty, and the right
# move is to submit everything and let apt decide.
MAYBE=()
SKIPPED=""
ALL_CANDIDATES=(${OPTIONAL[@]+"${OPTIONAL[@]}"} ${CANDIDATES[@]+"${CANDIDATES[@]}"})
if [ ${#ALL_CANDIDATES[@]} -gt 0 ]; then
    if in_archive "${REQUIRED[0]}"; then
        for pkg in "${ALL_CANDIDATES[@]}"; do
            if in_archive "$pkg"; then
                MAYBE+=("$pkg")
            else
                SKIPPED="$SKIPPED $pkg"
            fi
        done
        [ -n "$SKIPPED" ] && info "not in this release's archive:$SKIPPED"
    else
        warn "apt-cache cannot see '${REQUIRED[0]}', so it cannot be trusted to say"
        warn "which optional packages exist — offering the lot to apt instead."
        MAYBE=("${ALL_CANDIDATES[@]}")
    fi
fi

# The required/optional split still decides what a failure MEANS, which is
# the only reason to keep it: on the rare batch failure (a package that
# exists but cannot be configured, a held dependency) the sets are re-run
# on their own terms rather than the whole run being lost.
ALL=("${REQUIRED[@]}" ${MAYBE[@]+"${MAYBE[@]}"})
if apt_run install "${ALL[@]}"; then
    info "${#ALL[@]} packages"
else
    info "the combined install failed — separating the required from the rest"
    apt_run install "${REQUIRED[@]}" || {
        apt_log_tail 25
        die "could not install the required packages — see $APT_LOG"
    }
    info "${#REQUIRED[@]} required packages"
    for pkg in ${MAYBE[@]+"${MAYBE[@]}"}; do
        apt_run install "$pkg" || warn "optional package '$pkg' unavailable — continuing without it"
    done
fi
info "apt log: $APT_LOG"
