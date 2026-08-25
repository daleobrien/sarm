#!/usr/bin/env bash
# setup_ec2_metal.sh — provision an Ubuntu 26.04 LTS arm64 c6g.metal box
# for measuring and optimising sarm.
#
# Installs the measurement toolchain, clones and builds sarm, tunes the
# kernel for a one-process-per-connection server under load, and verifies
# that the Neoverse N1 PMU is actually readable (the whole reason to rent
# metal rather than a shared instance).
#
# Standalone by design — it is the script you run *before* the repo
# exists, so it can be fetched on its own:
#
#   curl -fsSLO https://raw.githubusercontent.com/daleobrien/sarm/main/scripts/aws/setup_ec2_metal.sh
#   chmod +x setup_ec2_metal.sh
#   ./setup_ec2_metal.sh
#
# Environment overrides:
#   SARM_REPO=<git url>     default https://github.com/daleobrien/sarm.git
#   SARM_BRANCH=<branch>    default main
#   SARM_DIR=<path>         default $HOME/sarm
#
# Reboot is not required. Re-running is safe and idempotent.

set -euo pipefail

REPO_URL="${SARM_REPO:-https://github.com/daleobrien/sarm.git}"
BRANCH="${SARM_BRANCH:-main}"
DEST="${SARM_DIR:-$HOME/sarm}"

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '\033[1;33m   WARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

# ── 0. Sanity: is this the machine we think it is? ────────────────────
say "Checking the host"

[ "$(uname -m)" = "aarch64" ] || die "not aarch64 — sarm is ARM64 assembly, there is nothing to run here"

. /etc/os-release 2>/dev/null || true
info "OS      : ${PRETTY_NAME:-unknown}"
info "Kernel  : $(uname -r)"
info "CPUs    : $(nproc)"

# Bare metal is what buys the PMU. On a virtualised instance most hardware
# events read <not supported> and half this toolchain is decorative.
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
info "Virt    : ${VIRT}"
if [ "$VIRT" != "none" ]; then
    warn "this does not look like a bare-metal instance (systemd-detect-virt = ${VIRT})."
    warn "Sampling will still work; hardware counters (cycles/stalls) probably will not."
fi

if [ "$(nproc)" -lt 32 ]; then
    warn "only $(nproc) CPUs. The measurement script pins the server and the load"
    warn "generator to disjoint core sets, so it wants room to work; a"
    warn "c6g.metal (64 cores) is the reference box."
fi

# ── 1. apt ────────────────────────────────────────────────────────────
say "Waiting for cloud-init / unattended-upgrades to release the apt lock"
for _ in $(seq 1 120); do
    if ! sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1; then
        break
    fi
    sleep 5
done
info "lock clear"

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq

# Split into "must have" and "nice to have" so one unavailable package in a
# fresh release does not abort the provisioning run.
REQUIRED=(
    build-essential binutils make git curl ca-certificates pkg-config
    python3 python3-pip
    libssl-dev zlib1g-dev
    nghttp2-client            # h2load — HTTP/2 and HTTP/2+TLS load
    openssl gzip jq
    util-linux procps psmisc  # taskset, pgrep, fuser
)
OPTIONAL=(
    bpftrace bpfcc-tools      # DTrace replacement: uprobe call counts, off-CPU
    valgrind                  # cachegrind/callgrind: deterministic A/B of two .S variants
    gdb lldb
    numactl sysstat linux-tools-common
    hyperfine
)

sudo apt-get install -y -qq "${REQUIRED[@]}" || die "could not install the required packages"

for pkg in "${OPTIONAL[@]}"; do
    if ! sudo apt-get install -y -qq "$pkg" 2>/dev/null; then
        warn "optional package '$pkg' unavailable — continuing without it"
    fi
done

# ── 2. perf, which is packaged per kernel flavour ─────────────────────
# EC2 Ubuntu runs the -aws kernel, so the tools live in linux-tools-aws.
# Names drift between releases; try every plausible one and verify by
# actually running perf, since the /usr/bin/perf wrapper happily exists
# while the versioned binary behind it does not.
say "Installing perf"
for pkg in "linux-tools-$(uname -r)" linux-tools-aws linux-tools-generic linux-aws-tools-common; do
    sudo apt-get install -y -qq "$pkg" 2>/dev/null && info "installed $pkg" || true
done

if ! perf --version >/dev/null 2>&1; then
    warn "the packaged perf does not match this kernel."
    warn "Fix with:  sudo apt-get install linux-tools-\$(uname -r)"
    warn "If that package does not exist, the running kernel is newer than the"
    warn "archive's tools; either boot the matching kernel or build perf from"
    warn "the kernel source tree."
else
    info "perf: $(perf --version)"
fi

# ── 3. wrk (HTTP/1.1 load) — universe package if present, else source ─
say "Installing wrk"
if command -v wrk >/dev/null 2>&1; then
    info "already present: $(command -v wrk)"
elif sudo apt-get install -y -qq wrk 2>/dev/null && command -v wrk >/dev/null 2>&1; then
    info "installed from apt"
else
    info "not packaged for this release — building from source"
    rm -rf /tmp/wrk-build
    git clone --depth 1 -q https://github.com/wg/wrk.git /tmp/wrk-build
    make -C /tmp/wrk-build -j"$(nproc)" >/dev/null
    sudo install -m 0755 /tmp/wrk-build/wrk /usr/local/bin/wrk
    rm -rf /tmp/wrk-build
    info "installed to /usr/local/bin/wrk"
fi

# ── 4. FlameGraph (not packaged anywhere) ─────────────────────────────
say "Installing FlameGraph"
if [ -d /opt/FlameGraph ]; then
    sudo git -C /opt/FlameGraph pull -q || true
else
    sudo git clone --depth 1 -q https://github.com/brendangregg/FlameGraph.git /opt/FlameGraph
fi
info "/opt/FlameGraph"

# ── 5. Kernel tuning ──────────────────────────────────────────────────
# sarm forks a process per connection, so the limits that matter here are
# process-table limits, not the usual thread/fd ones. Defaults for pid_max
# are low enough to become the bottleneck being measured.
say "Tuning the kernel for the benchmark"
sudo tee /etc/sysctl.d/99-sarm-bench.conf >/dev/null <<'SYSCTL'
# Written by scripts/aws/setup_ec2_metal.sh — benchmark host tuning.

# Let perf read hardware events and kernel symbols without sudo on every
# invocation. Appropriate for a dedicated benchmark box, not for a shared
# or production host.
kernel.perf_event_paranoid = -1
kernel.kptr_restrict = 0

# sarm forks one process per connection: the default pid_max becomes the
# ceiling being measured long before the server does.
kernel.pid_max = 400000
kernel.threads-max = 400000

# Accept queue and ephemeral ports, so the load generator rather than the
# socket layer decides the offered rate.
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10

fs.file-max = 2000000
fs.nr_open = 2000000
SYSCTL
sudo sysctl -q --system
info "applied /etc/sysctl.d/99-sarm-bench.conf"

sudo tee /etc/security/limits.d/99-sarm.conf >/dev/null <<'LIMITS'
*  soft  nofile  1000000
*  hard  nofile  1000000
*  soft  nproc   400000
*  hard  nproc   400000
LIMITS
info "applied /etc/security/limits.d/99-sarm.conf (takes effect on next login)"

# ── 6. sarm ───────────────────────────────────────────────────────────
say "Fetching sarm"
if [ -d "$DEST" ] && [ ! -d "$DEST/.git" ] && [ -f "$DEST/Makefile" ]; then
    # An uploaded working tree rather than a checkout — this is how
    # quick_test_ec2.sh delivers the sources, local edits included. There
    # is nothing to fetch; use what is there.
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
# depends on them, so the build fails outright without it) and the rendered
# error pages under www/err/, which get embedded into the binary.
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

SYMS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' T ' || echo 0)
if [ "$SYMS" -lt 50 ]; then
    warn "the production build left only ${SYMS} global symbols — perf could not"
    warn "attribute samples. Rebuilding unstripped instead."
    make -C "$DEST" clean >/dev/null 2>&1 || true
    make -C "$DEST" 2>&1 | tail -5
    SYMS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' T ' || echo 0)
fi
LOCALS=$(nm "$DEST/sarm" 2>/dev/null | grep -c ' t ' || echo 0)
info "binary: $DEST/sarm ($(stat -c %s "$DEST/sarm") bytes)"
info "symbols: ${SYMS} global text, ${LOCALS} local"
if [ "$LOCALS" -gt 0 ]; then
    warn "${LOCALS} local labels survive and will fragment per-function attribution"
fi

say "Smoke test"
PORT=8099
"$DEST/sarm" "$PORT" >/dev/null 2>&1 &
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

# ── 7. Verify the PMU ─────────────────────────────────────────────────
say "Verifying hardware performance counters"
PMU_OK=0
if perf --version >/dev/null 2>&1; then
    PMU_OUT=$(perf stat -e cycles,instructions -x, true 2>&1 || true)
    if printf '%s' "$PMU_OUT" | grep -q "not supported"; then
        warn "hardware counters read <not supported>."
        warn "On EC2 the PMU is exposed on bare-metal instances; if this is c6g.metal"
        warn "and you still see this, check that nothing else holds the PMU."
        warn "Sampling (-F/cpu-clock) and everything else still works."
    else
        PMU_OK=1
        info "cycles + instructions readable"
        info "$(perf list 2>/dev/null | grep -ci 'armv8\|cpu-cycles' || echo 0) PMU event names visible to perf"
    fi
fi

# ── 8. Report ─────────────────────────────────────────────────────────
say "Ready"
printf '   %-22s %s\n' "sarm"        "$DEST"
printf '   %-22s %s\n' "binary"      "$DEST/sarm (unstripped)"
printf '   %-22s %s\n' "CPUs"        "$(nproc)"
printf '   %-22s %s\n' "PMU"         "$([ "$PMU_OK" = 1 ] && echo 'available' || echo 'UNAVAILABLE — sampling only')"
for t in perf wrk h2load bpftrace valgrind; do
    printf '   %-22s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo '— not installed')"
done
cat <<NEXT

   Next:
     cd $DEST
     ./scripts/aws/run_perf_suite.sh

   Log out and back in first if you want the raised ulimits in your shell.
NEXT
