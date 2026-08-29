# scripts/aws/setup/lib.sh — helpers shared by the instance-side setup
# steps. Sourced by the scripts next to it; never run directly.
#
# Everything in scripts/aws/setup/ runs ON THE INSTANCE. The orchestration
# that runs on the laptop lives in scripts/aws/lib/.

[ -n "${SARM_SETUP_LIB_SH:-}" ] && return 0
SARM_SETUP_LIB_SH=1

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '\033[1;33m   WARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

SARM_DEST="${SARM_DIR:-$HOME/sarm}"

# Every make in these scripts and in anything they call, including
# recursive ones, without having to remember -j at each site. These boxes
# exist to build and measure; a serial build wastes minutes of billed time.
export MAKEFLAGS="-j$(nproc)"

# ── 0. Sanity: is this the machine we think it is? ────────────────────
# <role> is only used for the wording of the warnings: a load generator
# has no use for the PMU and does not want to be told about it, and it is
# the one box here that does NOT have to be aarch64 — h2load and wrk speak
# the same protocols on any architecture. The server does: sarm is ARM64
# assembly.
check_host() {  # check_host <role>
    local role="${1:-server}" virt
    say "Checking the host"
    . /etc/os-release 2>/dev/null || true
    info "Role    : $role"
    info "OS      : ${PRETTY_NAME:-unknown}"
    info "Kernel  : $(uname -r)"
    info "CPUs    : $(nproc)"

    if [ "$role" != "load" ] && [ "$(uname -m)" != "aarch64" ]; then
        die "not aarch64 — sarm is ARM64 assembly, there is nothing to run here"
    fi

    # Bare metal is what buys the PMU. On a virtualised instance most
    # hardware events read <not supported> and half the profiling
    # toolchain is decorative. systemd-detect-virt exits 1 when it finds
    # no virtualisation — which is the answer a metal run is hoping for —
    # so its status says nothing and only the word it prints is read. The
    # `|| true` is load-bearing under `set -e`: an assignment takes the
    # exit status of the command it substitutes.
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    [ -n "$virt" ] || virt=unknown
    info "Virt    : ${virt}"
    if [ "$role" = "metal" ] && [ "$virt" != "none" ]; then
        warn "this does not look like a bare-metal instance (systemd-detect-virt = ${virt})."
        warn "Sampling will still work; hardware counters (cycles/stalls) probably will not."
    fi

    if [ "$role" = "metal" ] && [ "$(nproc)" -lt 32 ]; then
        warn "only $(nproc) CPUs. run_perf_suite.sh pins the server and the load"
        warn "generator to disjoint core sets, so it wants room to work; a"
        warn "c6g.metal (64 cores) is the reference box."
    fi
}

# ── apt ───────────────────────────────────────────────────────────────
# Ubuntu's stock cloud image will, on its own schedule, download and apply
# updates and then restart services — sshd among them, and on a kernel
# update it asks for a reboot. On a benchmark box that is two separate
# problems: a restart mid-run drops the orchestrator's ssh (which is how
# the 2026-08-29 two-box run died, right after provisioning), and a
# background apt during a measurement window is CPU the server did not
# spend on requests.
#
# So both are turned off for the life of the instance. This is a machine
# that exists for twenty minutes and then terminates; it is not one that
# needs to stay patched, and `needrestart` in particular has no business
# restarting anything here.
quiesce_background_updates() {
    say "Stopping the background updaters"
    local unit
    for unit in unattended-upgrades apt-daily.timer apt-daily-upgrade.timer \
                apt-daily.service apt-daily-upgrade.service; do
        sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    # needrestart is what turns an ordinary `apt install` into an sshd
    # restart. Its list mode ("l") reports and does nothing.
    if [ -d /etc/needrestart/conf.d ]; then
        printf '%s\n' '$nrconf{restart} = "l";' '$nrconf{kernelhints} = -1;' \
            | sudo tee /etc/needrestart/conf.d/99-sarm-bench.conf >/dev/null
    fi
    export NEEDRESTART_MODE=l
    export NEEDRESTART_SUSPEND=1
    info "unattended-upgrades and the apt timers are off; needrestart is advisory"
}

wait_for_apt_lock() {
    say "Waiting for cloud-init / unattended-upgrades to release the apt lock"
    local _
    for _ in $(seq 1 120); do
        if ! sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1; then
            break
        fi
        sleep 5
    done
    info "lock clear"
}

# apt-fast is a wrapper that hands the downloads to aria2c with several
# connections per mirror. On a box with a fat pipe that is the whole
# difference between a two-minute and a ten-minute provisioning run; the
# package sets below are large and mostly download-bound.
#
# aria2 is the one thing apt-fast cannot do without. It lives in universe,
# and it is resolved from whatever package index the image happens to have
# — which on a fresh EC2 Ubuntu image is often empty, so the first attempt
# answers "Unable to locate package aria2". That is a stale-index problem,
# not a missing-package one, so: try, refresh, try again, and only then
# reach for enabling universe.
install_aria2() {
    command -v aria2c >/dev/null 2>&1 && return 0

    sudo apt-get install -y -qq aria2 2>/dev/null && return 0

    info "aria2 not in the current package index — refreshing"
    sudo apt-get update -qq || true
    sudo apt-get install -y -qq aria2 2>/dev/null && return 0

    # Universe is enabled on the stock cloud images, but a hardened or
    # mirrored one may not have it.
    info "still not found — enabling universe"
    sudo add-apt-repository -y universe >/dev/null 2>&1 || true
    sudo apt-get update -qq || true
    sudo apt-get install -y -qq aria2 2>/dev/null
}

# The packaged version is used when it is already installed; its debconf
# answers are preseeded either way, since the config file the script reads
# is the same one the package prompts for.
install_apt_fast() {
    if command -v apt-fast >/dev/null 2>&1; then
        info "already present: $(command -v apt-fast)"
        return 0
    fi

    sudo debconf-set-selections <<'DEBCONF'
apt-fast apt-fast/maxdownloads string 16
apt-fast apt-fast/dlflag boolean true
apt-fast apt-fast/aptmanager string apt-get
DEBCONF

    install_aria2 || return 1
    sudo curl -fsSL -o /usr/local/bin/apt-fast \
        https://raw.githubusercontent.com/ilikenwf/apt-fast/master/apt-fast || return 1
    sudo chmod 0755 /usr/local/bin/apt-fast
    if [ ! -f /etc/apt-fast.conf ]; then
        sudo curl -fsSL -o /etc/apt-fast.conf \
            https://raw.githubusercontent.com/ilikenwf/apt-fast/master/apt-fast.conf || return 1
    fi
    command -v apt-fast >/dev/null 2>&1
}

# apt and aria2 between them produce hundreds of lines that matter only
# when something fails, and they bury the parts of the run that do not.
# Everything goes to a log, and only a failure gets to print.
APT_LOG="/tmp/sarm-apt.log"
APT=()
apt_bootstrap() {
    export DEBIAN_FRONTEND=noninteractive
    # Belt and braces: these also matter for the installs below, not just
    # for whatever ran before quiesce_background_updates().
    export NEEDRESTART_MODE=l
    export NEEDRESTART_SUSPEND=1
    say "Installing apt-fast"
    # Everything installs through $APT, so a failed apt-fast install just
    # falls back to plain apt-get rather than aborting the run.
    if install_apt_fast; then
        APT=(sudo apt-fast -y -qq)
        # More parallel connections than the default 5. The archive
        # mirrors are the bottleneck, not the box.
        grep -q '^_MAXNUM=16' /etc/apt-fast.conf 2>/dev/null \
            || printf '\n# raised by scripts/aws/setup/lib.sh\n_MAXNUM=16\n' \
               | sudo tee -a /etc/apt-fast.conf >/dev/null
        info "using apt-fast for package installs"
    else
        warn "apt-fast could not be installed — falling back to apt-get."
        warn "The usual cause is aria2: check 'apt-cache policy aria2' on this box."
        APT=(sudo apt-get -y -qq)
    fi
    : > "$APT_LOG"
}

apt_run() {
    if "${APT[@]}" "$@" >>"$APT_LOG" 2>&1; then
        return 0
    fi
    return 1
}
apt_log_tail() { sed 's/^/     /' "$APT_LOG" | tail -"${1:-15}"; }

# `apt-cache show` rather than parsing `policy` output for a "Candidate:"
# line: policy's layout is apt's to change between releases, and a probe
# that silently answers "no" to everything would quietly throw away the
# entire toolchain.
in_archive() { apt-cache show "$1" >/dev/null 2>&1; }
