#!/usr/bin/env bash
# quick_test_ec2.sh — rent a ec2 (metal) in the nearest region with
# capacity, run the quick perf suite on it, bring the results home,
# and give the machine back.
#
# The whole point of the exercise is the Neoverse N1 PMU, which only bare
# metal exposes, and bare metal is billed by the second from the moment it
# boots. So this script is built around one rule: the instance dies. It
# dies when the run finishes, when a step fails, when you hit Ctrl-C, when
# the local timeout fires — and, if this laptop falls off the network
# entirely, it still dies on its own, because it boots with a shutdown
# timer and terminate-on-shutdown.
#
# What it does:
#   0. pick a region: Melbourne, then Sydney, then the US, skipping any
#      that lacks the image, the instance type or the vCPU quota
#   1. SSH key pair — the one this REGION maps to (Melbourne ->
#      DaleMelbourne, Sydney -> DaleSydney; override with SARM_EC2_KEYS or
#      --key-name), else an ephemeral pair — plus a security group locked
#      to your public IP
#   2. launch ec2 (metal) on the latest Ubuntu arm64 (AMI resolved from SSM)
#   3. upload this working tree (tracked files, as they are on disk)
#   4. scripts/aws/setup_ec2_metal.sh   — toolchain, tuning, build, smoke
#   5. scripts/aws/run_perf_suite.sh --quick, sized to SATURATE sarm
#      (see "Saturation layout" below)
#   6. pull the results into ./perf-results/ec2-<timestamp>/ — this
#      happens on the way out too, so a failed, interrupted or
#      timed-out run still brings home whatever perf managed to write
#   7. fire off the terminate call and the keypair delete, and hand the
#      security group to the deferred-deletion list (below) — we do not
#      wait around for the instance to actually die
#
# Deferred security groups: a security group cannot be deleted while an
# instance still holds it, and a terminating bare-metal instance can take
# many minutes to let go. Rather than sit there watching it, the group is
# appended to a list and every later run of this script starts by trying
# to delete whatever is on that list, dropping the ones that succeed (or
# that no longer exist) and leaving the rest for next time.
#
# SATURATION LAYOUT — the point of this script is finding what LIMITS
# sarm, and a measurement can only do that while sarm is the slowest part
# of the loop. Bare-metal Graviton does not come smaller than 64 vCPUs
# (c6g.metal is the floor for a machine that exposes the Neoverse N1 PMU
# at all), so "fewer cores" here means giving sarm fewer, not renting
# fewer: by default the server gets --server-cores 2 and the load
# generator gets every core above it, roughly 27 client cores per server
# core. h2load costs ~4x what sarm costs per request, so anything near an
# even split hands the bottleneck to the client and section 2 then
# reports h2load's ceiling under sarm's name — which is exactly what the
# 2026-08-25 and 2026-08-26 runs did.
#
# The connection count follows the server, not the client: 16 per server
# core, with --max-streams 128 on top, so h2 carries thousands of
# outstanding requests against two cores while keeping the number of
# forked server processes low enough that the figure is not measuring the
# scheduler. Worker scaling (suite section 3) is skipped, because that
# phase deliberately runs UNPINNED across the whole box and answers a
# different question.
#
# Read section 4's verdict line first. "server saturated" means sections
# 4-6 are describing sarm's real limits; "CLIENT-BOUND" or "neither side
# saturated" means they are not, and the run needs fewer server cores or
# a higher ceiling before anything else in it is worth reading. The tail
# of this script prints those lines for you.
#
# Usage:
#   ./scripts/aws/quick_test_ec2.sh
#   ./scripts/aws/quick_test_ec2.sh --yes                  # no confirmation
#   ./scripts/aws/quick_test_ec2.sh --server-cores 1       # squeeze harder
#   ./scripts/aws/quick_test_ec2.sh --server-cores 4       # more headroom
#   ./scripts/aws/quick_test_ec2.sh --conns-per-core 32 --max-streams 256
#   ./scripts/aws/quick_test_ec2.sh --no-saturate          # old whole-box
#                                                          # defaults
#   ./scripts/aws/quick_test_ec2.sh --suite-args '--duration 30 --repeat 7'
#   ./scripts/aws/quick_test_ec2.sh --key-name X --key-file ~/.ssh/X.pem
#   ./scripts/aws/quick_test_ec2.sh --ephemeral-key        # mint one instead
#   ./scripts/aws/quick_test_ec2.sh --ubuntu 24.04         # previous LTS
#   ./scripts/aws/quick_test_ec2.sh --region us-east-1     # pin one region
#   ./scripts/aws/quick_test_ec2.sh --regions "ap-southeast-2 us-west-2"
#   ./scripts/aws/quick_test_ec2.sh --on-demand            # not spot; costs
#                                                          # ~3x, cannot be
#                                                          # interrupted
#   ./scripts/aws/quick_test_ec2.sh --timeout 5400
#   ./scripts/aws/quick_test_ec2.sh --keep                 # leave it running
#   ./scripts/aws/quick_test_ec2.sh --sweep-only           # just drain the
#                                                          # deferred SG list
#
# Spot is the default market — the same bare metal for roughly a third of
# the on-demand price, at the cost of AWS being able to reclaim it with
# two minutes' notice. Everything here already survives the box
# disappearing, so an interruption costs the run and nothing else; pass
# --on-demand when a long suite is worth paying not to repeat.
#
# Needs: awscli v2 with credentials, ssh, scp, git. c6g.metal counts 64
# vCPUs against the "Running On-Demand Standard instances" quota in the
# target region — if that quota is still the default 5, that region is
# skipped during the plan rather than failing mid-launch. Capacity itself
# cannot be queried, only attempted: the launch walks every zone of the
# chosen region and then the next region, and nothing is billed until one
# of those attempts succeeds.
#
# HOW THIS SCRIPT IS PUT TOGETHER. Everything that is not specific to
# "rent one metal box and run the perf suite on it" now lives in
# scripts/aws/lib/ and is shared with scripts/aws/rps_two_box_ec2.sh, the
# two-machine RPS run:
#
#   lib/common.sh      say/info/warn/die and the small numeric helpers
#   lib/pending_sg.sh  the deferred security-group deletion list
#   lib/region.sh      region probing: image, instance type, vCPU quota
#   lib/pricing.sh     spot vs on-demand, per zone and per region
#   lib/ec2.sh         key pair, security group, the launch loop, ssh
#   lib/upload.sh      the working-tree tarball and its provenance stamp
#
# The instance-side provisioning is split the same way, under
# scripts/aws/setup/ — see scripts/aws/setup_ec2_metal.sh.
#
# The library is written for N instances because the two-box run needs
# two; this script asks it for one, which is why $ITYPES and $IROLES
# below are single-element lists.

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"
LIB="$REPO/scripts/aws/lib"
. "$LIB/common.sh"
. "$LIB/pending_sg.sh"
. "$LIB/region.sh"
. "$LIB/pricing.sh"
. "$LIB/ec2.sh"
. "$LIB/upload.sh"

# ── options ───────────────────────────────────────────────────────────
# Candidate regions, in preference order. The script probes each one for
# image + instance-type offering + vCPU quota before it launches anything,
# and falls through to the next when a region turns out to have no
# capacity. --region pins it to exactly one.
# Nearest first, then the deepest capacity pools. Probing is lazy — the
# first region that passes is the only one queried — so a long list costs
# nothing on a normal run and is what keeps a run possible on a day when
# metal is scarce or a spot quota is zero in the near regions.
REGION_CANDIDATES="${SARM_EC2_REGIONS:-\
ap-southeast-4 ap-southeast-2 \
us-west-2 us-west-1 us-east-1 us-east-2 \
ap-southeast-1 ap-northeast-1 ap-northeast-2 ap-south-1 \
eu-west-1 eu-west-2 eu-central-1 ca-central-1 sa-east-1}"
                        # Melbourne, Sydney,
                        # Oregon, N. California, N. Virginia, Ohio,
                        # Singapore, Tokyo, Seoul, Mumbai,
                        # Ireland, London, Frankfurt, Canada, Sao Paulo
REGION=""               # chosen from the above during the plan

# The regions that are compared on price rather than taken in list order.
# Australia only, and deliberately: Melbourne and Sydney are
# interchangeable for this workload — same country, same order of latency
# from here, same data-residency answer — so a run should go wherever
# spot is cheaper that hour rather than wherever the list happens to
# start. Everywhere else the list order IS the preference, and a cheaper
# region on another continent is not a better one.
PRICE_GROUP="ap-southeast-4 ap-southeast-2"
ITYPE="c6g.metal"  # 64 cores
#ITYPE="c8g.metal-48xl"  # 192 cores
AMI=""
UBUNTU="26.04"          # latest release (Resolute, an LTS)
VOLUME_GB=40
SUITE_ARGS="--quick"
# ── saturation sizing (see the header) ────────────────────────────────
# These are turned into --server-cpus/--load-cpus/--connections/--threads
# /--max-streams once the instance is up and its core count is known;
# nothing here is computed locally, because the core count belongs to the
# machine we are about to rent, not to this laptop.
# Spot by default: it is the same hardware at roughly a third of the price,
# and this script's whole design already assumes the instance can vanish
# without warning — deadman shutdown, terminate-on-shutdown, cleanup on
# every exit path, results fetched on the way out. An interruption costs a
# re-run, not a leak. --on-demand buys certainty for a long suite.
SPOT=1                  # effective for the CURRENT region; the price
                        #   check below can drop a region to on-demand
SATURATE=1
SERVER_CORES=2          # cores sarm is pinned to — the smaller, the
                        #   sooner it saturates and the cleaner the PMU
                        #   attribution (one core = no migration at all)
RESERVE_CORES=0         # cores left to the kernel and NIC; 0 = nproc/8
CONNS_PER_CORE=16       # concurrent connections per server core
MAX_STREAMS=128         # h2 streams per connection — the other half of
                        #   the concurrency ceiling
TIMEOUT=3600            # local watchdog, seconds
DEADMAN=90              # in-instance self-destruct, minutes
SSH_CIDR=""
# Key pair. An existing AWS key pair is used when its private half is on
# this machine; otherwise the script falls back to minting an ephemeral
# one for the run. A key pair belongs to a single region, so the default
# here is paired with the first candidate region above; in any other
# region it will not be found and an ephemeral pair is minted instead.
KEY_NAME="${SARM_EC2_KEY_NAME:-DaleMelbourne}"
KEY_FILE="${SARM_EC2_KEY_FILE:-$HOME/.ssh/DaleMelbourne.pem}"
KEY_EXPLICIT=0
ASSUME_YES=0
KEEP=0
SKIP_SUITE=0
SWEEP_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --region)      REGION_CANDIDATES="$2"; shift ;;
        --regions)     REGION_CANDIDATES="$2"; shift ;;
        --spot)        SPOT=1 ;;
        --on-demand)   SPOT=0 ;;
        --type)        ITYPE="$2"; shift ;;
        --ami)         AMI="$2"; shift ;;
        --ubuntu)      UBUNTU="$2"; shift ;;
        --volume-gb)   VOLUME_GB="$2"; shift ;;
        --suite-args)  SUITE_ARGS="$2"; shift ;;
        --server-cores)   SERVER_CORES="$2"; shift ;;
        --reserve-cores)  RESERVE_CORES="$2"; shift ;;
        --conns-per-core) CONNS_PER_CORE="$2"; shift ;;
        --max-streams)    MAX_STREAMS="$2"; shift ;;
        --no-saturate)    SATURATE=0 ;;
        --timeout)     TIMEOUT="$2"; shift ;;
        --deadman)     DEADMAN="$2"; shift ;;
        --ssh-cidr)    SSH_CIDR="$2"; shift ;;
        --key-name)    KEY_NAME="$2"; KEY_EXPLICIT=1; shift ;;
        --key-file)    KEY_FILE="$2"; KEY_EXPLICIT=1; shift ;;
        --ephemeral-key) KEY_NAME=""; KEY_FILE=""; KEY_EXPLICIT=0 ;;
        --setup-only)  SKIP_SUITE=1 ;;
        --sweep-only)  SWEEP_ONLY=1 ;;
        --keep)        KEEP=1 ;;
        -y|--yes)      ASSUME_YES=1 ;;
        -h|--help)     sed -n '2,/^set -euo/p' "$0" | sed -E 's/^#[[:space:]]?//;$d'; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

for opt in SERVER_CORES RESERVE_CORES CONNS_PER_CORE MAX_STREAMS; do
    case "${!opt}" in
        ''|*[!0-9]*) echo "$0: --$(echo "$opt" | tr 'A-Z_' 'a-z-') must be a non-negative integer" >&2; exit 2 ;;
    esac
done
[ "$SERVER_CORES" -ge 1 ] || { echo "$0: --server-cores must be at least 1" >&2; exit 2; }

# $SPOT is per region from here on — the price check drops a region with
# no spot discount to on-demand, and that verdict must not follow us into
# the next region on a capacity fallback. $SPOT_WANTED is what was asked
# for, and is what "did this run ever ask for spot" means.
SPOT_WANTED="$SPOT"

require_tools aws ssh scp git

# Before anything is priced or launched: every script this run will execute
# on the instance has to be in the upload, and the upload is `git ls-files`.
require_tracked \
    scripts/aws/setup_ec2_metal.sh scripts/aws/run_perf_suite.sh \
    scripts/aws/setup/lib.sh scripts/aws/setup/packages.sh \
    scripts/aws/setup/tuning.sh scripts/aws/setup/loadgen.sh \
    scripts/aws/setup/build_sarm.sh scripts/aws/setup/profiling.sh \
    scripts/aws/setup/report.sh scripts/benchmarks/rps_bench.sh

RUNID="$(date +%Y%m%d-%H%M%S)"
TAG="sarm-quicktest-$RUNID"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sarm-ec2-XXXXXX")"
KEYFILE=""
LOCAL_OUT="$REPO/perf-results/ec2-$RUNID"
AWSC=()                 # rebuilt once the region is chosen

# The library launches a group, so the id lives in an array; this run
# holds exactly one and INSTANCE_ID is the readable name for it.
INSTANCE_IDS=()
INSTANCE_ID=""
SG_ID=""
SG_INTERNAL=0       # one box: nothing has to reach it but ssh
ONDEMAND=""         # on-demand $/hr for $ITYPE in $REGION, once known
SPOT_AZS=""         # the zones where spot actually beats it
KEY_EPHEMERAL=0     # 1 only when this run created the key pair in AWS
WATCHDOG=""
STARTED=$(date +%s)
RESULTS_FETCHED=0

# The library probes, prices and launches whatever is in $ITYPES, with
# $IROLES naming each one for its Name tag. One entry each here.
ITYPES="$ITYPE"
IROLES=""

# ── pulling the results home ──────────────────────────────────────────
# Defined before cleanup() because cleanup calls it: whatever the suite
# managed to write is worth having, and on a failed or interrupted run it
# is worth more than on a clean one. Idempotent and entirely best-effort —
# nothing in here may prevent the instance from being terminated. Only
# usable once REMOTE exists; before that it is a no-op.
fetch_results() {
    [ "$RESULTS_FETCHED" = 1 ] && return 0
    [ -n "${REMOTE:-}" ] || return 0
    RESULTS_FETCHED=1

    mkdir -p "$LOCAL_OUT"
    # The logs of this side of the run exist regardless of whether the box
    # is still reachable, so save them first.
    cp "$WORK/setup.log" "$WORK/suite.log" "$LOCAL_OUT/" 2>/dev/null || true

    say "Downloading results"
    # Streamed as a tarball rather than scp -r: recent scp speaks SFTP and
    # will not expand a remote glob, and perf.data files are worth the gzip.
    #
    # Judged by what lands here, not by tar's exit status. GNU tar exits
    # non-zero for things that do not cost us the results — a file it
    # could not read, a file that changed under it — and the old `&&`
    # threw a good tarball away on those, reporting nothing but "could
    # not retrieve". Both sides' stderr is kept and quoted instead, so
    # the next failure says what actually happened.
    local before after
    before="$(find "$LOCAL_OUT" -type f | wc -l | tr -d ' ')"
    rsh "cd \$HOME/sarm/perf-results && tar -czf - '$RUNID'" \
        > "$WORK/results.tar.gz" 2> "$WORK/results.err" || true
    if [ -s "$WORK/results.tar.gz" ]; then
        # A truncated archive still yields every member before the cut,
        # so unpack first and count afterwards rather than believing the
        # exit status either way.
        tar -xzf "$WORK/results.tar.gz" -C "$LOCAL_OUT" --strip-components 1 \
            2>> "$WORK/results.err" || true
    fi
    after="$(find "$LOCAL_OUT" -type f | wc -l | tr -d ' ')"

    if [ "$after" -gt "$before" ]; then
        info "$(du -sh "$LOCAL_OUT" | cut -f1) retrieved"
        # Arrived, but not cleanly: say so rather than let a half-copied
        # run look like a complete one in perf-results/.
        if [ -s "$WORK/results.err" ]; then
            warn "the transfer complained — results may be incomplete:"
            sed 's/^/     /' "$WORK/results.err" | head -3
            cp "$WORK/results.err" "$LOCAL_OUT/results-fetch.err" 2>/dev/null || true
        fi
    else
        warn "could not retrieve $RUNID from ~/sarm/perf-results — keeping what we have locally"
        if [ -s "$WORK/results.err" ]; then
            sed 's/^/     /' "$WORK/results.err" | head -5
            cp "$WORK/results.err" "$LOCAL_OUT/results-fetch.err" 2>/dev/null || true
        fi
        # What the box thinks it has. One round trip, only on the failing
        # path, and it is the difference between guessing and knowing
        # whether the suite wrote anywhere we then failed to read.
        local listing
        listing="$(rsh 'ls -1 $HOME/sarm/perf-results 2>&1 | tail -5' 2>/dev/null || true)"
        if [ -n "$listing" ]; then
            warn "~/sarm/perf-results on the instance holds:"
            printf '%s\n' "$listing" | sed 's/^/     /'
        fi
    fi
    rsh 'uname -a; nproc; head -20 /proc/cpuinfo' > "$LOCAL_OUT/host.txt" 2>/dev/null || true
    # Anything the suite wrote outside its own directory, plus what the
    # kernel logged: on a run that died early these are often the only
    # evidence of why.
    rsh 'journalctl -n 2000 --no-pager 2>/dev/null; dmesg 2>/dev/null | tail -200' \
        > "$LOCAL_OUT/instance-journal.txt" 2>/dev/null || true

    # A redirection creates its file even when the ssh behind it fails, so
    # an unreachable box leaves a directory of zero-byte stubs. Neither
    # they nor the empty directory are worth keeping in perf-results/.
    find "$LOCAL_OUT" -maxdepth 1 -type f -empty -delete 2>/dev/null || true
    rmdir "$LOCAL_OUT" 2>/dev/null && { warn "nothing was retrieved"; return 0; }
    info "results in $LOCAL_OUT"
}

# ── cleanup: the reason this script exists ────────────────────────────
# Runs on every exit path — success, failure (set -e), Ctrl-C, watchdog
# TERM. Each step is independently best-effort: a failure deleting the
# security group must never skip terminating the instance.
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    [ -n "$WATCHDOG" ] && kill "$WATCHDOG" 2>/dev/null || true

    # Before the machine goes away — every path that reaches here without
    # having downloaded yet (a failed suite, Ctrl-C, the watchdog) still
    # gets whatever perf wrote. A clean run has already fetched, and this
    # is then a no-op.
    fetch_results || warn "results download failed"

    if [ -n "$INSTANCE_ID" ]; then
        if [ "$KEEP" = 1 ]; then
            say "Leaving $INSTANCE_ID running (--keep)"
            warn "you are being billed. Terminate with:"
            warn "  aws ec2 terminate-instances --region $REGION --instance-ids $INSTANCE_ID"
            warn "it will self-terminate after ${DEADMAN} minutes regardless."
            if [ "$KEY_EPHEMERAL" = 1 ]; then
                info "ephemeral ssh key kept at $KEYFILE"
            fi
            info "ssh -i $KEYFILE ubuntu@${PUBLIC_IP:-<ip>}"
            # Queued rather than deleted: the group is in use for as long
            # as you keep the box, and the sweep will simply skip it until
            # it is not.
            [ -n "$SG_ID" ] && defer_security_group "$SG_ID" "$REGION"
            printf '\n'
            exit "$rc"
        fi
        say "Terminating $INSTANCE_ID"
        # The API call is what stops the billing clock; the instance
        # reaching the terminated state can take many minutes on bare
        # metal and there is nothing here that needs to see it happen.
        "${AWSC[@]}" ec2 terminate-instances --instance-ids "$INSTANCE_ID" \
            --query 'TerminatingInstances[].CurrentState.Name' 2>&1 | sed 's/^/   /' || \
            warn "terminate call failed — CHECK THE CONSOLE for $INSTANCE_ID"
    fi

    # After the terminate, not before: the terminate is what stops the
    # billing clock, and this runs on the no-instance paths too.
    cancel_spot_requests ${INSTANCE_ID:+"$INSTANCE_ID"} || warn "spot request cleanup failed"

    # The security group cannot be deleted while the instance still holds
    # it, and we are not waiting for that. Onto the list it goes.
    if [ -n "$SG_ID" ]; then
        defer_security_group "$SG_ID" "$REGION"
    fi
    # Only ever the pair this run created — a long-lived key of yours is
    # not this script's to delete.
    if [ "$KEY_EPHEMERAL" = 1 ] && [ -n "$KEY_NAME" ]; then
        "${AWSC[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 \
            && info "deleted key pair $KEY_NAME" || warn "could not delete key pair $KEY_NAME"
    fi
    rm -rf "$WORK"

    local mins=$(( ($(date +%s) - STARTED) / 60 ))
    info "elapsed: ${mins} min of ${ITYPE} time"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ── collect what earlier runs left behind ─────────────────────────────
# Cheap, and doing it first means the leftovers of the previous run are
# usually gone by the time this one launches anything.
sweep_pending_security_groups

if [ "$SWEEP_ONLY" = 1 ]; then
    report_pending_security_groups
    exit 0
fi

# ── 0. where to rent ──────────────────────────────────────────────────
# See lib/region.sh for what a region is checked for and why none of it
# proves there is capacity. The order is deliberate: Melbourne and Sydney
# are close, and the US regions are the deep capacity pool that almost
# always has metal free when ap-southeast-4 does not.

say "Choosing a region"
# An AMI id belongs to exactly one region, so pinning one pins the region.
if [ -n "$AMI" ] && [ "$(printf '%s' "$REGION_CANDIDATES" | wc -w)" -gt 1 ]; then
    REGION_CANDIDATES="${REGION_CANDIDATES%% *}"
    warn "--ami is region-specific; only $REGION_CANDIDATES will be tried"
fi
AMI_SSM="/aws/service/canonical/ubuntu/server/$UBUNTU/stable/current/arm64/hvm/ebs-gp3/ami-id"
AMI_PINNED="$AMI"       # empty unless --ami was given
# Probing is lazy: the first region that passes is the one we use, and the
# rest are never asked about unless it turns out to have no capacity. Four
# regions x three API calls is a slow way to answer a question that the
# first region almost always settles, and every one of those calls is a
# round trip to the other side of the planet.
#
# PENDING_REGIONS is the queue of codes not yet looked at. next_region()
# takes from the front until one passes, sets the globals for it, and
# leaves the remainder in place for the launch loop to fall back on.
PENDING_REGIONS="$REGION_CANDIDATES"

next_region || no_region_left

# ── 0c. spot pricing ──────────────────────────────────────────────────
# Spot is the default market — the same bare metal for roughly a third of
# the on-demand price, at the cost of AWS being able to reclaim it with
# two minutes' notice. See lib/pricing.sh.
price_region

# ── 0b. plan ──────────────────────────────────────────────────────────
say "Plan"
printf '   %-14s %s\n' region "$REGION — $(region_name "$REGION")" type "$ITYPE" az "$AZ" \
    ubuntu "$UBUNTU" ami "$AMI" \
    suite "run_perf_suite.sh $SUITE_ARGS" timeout "${TIMEOUT}s (deadman ${DEADMAN}m)" \
    results "$LOCAL_OUT"
printf '   %-14s %s\n' zones "$AZS" \
    market "$(market_summary)"
if [ -n "$PENDING_REGIONS" ]; then
    fallbacks=""
    for r in $PENDING_REGIONS; do fallbacks="$fallbacks $r ($(region_name "$r")),"; done
    printf '   %-14s %s\n' fallbacks \
        "${fallbacks# } — not checked yet, only if $REGION is out of capacity"
fi
if [ "$SATURATE" = 1 ]; then
    printf '   %-14s %s\n' layout \
        "sarm on $SERVER_CORES core(s), load on the rest, $(( SERVER_CORES * CONNS_PER_CORE )) conns x $MAX_STREAMS streams"
    printf '   %-14s %s\n' '' "(exact CPU ranges are derived on the box, from its own nproc)"
else
    printf '   %-14s %s\n' layout "--no-saturate: whatever run_perf_suite.sh defaults to"
fi

if [ "$ASSUME_YES" != 1 ]; then
    printf '\n   Bare metal is billed per second from boot. Launch? [y/N] '
    read -r reply
    case "$reply" in [yY]*) ;; *) INSTANCE_ID=""; die "aborted" ;; esac
fi

# ── 1. keypair and security group ─────────────────────────────────────
# Both are per region, so they are redone inside the launch loop when a
# region turns out to have no capacity. See lib/ec2.sh.
KEY_NAME_REQUESTED="$KEY_NAME"
KEY_FILE_REQUESTED="$KEY_FILE"
resolve_ssh_cidr

# ── 2. launch ─────────────────────────────────────────────────────────
# Two independent kill switches, because the local trap only fires while
# this shell is alive: the instance shuts itself down after $DEADMAN
# minutes, and shutdown means terminate.
write_user_data "$DEADMAN"

# next_region() has already chosen the first one; a region that turns out
# to have no capacity sends us back to it for the next candidate, which is
# only probed at that point.
LAUNCHED=0
TRIED=""
while :; do
    say "Launching $ITYPE in $REGION / $(region_name "$REGION") (bare metal takes several minutes to POST)"
    TRIED="$TRIED $REGION"
    setup_keypair
    setup_security_group
    if launch_group_in_region; then LAUNCHED=1; break; fi

    warn "no $ITYPE available anywhere in $REGION ($(region_name "$REGION"))"
    release_region
    next_region || break
    # Priced from scratch: see price_region(). Without this the new
    # region inherits the old one's zone order and its $SPOT_AZS, and
    # every zone here would quietly launch on-demand.
    price_region
    info "market: $(market_summary)"
done

if [ "$LAUNCHED" != 1 ]; then
    INSTANCE_ID=""
    die "no $ITYPE capacity in any region tried:${TRIED}
   Nothing is running and nothing is billed. Options: wait and re-run,
   try another type with --type, or name a region directly with --region."
fi
INSTANCE_ID="${LAUNCHED_IDS[0]}"
INSTANCE_IDS=("$INSTANCE_ID")
info "$INSTANCE_ID in $AZ — $(region_name "$REGION")"

# The watchdog is armed only now — before this point there is nothing to
# leak, and after it the trap does the right thing on TERM.
( sleep "$TIMEOUT"; kill -TERM $$ 2>/dev/null ) &
WATCHDOG=$!
# Killing it on the way out is normal and expected, but the shell reaps it
# noisily ("Terminated: 15 ( sleep ... )") on top of whatever the run was
# actually reporting. Disowning it drops the job-table entry, so cleanup
# can still kill the pid and nothing is printed about it.
disown "$WATCHDOG" 2>/dev/null || true

"${AWSC[@]}" ec2 wait instance-running --instance-ids "$INSTANCE_ID"
PUBLIC_IP="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress')"
info "running at $PUBLIC_IP"

SSH_OPTS=()
while IFS= read -r o; do SSH_OPTS+=("$o"); done <<< "$(ssh_opts)"
REMOTE="ubuntu@$PUBLIC_IP"
rsh() { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }

say "Waiting for sshd"
wait_for_ssh "$ITYPE" "$REMOTE" "${SSH_OPTS[@]}"

# ── 3. upload the working tree ────────────────────────────────────────
# Tracked files as they are on disk, not HEAD — so a local edit is what
# gets measured. Untracked build inputs (certs, error pages) are
# regenerated on the box by setup_ec2_metal.sh. The tarball also carries
# a .perf-provenance stamp, because the tree it unpacks has no .git and
# run_perf_suite.sh would otherwise report every run as clean — see
# lib/upload.sh.
say "Uploading the working tree"
upload_tree "$REMOTE" "${SSH_OPTS[@]}"
info "unpacked to ~/sarm"

# ── 4. bootstrap ──────────────────────────────────────────────────────
say "Bootstrapping (toolchain, kernel tuning, build, smoke test)"
rsh 'SARM_DIR=$HOME/sarm ~/sarm/scripts/aws/setup_ec2_metal.sh' \
    2>&1 | tee "$WORK/setup.log"

if [ "$SKIP_SUITE" = 1 ]; then
    say "--setup-only: stopping before the suite"
else
    # ── 4b. size the run so that sarm is what runs out ────────────────
    # Done here rather than in the options block because it needs the
    # instance's own core count: this script is pointed at c6g.metal (64)
    # today and c8g.metal-48xl (192) by uncommenting one line, and the
    # split has to follow.
    #
    # Anything the caller already put in --suite-args wins — the flags
    # below are defaults being supplied late, not an override.
    SAT_ARGS=""
    if [ "$SATURATE" = 1 ]; then
        suite_has() { case " $SUITE_ARGS " in (*" $1 "*) return 0 ;; (*) return 1 ;; esac; }

        RCPUS="$(rsh nproc 2>/dev/null | tr -d '\r' | head -1)"
        case "${RCPUS:-}" in ''|*[!0-9]*) RCPUS=0 ;; esac

        if [ "$RCPUS" -lt 4 ]; then
            warn "instance reports ${RCPUS:-no} usable CPUs — leaving the layout to run_perf_suite.sh"
        else
            reserve=$RESERVE_CORES
            [ "$reserve" -eq 0 ] && reserve=$(( RCPUS / 8 ))
            [ "$reserve" -lt 1 ] && reserve=1

            s_lo=$reserve
            s_hi=$(( s_lo + SERVER_CORES - 1 ))
            l_lo=$(( s_hi + 1 ))
            l_hi=$(( RCPUS - 1 ))

            # Refuse to produce a layout where the client shares cores
            # with the server: that measures the box, not sarm, and it is
            # better to fall back to the suite's own defaults (which warn
            # about it) than to hand back a plausible-looking number.
            if [ "$l_lo" -gt "$l_hi" ]; then
                warn "$SERVER_CORES server cores + $reserve reserved leaves nothing for the load"
                warn "generator on $RCPUS CPUs — falling back to run_perf_suite.sh's own split"
            else
                load_cores=$(( l_hi - l_lo + 1 ))
                conns=$(( SERVER_CORES * CONNS_PER_CORE ))
                [ "$conns" -lt 16 ] && conns=16
                # h2load requires connections >= threads, and one client
                # thread per connection is as close to pinned as it gets
                # without h2load having affinity of its own.
                threads=$conns
                [ "$threads" -gt "$load_cores" ] && threads=$load_cores

                suite_has --server-cpus  || SAT_ARGS="$SAT_ARGS --server-cpus $s_lo-$s_hi"
                suite_has --load-cpus    || SAT_ARGS="$SAT_ARGS --load-cpus $l_lo-$l_hi"
                suite_has --connections  || SAT_ARGS="$SAT_ARGS --connections $conns"
                suite_has --threads      || SAT_ARGS="$SAT_ARGS --threads $threads"
                suite_has --max-streams  || SAT_ARGS="$SAT_ARGS --max-streams $MAX_STREAMS"
                # Section 3 runs UNPINNED across the whole machine on
                # purpose, so it neither respects this layout nor tells us
                # anything about what limits a saturated server. It is also
                # the single most expensive phase in the suite.
                suite_has --skip         || SAT_ARGS="$SAT_ARGS --skip scaling"

                info "sarm on CPUs $s_lo-$s_hi ($SERVER_CORES core(s)), load on $l_lo-$l_hi ($load_cores cores)"
                info "$(awk -v l="$load_cores" -v sv="$SERVER_CORES" \
                        'BEGIN{printf "%.0f load cores per server core", l/sv}')"
                info "$conns connections x $MAX_STREAMS streams = $(( conns * MAX_STREAMS )) requests in flight (h2)"
                info "reserved for kernel/NIC: CPUs 0-$(( reserve - 1 ))"
            fi
        fi
    fi

    # ── 5. the quick test ─────────────────────────────────────────────
    say "Running run_perf_suite.sh $SUITE_ARGS$SAT_ARGS"
    rsh "cd ~/sarm && ./scripts/aws/run_perf_suite.sh $SUITE_ARGS$SAT_ARGS --out \$HOME/sarm/perf-results/$RUNID" \
        2>&1 | tee "$WORK/suite.log"

    # ── 6. bring the results home ─────────────────────────────────────
    fetch_results

    say "Results in $LOCAL_OUT"
    ls -1 "$LOCAL_OUT" | sed 's/^/   /'

    # ── 7. the limiting-factor readout ────────────────────────────────
    # Ordered by what has to be true before the next line means anything:
    # was sarm the bottleneck at all (section 4's verdict), what did it
    # cost per request, and only then which functions burned it. Quoting
    # req/s first is how the earlier runs got misread.
    if [ -f "$LOCAL_OUT/summary.txt" ]; then
        say "Was sarm the bottleneck?"
        if grep -qE 'cores busy' "$LOCAL_OUT/summary.txt" 2>/dev/null; then
            grep -E 'cores busy|cost ratio' "$LOCAL_OUT/summary.txt" | sed 's/^ *//;s/^/   /'
            if ! grep -q 'server saturated' "$LOCAL_OUT/summary.txt"; then
                warn "sarm never saturated, so sections 4-6 do not describe its limits."
                if grep -q 'CLIENT-BOUND' "$LOCAL_OUT/summary.txt"; then
                    warn "The client ran out first. Re-run with fewer server cores:"
                    warn "  $0 --server-cores 1"
                else
                    warn "Neither side ran out — the concurrency ceiling was binding. Re-run with:"
                    warn "  $0 --max-streams $(( MAX_STREAMS * 2 ))"
                fi
            fi
        else
            warn "no counter data — perf could not run system-wide on the instance."
            warn "Everything below is throughput only; there are no limiting factors in it."
        fi

        say "Cost per request"
        grep -E 'per core:|IPC |scheduling:' "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' || true

        say "Where the cycles went"
        grep -E 'totals: sarm|frontend|backend|branch-misses|cache-misses|context-switches' \
            "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' | head -24 || true

        say "Throughput (read this LAST, and only if sarm saturated)"
        grep -E 'req/s' "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' | head -6 || true
    fi
fi

# cleanup() terminates on the way out