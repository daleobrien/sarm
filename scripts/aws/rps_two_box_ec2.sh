#!/usr/bin/env bash
# rps_two_box_ec2.sh — a requests-per-second number that is actually
# sarm's, measured from a second machine.
#
# THE PROBLEM THIS EXISTS TO FIX. Every figure in perf-results/ so far was
# taken with sarm and the load generator on the SAME box, talking over
# loopback. h2load pays for TLS, HPACK and frame handling too, and it pays
# roughly 4x what sarm pays per request, so the two compete for one
# machine's cores and one of them has to lose. quick_test_ec2.sh manages
# that by starving the server on purpose — two cores for sarm, sixty-odd
# for the client — which is exactly right for a PROFILE (small, pinned,
# attributable) and is not a throughput number anybody would quote.
#
# So: two machines. A small one that runs nothing but sarm, and a large
# one that runs nothing but the load generator, in the same availability
# zone, talking over the VPC on their private addresses. The client cannot
# be the bottleneck when it has sixteen times the cores of the server and
# no server work to do, and nothing lands on the server's cores except
# sarm. What comes back is a ceiling rather than a floor.
#
#   server   c6gn.4xlarge  16 vCPU   runs sarm, nothing else installed
#   load     c6gn.12xlarge 48 vCPU   runs wrk/h2load, no sarm, no compiler
#
# THE FAMILY IS c6gn AND THAT MATTERS MORE THAN THE CORE COUNT. A
# small-payload RPS test is bound by packet rate, not bandwidth, and c7g's
# network is a burstable "up to 15 Gbps" allowance that runs out long
# before its cores do. Measured on 2026-08-29, same 16 cores, same load
# shape, only the family changed:
#
#              c7g.4xlarge          c6gn.4xlarge
#   h2c     4,421,914 @ 60% cpu   7,375,611 @ 97% cpu   +67%
#   h2 TLS  4,409,312 @ 51% cpu   7,363,824 @ 94% cpu   +67%
#   h1        695,027 @ 98% cpu     635,706 @ 98% cpu    -9%
#
# The two protocols move in opposite directions, which is what makes the
# reading safe rather than a coincidence: c6gn is Graviton2 and its cores
# are SLOWER than c7g's Graviton3, so HTTP/1.1 — already CPU-bound on both
# — drops 9%, exactly as you would expect. HTTP/2 was network-bound on
# c7g, so it gains 67% despite the slower cores and only stops when the
# CPU runs out. Nothing but the network explains that pattern.
#
# So every h2 figure taken on c7g understates sarm. Use c6gn (or c7gn
# where it is offered — it is not in ap-southeast-2) unless you have
# checked that the run is CPU-bound on whatever you picked; the summary
# tells you, per protocol, every time.
#
# The load box is not a fixed type: it is sized at --load-ratio (default
# 3) times the server's cores, so changing --server-type cannot silently
# erode the margin that makes the measurement valid. Both sides' CPU is
# then sampled over every protocol's window, so "the client had room to
# spare" is a measurement in the summary rather than an assumption.
#
# Both instances go into ONE availability zone and one subnet, and the
# load is driven at the server's PRIVATE address. That is checked after
# launch, not just intended: cross-zone traffic is billed per gigabyte
# each way and is slower, and a benchmark that quietly measures the
# network instead of sarm is worse than one that stops.
#
# WHAT IT DOES
#   0. sweep the deferred security groups an earlier run left behind
#   1. pick a region and a zone that offers BOTH instance types, priced
#      as a pair on spot (the two are one bill and one quota)
#   1b. a cluster placement group, so the two boxes are not merely in the
#      same zone but as close on the network as EC2 will put them. A
#      closed-loop client's throughput is concurrency/latency, so the
#      round trip is part of the answer; --no-placement-group turns it
#      off when capacity keeps refusing
#   2. the region's key pair (Melbourne -> DaleMelbourne, Sydney ->
#      DaleSydney; override with SARM_EC2_KEYS or --key-name) and one
#      security group: port 22 from your address,
#      and every TCP port from the group to itself — which is how the
#      load box reaches sarm without anything being exposed publicly
#   3. launch both into the same subnet; half a pair is rolled back
#   4. upload this working tree to both, then provision them in parallel:
#      setup_ec2_server.sh on one, setup_ec2_load.sh on the other
#   5. start sarm on the server box, bound to 0.0.0.0
#   6. from the load box, run rps_bench.sh --target <private-ip>:<port>
#      once per protocol, sampling the SERVER's /proc/stat across each
#      window so the answer to "did the server saturate" is a reading
#      rather than a hope
#   7. write everything to ./perf-results/two-box-<timestamp>/
#   8. terminate both instances
#
# Like quick_test_ec2.sh, the machines die: on success, on failure, on
# Ctrl-C, on the local watchdog, and — if this laptop falls off the
# network entirely — on their own, because both boot with a shutdown timer
# and terminate-on-shutdown.
#
# READING THE RESULT. The summary prints, per protocol, req/s and the
# server's busy cores over the same window. Busy cores near the server's
# core count means the number above it is sarm's ceiling. Well under it
# means something else was binding — raise --connections or --max-streams
# and run it again, or shrink the server with --server-type. The script
# says which of those it thinks happened.
#
# Usage:
#   ./scripts/aws/rps_two_box_ec2.sh
#   ./scripts/aws/rps_two_box_ec2.sh --yes
#   ./scripts/aws/rps_two_box_ec2.sh --server-type c6gn.8xlarge # 32 vCPU
#   ./scripts/aws/rps_two_box_ec2.sh --server-type c6gn.large   # 2 vCPU
#   ./scripts/aws/rps_two_box_ec2.sh --server-type c7g.4xlarge  # faster cores,
#                                                    # but h2 hits its NIC first
#   ./scripts/aws/rps_two_box_ec2.sh --load-ratio 6             # more headroom
#   ./scripts/aws/rps_two_box_ec2.sh --load-type c6gn.16xlarge  # pin it
#   ./scripts/aws/rps_two_box_ec2.sh --protocols h2tls          # just TLS
#   ./scripts/aws/rps_two_box_ec2.sh --duration 30 --repeat 5
#   ./scripts/aws/rps_two_box_ec2.sh --connections 64 --max-streams 256
#   ./scripts/aws/rps_two_box_ec2.sh --workers 1     # one accepting process
#   ./scripts/aws/rps_two_box_ec2.sh --no-placement-group   # if capacity
#                                                    # keeps refusing
#   ./scripts/aws/rps_two_box_ec2.sh --on-demand     # ~3x, not interruptible
#   ./scripts/aws/rps_two_box_ec2.sh --key-name X --key-file ~/.ssh/X.pem
#   ./scripts/aws/rps_two_box_ec2.sh --ephemeral-key # mint one instead
#   ./scripts/aws/rps_two_box_ec2.sh --keep          # leave them running
#   ./scripts/aws/rps_two_box_ec2.sh --sweep-only
#
# Needs: awscli v2 with credentials, ssh, scp, git. Both instances count
# against ONE regional vCPU quota, so the plan checks the sum and skips a
# region that cannot hold both — the failure that otherwise arrives as
# VcpuLimitExceeded several minutes and one security group into the run.

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
# Nearest first, then the deepest capacity pools; see quick_test_ec2.sh
# for why the list is shaped this way. Probing is lazy, so a long list
# costs nothing on a normal run.
REGION_CANDIDATES="${SARM_EC2_REGIONS:-\
ap-southeast-4 ap-southeast-2 \
us-west-2 us-west-1 us-east-1 us-east-2 \
ap-southeast-1 ap-northeast-1 ap-northeast-2 ap-south-1 \
eu-west-1 eu-west-2 eu-central-1 ca-central-1 sa-east-1}"
PRICE_GROUP="ap-southeast-4 ap-southeast-2"
REGION=""

# The server box is the measurement. Graviton3 rather than metal: this run
# wants no PMU, and a shared instance is a fraction of the price of the
# smallest metal Graviton there is (c6g.metal, 64 cores, because metal
# does not come smaller).
#
# Its core count is the main thing to turn. More cores measure sarm closer
# to how it would actually be deployed and give the fork-per-connection
# model somewhere to go; fewer cores saturate sooner and cost less. What
# must not happen is the load box failing to keep up, so it is not a fixed
# type: LOAD_TYPE=auto sizes it at LOAD_RATIO times the server's cores,
# and the run MEASURES both sides to prove the choice was right.
# c6gn, not c7g: see the family note in the header. c7g has the faster
# cores and loses anyway, because this workload runs out of packets before
# it runs out of CPU.
SERVER_TYPE="c6gn.4xlarge"  # 16 vCPU, 25 Gbps dedicated
LOAD_TYPE="auto"            # sized from the server; see resolve_load_type()
# MEASURED, not assumed. The repo's "h2load costs ~4x what sarm costs per
# request" comes from LOOPBACK runs, where the two contend for the same
# cores and caches; it does not survive the move to two boxes. The
# 2026-08-29 run (perf-results/two-box-20260829-213226) drove a saturated
# 8-core server and the client's own busy cores came to:
#
#   HTTP/1.1      4.49 client cores per 7.83 server   0.57x
#   HTTP/2 h2c    9.53 per 7.81                       1.22x
#   HTTP/2 + TLS 10.69 per 7.28                       1.47x
#
# So the worst protocol needs about 1.5 client cores per server core, and
# the old 8:1 default was provisioning five times what the job used. 3:1
# keeps a 2x margin over the worst case measured, which buys a much bigger
# server inside the same family — and the run measures both sides every
# time, so a ratio that turns out to be too thin is reported as
# CLIENT-BOUND rather than quietly published as a server result.
LOAD_RATIO=3
AMI=""
UBUNTU="26.04"
VOLUME_GB=30

PORT=8080
WORKERS="auto"
PROTOCOLS="h1 h2c h2tls"
DURATION=20
REPEAT=3
WARMUP=3
REQ_PATH=/
PIPELINE=1
# 0 = derive: CONNS_PER_CORE per SERVER vCPU. Connections follow the
# server, not the client, because sarm serves one connection per process
# and this is therefore how many processes the small box has to
# multiplex. Following the client instead would just oversubscribe it.
CONNECTIONS=0
CONNS_PER_CORE=16
MAX_STREAMS=128
THREADS=0                   # 0 = one h2load thread per load-box core

# A cluster placement group: same zone is not the same as close. See
# setup_placement_group() in lib/ec2.sh for why this is the one knob that
# moves the number, and what it costs in launch success rate.
PLACEMENT=1
SPOT=1
SPOT_WANTED=1
TIMEOUT=3600
DEADMAN=90
SSH_CIDR=""
KEY_NAME="${SARM_EC2_KEY_NAME:-DaleMelbourne}"
KEY_FILE="${SARM_EC2_KEY_FILE:-$HOME/.ssh/DaleMelbourne.pem}"
KEY_EXPLICIT=0
ASSUME_YES=0
KEEP=0
SKIP_BENCH=0
SWEEP_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --region)        REGION_CANDIDATES="$2"; shift ;;
        --regions)       REGION_CANDIDATES="$2"; shift ;;
        --server-type)   SERVER_TYPE="$2"; shift ;;
        --load-type)     LOAD_TYPE="$2"; shift ;;
        --load-ratio)    LOAD_RATIO="$2"; shift ;;
        --ami)           AMI="$2"; shift ;;
        --ubuntu)        UBUNTU="$2"; shift ;;
        --volume-gb)     VOLUME_GB="$2"; shift ;;
        --port)          PORT="$2"; shift ;;
        --workers)       WORKERS="$2"; shift ;;
        --protocols)     PROTOCOLS="$(printf '%s' "$2" | tr ',' ' ')"; shift ;;
        --duration)      DURATION="$2"; shift ;;
        --repeat)        REPEAT="$2"; shift ;;
        --warm-up)       WARMUP="$2"; shift ;;
        --path)          REQ_PATH="$2"; shift ;;
        --pipeline)      PIPELINE="$2"; shift ;;
        --connections)   CONNECTIONS="$2"; shift ;;
        --conns-per-core) CONNS_PER_CORE="$2"; shift ;;
        --max-streams)   MAX_STREAMS="$2"; shift ;;
        --threads)       THREADS="$2"; shift ;;
        --placement-group)    PLACEMENT=1 ;;
        --no-placement-group) PLACEMENT=0 ;;
        --spot)          SPOT=1 ;;
        --on-demand)     SPOT=0 ;;
        --timeout)       TIMEOUT="$2"; shift ;;
        --deadman)       DEADMAN="$2"; shift ;;
        --ssh-cidr)      SSH_CIDR="$2"; shift ;;
        --key-name)      KEY_NAME="$2"; KEY_EXPLICIT=1; shift ;;
        --key-file)      KEY_FILE="$2"; KEY_EXPLICIT=1; shift ;;
        --ephemeral-key) KEY_NAME=""; KEY_FILE=""; KEY_EXPLICIT=0 ;;
        --setup-only)    SKIP_BENCH=1 ;;
        --sweep-only)    SWEEP_ONLY=1 ;;
        --keep)          KEEP=1 ;;
        -y|--yes)        ASSUME_YES=1 ;;
        -h|--help)       sed -n '2,/^set -euo/p' "$0" | sed -E 's/^#[[:space:]]?//;$d'; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

for opt in PORT DURATION REPEAT WARMUP CONNECTIONS CONNS_PER_CORE MAX_STREAMS THREADS PIPELINE VOLUME_GB TIMEOUT DEADMAN; do
    require_uint "${!opt}" "--$(echo "$opt" | tr 'A-Z_' 'a-z-')"
done
for proto in $PROTOCOLS; do
    case "$proto" in h1|h2c|h2tls) ;; *) die "--protocols wants h1, h2c and/or h2tls, got '$proto'" ;; esac
done
[ -n "$PROTOCOLS" ] || die "--protocols selected nothing"
[ "$PORT" -ge 1 ] || die "--port must be a real port"
[ "$DURATION" -ge 1 ] || die "--duration must be at least 1 second"
[ "$REPEAT" -ge 1 ] || die "--repeat must be at least 1"

SPOT_WANTED="$SPOT"
[ "$LOAD_RATIO" -ge 1 ] || die "--load-ratio must be at least 1"
require_tools aws ssh scp git

# Before anything is priced or launched: every script this run will execute
# on an instance has to be in the upload, and the upload is `git ls-files`.
require_tracked \
    scripts/aws/setup_ec2_server.sh scripts/aws/setup_ec2_load.sh \
    scripts/aws/setup/lib.sh scripts/aws/setup/packages.sh \
    scripts/aws/setup/tuning.sh scripts/aws/setup/loadgen.sh \
    scripts/aws/setup/build_sarm.sh scripts/aws/setup/report.sh \
    scripts/benchmarks/rps_bench.sh

RUNID="$(date +%Y%m%d-%H%M%S)"
TAG="sarm-twobox-$RUNID"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sarm-twobox-XXXXXX")"
LOCAL_OUT="$REPO/perf-results/two-box-$RUNID"
AWSC=()
KEYFILE=""
KEY_EPHEMERAL=0
SG_ID=""
SG_INTERNAL=1           # the two boxes must be able to talk to each other
ONDEMAND=""
SPOT_AZS=""
WATCHDOG=""
STARTED=$(date +%s)
INSTANCE_IDS=()
SERVER_ID=""; LOAD_ID=""
SERVER_IP=""; LOAD_IP=""; SERVER_PRIVATE_IP=""

# ── sizing the load box against the server ────────────────────────────
# The whole design rests on the client never being the slowest part of the
# loop, and "never" is a function of how big the server is. Pinning the
# load box to one type means every --server-type change silently moves the
# ratio — a c6gn.8xlarge that gives 16:1 against 2 server cores gives 4:1
# against 8, which is break-even and no longer safe.
#
# So it is derived by default: the smallest size in the server's own family
# with at least LOAD_RATIO times its cores. Same family means same
# generation and same clocks, so the ratio is in cores rather than in
# vaguely comparable machines. An explicit --load-type is honoured as
# given, and checked rather than resized.
resolve_load_type() {
    local svcpus want family size
    svcpus="$(itype_vcpus_static "$SERVER_TYPE")" \
        || die "cannot size a load box against '$SERVER_TYPE' — pass --load-type explicitly"
    SERVER_VCPUS_PLANNED="$svcpus"
    want=$(( svcpus * LOAD_RATIO ))

    [ "$LOAD_TYPE" != auto ] && return 0

    family="${SERVER_TYPE%%.*}"
    # Up to 48xlarge: families like c8gn go to 192 vCPUs, and stopping the
    # search at 16xlarge silently returned a 64-core client for a job
    # wanting 96 — a 2:1 ratio under a flag that said 3:1. Sizes absent
    # from a family are simply never offered there, and the region probe
    # rejects the pair before anything is launched.
    for size in large xlarge 2xlarge 4xlarge 8xlarge 12xlarge 16xlarge 24xlarge 48xlarge; do
        if [ "$(itype_vcpus_static "x.$size")" -ge "$want" ]; then
            LOAD_TYPE="$family.$size"
            return 0
        fi
    done
    # Past the top of the family there is nothing bigger to ask for. Say so
    # rather than quietly returning a box that cannot drive the server:
    # the run still works, and the load-side measurement below is what will
    # show whether it was enough.
    LOAD_TYPE="$family.48xlarge"
    warn "a ${LOAD_RATIO}:1 load box for $SERVER_TYPE would need $want vCPUs;"
    warn "$LOAD_TYPE is the largest size this script will ask for, at 192."
    warn "The summary reports the client's own busy cores — read it before"
    warn "quoting req/s."
}
resolve_load_type

# The pair, in the order launch_group_in_region() walks them. Both lists
# are consumed positionally, so they stay in step.
ITYPES="$SERVER_TYPE $LOAD_TYPE"
IROLES="server load"

# ── cleanup ───────────────────────────────────────────────────────────
# Runs on every exit path — success, failure (set -e), Ctrl-C, watchdog
# TERM. Each step is independently best-effort: a failure deleting the
# security group must never skip terminating the instances, and there are
# two of them here rather than one.
RESULTS_FETCHED=0
fetch_results() {
    [ "$RESULTS_FETCHED" = 1 ] && return 0
    RESULTS_FETCHED=1
    mkdir -p "$LOCAL_OUT"
    cp "$WORK"/*.log "$WORK"/*.json "$WORK"/summary.txt "$LOCAL_OUT/" 2>/dev/null || true
    # Empty stubs are what a redirection leaves behind when the ssh it
    # wrapped never connected; neither they nor the empty directory are
    # worth keeping in perf-results/.
    find "$LOCAL_OUT" -maxdepth 1 -type f -empty -delete 2>/dev/null || true
    if rmdir "$LOCAL_OUT" 2>/dev/null; then
        warn "nothing was retrieved"
    else
        info "results in $LOCAL_OUT"
    fi
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    [ -n "$WATCHDOG" ] && kill "$WATCHDOG" 2>/dev/null || true

    fetch_results || warn "could not save the results"

    if [ ${#INSTANCE_IDS[@]} -gt 0 ]; then
        if [ "$KEEP" = 1 ]; then
            say "Leaving ${INSTANCE_IDS[*]} running (--keep)"
            warn "you are being billed for BOTH. Terminate with:"
            warn "  aws ec2 terminate-instances --region $REGION --instance-ids ${INSTANCE_IDS[*]}"
            warn "they will self-terminate after ${DEADMAN} minutes regardless."
            if [ "$KEY_EPHEMERAL" = 1 ]; then info "ephemeral ssh key kept at $KEYFILE"; fi
            if [ -n "$SERVER_IP" ]; then info "server: ssh -i $KEYFILE ubuntu@$SERVER_IP"; fi
            if [ -n "$LOAD_IP" ];   then info "load:   ssh -i $KEYFILE ubuntu@$LOAD_IP"; fi
            # Queued rather than deleted: the group is in use for as long
            # as you keep the boxes, and the sweep skips it until it is not.
            if [ -n "$SG_ID" ]; then defer_security_group "$SG_ID" "$REGION"; fi
            if [ -n "${PG_NAME:-}" ]; then defer_placement_group "$PG_NAME" "$REGION"; fi
            printf '\n'
            exit "$rc"
        fi
        say "Terminating ${INSTANCE_IDS[*]}"
        # The API call is what stops the billing clock; the instances
        # reaching the terminated state can take minutes and there is
        # nothing here that needs to see it happen.
        "${AWSC[@]}" ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" \
            --query 'TerminatingInstances[].CurrentState.Name' 2>&1 | sed 's/^/   /' || \
            warn "terminate call failed — CHECK THE CONSOLE for ${INSTANCE_IDS[*]}"
    fi

    # After the terminate, not before: the terminate is what stops the
    # billing clock, and this runs on the no-instance paths too.
    cancel_spot_requests ${INSTANCE_IDS[@]+"${INSTANCE_IDS[@]}"} \
        || warn "spot request cleanup failed"

    if [ -n "$SG_ID" ]; then defer_security_group "$SG_ID" "$REGION"; fi
    # Same reason as the security group: a placement group cannot be
    # deleted while an instance is still in it, and we are not waiting.
    if [ -n "${PG_NAME:-}" ]; then defer_placement_group "$PG_NAME" "$REGION"; fi
    if [ "$KEY_EPHEMERAL" = 1 ] && [ -n "$KEY_NAME" ]; then
        "${AWSC[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 \
            && info "deleted key pair $KEY_NAME" || warn "could not delete key pair $KEY_NAME"
    fi
    rm -rf "$WORK"

    local mins=$(( ($(date +%s) - STARTED) / 60 ))
    info "elapsed: ${mins} min of $SERVER_TYPE + $LOAD_TYPE time"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ── 0. collect what earlier runs left behind ──────────────────────────
sweep_pending_security_groups
if [ "$SWEEP_ONLY" = 1 ]; then
    report_pending_security_groups
    # Nothing was measured, so there is nothing for cleanup to save and no
    # reason for it to say so.
    RESULTS_FETCHED=1
    exit 0
fi

# ── 1. where to rent ──────────────────────────────────────────────────
say "Choosing a region"
if [ -n "$AMI" ] && [ "$(printf '%s' "$REGION_CANDIDATES" | wc -w)" -gt 1 ]; then
    REGION_CANDIDATES="${REGION_CANDIDATES%% *}"
    warn "--ami is region-specific; only $REGION_CANDIDATES will be tried"
fi
AMI_SSM="/aws/service/canonical/ubuntu/server/$UBUNTU/stable/current/arm64/hvm/ebs-gp3/ami-id"
AMI_PINNED="$AMI"
PENDING_REGIONS="$REGION_CANDIDATES"

next_region || no_region_left
price_region

# ── 2. plan ───────────────────────────────────────────────────────────
say "Plan"
printf '   %-14s %s\n' region "$REGION — $(region_name "$REGION")" \
    server "$SERVER_TYPE (${SERVER_VCPUS_PLANNED} vCPU) — runs only sarm" \
    load   "$LOAD_TYPE — runs only wrk/h2load, sized ${LOAD_RATIO}:1 to the server" \
    az     "$AZ" ubuntu "$UBUNTU" ami "$AMI" \
    protocols "$PROTOCOLS" \
    load-shape "${DURATION}s x $REPEAT, -m$MAX_STREAMS, pipeline $PIPELINE" \
    timeout "${TIMEOUT}s (deadman ${DEADMAN}m)" \
    results "$LOCAL_OUT"
printf '   %-14s %s\n' zones "$AZS" market "$(market_summary)" \
    placement "$([ "$PLACEMENT" = 1 ] \
        && echo 'cluster placement group — shortest path EC2 will give them' \
        || echo 'none (--no-placement-group) — an ordinary VPC hop')"
if [ "$CONNECTIONS" -eq 0 ]; then
    printf '   %-14s %s\n' connections \
        "$CONNS_PER_CORE per server vCPU — the exact count is derived on the box, from its own nproc"
else
    printf '   %-14s %s\n' connections "$CONNECTIONS"
fi
if [ -n "$PENDING_REGIONS" ]; then
    fallbacks=""
    for r in $PENDING_REGIONS; do fallbacks="$fallbacks $r ($(region_name "$r")),"; done
    printf '   %-14s %s\n' fallbacks \
        "${fallbacks# } — not checked yet, only if $REGION is out of capacity"
fi

if [ "$ASSUME_YES" != 1 ]; then
    printf '\n   TWO instances, both billed from boot. Launch? [y/N] '
    read -r reply
    # Nothing was launched and nothing was measured; cleanup should say
    # neither "terminating" nor "nothing was retrieved".
    case "$reply" in [yY]*) ;; *) INSTANCE_IDS=(); RESULTS_FETCHED=1; die "aborted" ;; esac
fi

# ── 3. key pair, security group, launch ───────────────────────────────
KEY_NAME_REQUESTED="$KEY_NAME"
KEY_FILE_REQUESTED="$KEY_FILE"
resolve_ssh_cidr
write_user_data "$DEADMAN"

LAUNCHED=0
TRIED=""
while :; do
    say "Launching $SERVER_TYPE + $LOAD_TYPE in $REGION / $(region_name "$REGION")"
    TRIED="$TRIED $REGION"
    setup_keypair
    setup_security_group
    setup_placement_group
    if launch_group_in_region; then LAUNCHED=1; break; fi

    warn "no zone in $REGION ($(region_name "$REGION")) could hold both"
    release_region
    next_region || break
    # Priced from scratch: the zone order, the spot verdict and the
    # on-demand rate are all per region, and a fallback that kept the
    # first region's answers would launch on-demand in every zone of the
    # second while claiming otherwise in the plan.
    price_region
    info "market: $(market_summary)"
done

if [ "$LAUNCHED" != 1 ]; then
    INSTANCE_IDS=()
    die "no region tried could run $SERVER_TYPE and $LOAD_TYPE in one zone:${TRIED}
   Nothing is running and nothing is billed. Options: wait and re-run,
   pick other types with --server-type/--load-type, or name a region
   directly with --region."
fi

INSTANCE_IDS=("${LAUNCHED_IDS[@]}")
SERVER_ID="${LAUNCHED_IDS[0]}"
LOAD_ID="${LAUNCHED_IDS[1]}"
info "server $SERVER_ID, load $LOAD_ID — both in $AZ"

# The watchdog is armed only now — before this point there is nothing to
# leak, and after it the trap does the right thing on TERM.
( sleep "$TIMEOUT"; kill -TERM $$ 2>/dev/null ) &
WATCHDOG=$!
# Killing it on the way out is normal and expected, but the shell reaps it
# noisily on top of whatever the run was reporting. Disowning it drops the
# job-table entry, so cleanup can still kill the pid and nothing is printed.
disown "$WATCHDOG" 2>/dev/null || true

say "Waiting for both instances to boot"
"${AWSC[@]}" ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"
SERVER_IP="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$SERVER_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress')"
# The PRIVATE address is what the benchmark uses. Same zone, same VPC: no
# NAT, no internet gateway, no per-gigabyte charge, and a link whose
# latency is a property of the datacentre rather than of the route home.
SERVER_PRIVATE_IP="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$SERVER_ID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress')"
LOAD_IP="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$LOAD_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress')"
info "server $SERVER_IP (private $SERVER_PRIVATE_IP)"
info "load   $LOAD_IP"

# Checked, not assumed. launch_group_in_region() resolves ONE subnet per
# zone and puts both instances in it, so this should never fire — but the
# cost of it being wrong is silent: cross-AZ traffic is billed per
# gigabyte in both directions and adds latency that would land in the
# req/s figure as if it were the server's. A benchmark that quietly
# measures the network instead of sarm is worse than one that stops.
SERVER_AZ="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$SERVER_ID" \
    --query 'Reservations[0].Instances[0].Placement.AvailabilityZone')"
LOAD_AZ="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$LOAD_ID" \
    --query 'Reservations[0].Instances[0].Placement.AvailabilityZone')"
if [ "$SERVER_AZ" != "$LOAD_AZ" ]; then
    die "the two instances landed in different zones ($SERVER_AZ vs $LOAD_AZ).
   Cross-zone traffic is billed per gigabyte and is slower, so this would
   measure the network rather than sarm. Both are being terminated."
fi
# 10/8, 172.16/12 and 192.168/16 are the private ranges; anything else
# means the traffic would leave the VPC and be billed as egress.
case "$SERVER_PRIVATE_IP" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
    *) die "the server's benchmark address $SERVER_PRIVATE_IP is not an RFC1918
   private address, so the load would leave the VPC and be billed as
   egress. Both are being terminated." ;;
esac
info "both in $SERVER_AZ, over private addresses — no cross-zone or egress charges"

SSH_OPTS=()
while IFS= read -r o; do SSH_OPTS+=("$o"); done <<< "$(ssh_opts)"
SERVER_REMOTE="ubuntu@$SERVER_IP"
LOAD_REMOTE="ubuntu@$LOAD_IP"
srv() { ssh "${SSH_OPTS[@]}" "$SERVER_REMOTE" "$@"; }
lod() { ssh "${SSH_OPTS[@]}" "$LOAD_REMOTE" "$@"; }

say "Waiting for sshd on both"
wait_for_ssh server "$SERVER_REMOTE" "${SSH_OPTS[@]}"
wait_for_ssh load   "$LOAD_REMOTE"   "${SSH_OPTS[@]}"

# ── 4. upload and provision, both at once ─────────────────────────────
# The same tarball goes to both boxes: it is small, and the load box needs
# scripts/benchmarks/rps_bench.sh and pipeline.lua out of it anyway. What
# differs is what each box then INSTALLS, which is the whole point of the
# setup_ec2_server / setup_ec2_load split — the load box builds no sarm
# and the server box installs no load generator.
say "Uploading the working tree to both"
upload_tree "$SERVER_REMOTE" "${SSH_OPTS[@]}"
upload_tree "$LOAD_REMOTE"   "${SSH_OPTS[@]}"
info "unpacked to ~/sarm on both"

say "Provisioning (in parallel — the two boxes install different things)"
info "server: toolchain + sarm build   load: wrk/h2load only"
srv 'SARM_DIR=$HOME/sarm ~/sarm/scripts/aws/setup_ec2_server.sh' > "$WORK/setup-server.log" 2>&1 &
SETUP_SERVER=$!
lod 'SARM_DIR=$HOME/sarm ~/sarm/scripts/aws/setup_ec2_load.sh'   > "$WORK/setup-load.log" 2>&1 &
SETUP_LOAD=$!
server_rc=0; load_rc=0
wait "$SETUP_SERVER" || server_rc=$?
wait "$SETUP_LOAD"   || load_rc=$?
if [ "$server_rc" != 0 ]; then
    tail -25 "$WORK/setup-server.log" | sed 's/^/     /'
    die "provisioning the server box failed — see $LOCAL_OUT/setup-server.log"
fi
if [ "$load_rc" != 0 ]; then
    tail -25 "$WORK/setup-load.log" | sed 's/^/     /'
    die "provisioning the load box failed — see $LOCAL_OUT/setup-load.log"
fi
info "server: $(grep -c . "$WORK/setup-server.log") lines, load: $(grep -c . "$WORK/setup-load.log") lines (both saved)"

# Provisioning installs packages, and on Ubuntu that can still restart
# sshd underneath us even with the updaters quiesced. Re-establish both
# connections before anything depends on them, rather than discovering it
# one command later and calling it a failure.
say "Re-checking ssh after provisioning"
wait_for_ssh server "$SERVER_REMOTE" "${SSH_OPTS[@]}"
wait_for_ssh load   "$LOAD_REMOTE"   "${SSH_OPTS[@]}"

SERVER_CPUS_N="$(srv nproc 2>/dev/null | tr -d '\r' | head -1)"
LOAD_CPUS_N="$(lod nproc 2>/dev/null | tr -d '\r' | head -1)"
case "${SERVER_CPUS_N:-}" in ''|*[!0-9]*) SERVER_CPUS_N=1 ;; esac
case "${LOAD_CPUS_N:-}"   in ''|*[!0-9]*) LOAD_CPUS_N=1 ;; esac
info "server has $SERVER_CPUS_N vCPU, load box has $LOAD_CPUS_N"
info "$(awk -v l="$LOAD_CPUS_N" -v s="$SERVER_CPUS_N" \
    'BEGIN{printf "%.1f:1 client cores per server core", (s>0?l/s:0)}')"
if [ "$LOAD_CPUS_N" -lt $(( SERVER_CPUS_N * 2 )) ]; then
    warn "the load box has only $LOAD_CPUS_N cores to the server's $SERVER_CPUS_N."
    warn "Measured worst case is ~1.5 client cores per server core (TLS), so below"
    warn "2:1 there is no margin left and the client can be the side that runs out."
    warn "Raise --load-ratio, or name a --load-type."
fi

# ── 5. size the load ──────────────────────────────────────────────────
# Derived here rather than in the options block because it needs both
# machines' core counts, and neither belongs to this laptop.
if [ "$CONNECTIONS" -eq 0 ]; then
    CONNECTIONS=$(( SERVER_CPUS_N * CONNS_PER_CORE ))
    [ "$CONNECTIONS" -lt 16 ] && CONNECTIONS=16
fi
if [ "$THREADS" -eq 0 ]; then
    # One client thread per load core, capped at the connection count:
    # h2load requires connections >= threads, and a thread count above it
    # is rejected rather than merely wasteful.
    THREADS=$LOAD_CPUS_N
    [ "$THREADS" -gt "$CONNECTIONS" ] && THREADS=$CONNECTIONS
fi
info "$CONNECTIONS connections x $MAX_STREAMS streams = $(( CONNECTIONS * MAX_STREAMS )) requests in flight (h2)"
info "$THREADS client threads on $LOAD_CPUS_N load cores"

if [ "$SKIP_BENCH" = 1 ]; then
    say "--setup-only: both boxes are provisioned, stopping before the benchmark"
    info "server: ssh -i $KEYFILE $SERVER_REMOTE"
    info "load:   ssh -i $KEYFILE $LOAD_REMOTE"
    exit 0
fi

# ── 6. start sarm on the server box ───────────────────────────────────
# setsid + nohup because the ssh that starts it goes away immediately; the
# server has to outlive its own launch. On Linux sarm binds 0.0.0.0 (see
# `addr:` in src/sarm/main.S), so the load box reaches it on the private
# address without anything being changed here.
say "Starting sarm on the server box"
# THE REDIRECTIONS BELONG TO THE GROUP, NOT TO THE COMMAND INSIDE IT, and
# getting that wrong costs the whole run rather than failing visibly.
#
# ssh does not return until nothing on the far side still holds the
# channel's stdout and stderr. Written the obvious way —
#
#     setsid ./sarm ... > log 2>&1 < /dev/null &
#
# — the redirections bind to the `setsid` simple command, so sarm's own
# fds are the log file and everything looks correct. But the `&` puts that
# command in a background SUBSHELL, and the subshell inherited fd 1 and 2
# from ssh and was never redirected. It survives long enough to hold the
# channel open, and the ssh hangs forever: the 2026-08-29 run sat at this
# line printing "started" while `/proc/<pid>/fd` on the box showed the
# wrapper still pointing at `pipe:[...]`. sarm itself was up and serving
# 200s the whole time.
#
# So the redirections go on the `{ ...; }` group, which is what the `&`
# backgrounds — every fd in the subshell is then the log file or
# /dev/null before anything runs. `exec` replaces the subshell rather than
# leaving a shell parked behind sarm, `setsid` detaches it from the
# session so channel teardown cannot SIGHUP it, and 3>&- 4>&- matches
# every other sarm launch site in this repo (see rps_bench.sh).
start_sarm() {
    srv "{ cd \$HOME/sarm && exec setsid ./sarm $PORT --workers $WORKERS; } \
         > \$HOME/sarm-server.log 2>&1 < /dev/null 3>&- 4>&- & echo started" \
        >/dev/null 2>&1
}
# Polled rather than started-and-hoped. A single ssh that fails here is not
# evidence that sarm is broken — it is more often evidence that the box is
# still settling — so the start is retried and the readiness check is given
# a real deadline. Two whole instances are already billing by this point;
# failing on the first refused connection throws that away.
SARM_UP=0
for attempt in 1 2 3; do
    # Belt and braces on top of the redirection fix above: a start that
    # somehow still holds the channel is capped rather than allowed to
    # stall the run until the hour-long watchdog fires, with two instances
    # billing the whole time.
    start_sarm & START_PID=$!
    ( sleep 30; kill -9 "$START_PID" 2>/dev/null ) & START_KILLER=$!
    disown "$START_KILLER" 2>/dev/null || true
    wait "$START_PID" 2>/dev/null || warn "the start command did not return cleanly"
    kill "$START_KILLER" 2>/dev/null || true
    for _ in $(seq 1 20); do
        if srv "curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:$PORT/" 2>/dev/null; then
            SARM_UP=1; break
        fi
        sleep 3
    done
    [ "$SARM_UP" = 1 ] && break
    warn "sarm not answering yet on the server box (attempt $attempt of 3)"
done
if [ "$SARM_UP" != 1 ]; then
    # Whatever the box will still tell us. Short timeouts and || true
    # throughout: this runs when the box is already misbehaving, and a
    # diagnostic that hangs is worse than no diagnostic.
    warn "diagnostics from the server box:"
    srv "tail -20 \$HOME/sarm-server.log 2>&1;
         echo '--- processes ---'; pgrep -a sarm 2>&1 | head -5;
         echo '--- listening ---'; ss -ltnp 2>&1 | head -5;
         echo '--- uptime ---'; uptime; who -b 2>&1;
         echo '--- last kernel messages ---'; dmesg 2>&1 | tail -15" \
        2>&1 | sed 's/^/     /' || true
    die "sarm did not answer on the server box's own loopback"
fi
info "answering on 127.0.0.1:$PORT (workers: $WORKERS)"
# And from the other machine, which is the path that actually matters: a
# server that answers itself but not the load box is a security group
# problem, and it is much cheaper to find out now than one load window in.
REACHED=0
for _ in $(seq 1 10); do
    if lod "curl -fsS --max-time 10 -o /dev/null http://$SERVER_PRIVATE_IP:$PORT/" 2>/dev/null; then
        REACHED=1; break
    fi
    sleep 3
done
if [ "$REACHED" != 1 ]; then
    die "the load box cannot reach $SERVER_PRIVATE_IP:$PORT — check the security group"
fi
info "reachable from the load box at $SERVER_PRIVATE_IP:$PORT"

# ── 7. the benchmark ──────────────────────────────────────────────────
# One protocol at a time, each with its own server-side CPU sample, so
# "did the server saturate" is answered per protocol rather than averaged
# across three of them.
#
# The sample is the whole /proc/stat cpu line, before and after. Busy is
# everything that is not idle or iowait; expressed as a fraction of the
# total it becomes busy CORES once multiplied by nproc, which is the
# figure that stays comparable when the instance type changes.
# <side> is srv or lod — the function that runs a command on that box.
cpu_snapshot() { "$1" 'head -1 /proc/stat' 2>/dev/null | tr -d '\r'; }
busy_cores() {  # busy_cores <before> <after> <ncpu>
    awk -v b="$1" -v a="$2" -v n="$3" 'BEGIN {
        split(b, x, " "); split(a, y, " ")
        tot = 0; idle = 0
        for (i = 2; i <= 11; i++) { d = y[i] - x[i]; if (d < 0) d = 0; tot += d
                                    if (i == 5 || i == 6) idle += d }
        if (tot <= 0) { print "?"; exit }
        printf "%.2f", (tot - idle) / tot * n
    }'
}

: > "$WORK/summary.txt"
note() { printf '%s\n' "$*" | tee -a "$WORK/summary.txt"; }

{
    echo "run           : $RUNID"
    echo "region        : $REGION ($(region_name "$REGION")), zone $AZ"
    echo "server        : $SERVER_TYPE, $SERVER_CPUS_N vCPU, $SERVER_ID"
    echo "load          : $LOAD_TYPE, $LOAD_CPUS_N vCPU, $LOAD_ID"
    echo "link          : private VPC address $SERVER_PRIVATE_IP:$PORT"
    echo "zone          : $SERVER_AZ (both instances, checked) — no cross-zone or egress charges"
    echo "core ratio    : $(awk -v l="$LOAD_CPUS_N" -v s="$SERVER_CPUS_N" \
                              'BEGIN{printf "%.1f:1 client per server", (s>0?l/s:0)}')"
    echo "placement     : $([ -n "${PG_NAME:-}" ] && echo "cluster group $PG_NAME" || echo none)"
    echo "market        : $(market_summary)"
    echo "workers       : $WORKERS"
    echo "shape         : -c$CONNECTIONS -t$THREADS -m$MAX_STREAMS, ${DURATION}s x $REPEAT, warm-up ${WARMUP}s, pipeline $PIPELINE"
    echo "path          : $REQ_PATH"
    sed 's/^/provenance    : /' "$WORK/provenance" 2>/dev/null
} > "$WORK/environment.log"

say "Benchmarking (the load box drives, the server box is measured)"
for proto in $PROTOCOLS; do
    info "── $proto ──"
    # BOTH sides, over the same window. The server's busy cores say
    # whether sarm saturated; the client's say whether it had room to
    # spare, which is the only evidence that the number is sarm's ceiling
    # and not the load box's. Measuring one without the other is how a
    # client-bound run gets published as a server result.
    before="$(cpu_snapshot srv)"
    lbefore="$(cpu_snapshot lod)"
    if ! lod "cd \$HOME/sarm && ./scripts/benchmarks/rps_bench.sh \
            --target $SERVER_PRIVATE_IP:$PORT --only $proto --json \
            --duration $DURATION --repeat $REPEAT --warm-up $WARMUP \
            --connections $CONNECTIONS --threads $THREADS \
            --max-streams $MAX_STREAMS --pipeline $PIPELINE --path '$REQ_PATH'" \
            > "$WORK/$proto.json" 2> "$WORK/$proto.log"; then
        warn "$proto failed — see $proto.log"
        tail -8 "$WORK/$proto.log" | sed 's/^/     /'
        continue
    fi
    after="$(cpu_snapshot srv)"
    lafter="$(cpu_snapshot lod)"
    BUSY="$(busy_cores "$before" "$after" "$SERVER_CPUS_N")"
    LBUSY="$(busy_cores "$lbefore" "$lafter" "$LOAD_CPUS_N")"
    # The busy figure belongs with the throughput figure, so it is folded
    # into the same JSON rather than kept in a second file that a later
    # reader has to remember to join.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$WORK/$proto.json" "$BUSY" "$SERVER_CPUS_N" "$LBUSY" "$LOAD_CPUS_N" <<'PYEOF' || true
import json, sys
path, busy, ncpu, lbusy, lcpu = sys.argv[1:6]
try:
    d = json.load(open(path))
except Exception:
    sys.exit(0)
num = lambda v: None if v == "?" else float(v)
d["server_busy_cores"] = num(busy)
d["server_cores"] = int(ncpu)
d["client_busy_cores"] = num(lbusy)
d["client_cores"] = int(lcpu)
json.dump(d, open(path, "w"), indent=1)
PYEOF
    fi
    info "server busy: $BUSY of $SERVER_CPUS_N cores, client busy: $LBUSY of $LOAD_CPUS_N"
done

# ── 8. the readout ────────────────────────────────────────────────────
# Ordered by what has to be true before the next line means anything: was
# the server the thing that ran out, and only then how many requests it
# served. Quoting req/s first is how a client-bound run gets misread.
say "Results"
note "sarm on $SERVER_TYPE ($SERVER_CPUS_N vCPU), driven from $LOAD_TYPE ($LOAD_CPUS_N vCPU)"
note "-c$CONNECTIONS -t$THREADS -m$MAX_STREAMS, ${DURATION}s x $REPEAT, over the VPC in $AZ"
note ""
VERDICT_WARN=0
for proto in $PROTOCOLS; do
    [ -s "$WORK/$proto.json" ] || continue
    line="$(python3 - "$WORK/$proto.json" "$proto" <<'PYEOF' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1]))
proto = sys.argv[2]
key = {"h1": "http1", "h2c": "http2_h2c", "h2tls": "http2_tls"}[proto]
name = {"h1": "HTTP/1.1", "h2c": "HTTP/2 h2c", "h2tls": "HTTP/2 + TLS"}[proto]
rps = d.get(key + "_rps")
spread = d.get(key + "_spread_pct", 0)
lat = d.get(key + "_latency_us")
busy = d.get("server_busy_cores")
cores = d.get("server_cores") or 1
cbusy = d.get("client_busy_cores")
ccores = d.get("client_cores") or 1
if rps is None:
    print(f"{name:<13}: no result"); sys.exit(0)
per = f"{rps / busy:,.0f}/busy core" if busy else "server load unknown"
pct = f"{busy / cores * 100:.0f}%" if busy is not None else "?"
lat_s = f"{lat:.0f}us" if lat is not None else "?"
# The client column is the one that says whether to believe the rest of
# the line: a saturated server next to a saturated client is not a server
# measurement, however good the req/s looks.
cli = (f"client {cbusy}/{ccores} ({cbusy / ccores * 100:.0f}%)"
       if cbusy is not None else "client ?")
print(f"{name:<13}: {rps:>12,.0f} req/s (+/-{spread}%)  {lat_s:>8} mean  "
      f"server {busy if busy is not None else '?'}/{cores} ({pct})  {cli}  {per}")
PYEOF
)"
    if [ -n "$line" ]; then note "$line"; fi
done

# What the pair actually cost, as opposed to what it was provisioned for.
# This is the number that should set --load-ratio on the next run, and the
# only reason the default is 3 rather than the 8 it started at: the figure
# quoted everywhere for h2load's cost (~4x sarm) is a LOOPBACK figure and
# does not survive the move to two boxes.
RATIO_NOTE="$(python3 - "$WORK" $PROTOCOLS <<'PYEOF' 2>/dev/null || true
import json, os, sys
work = sys.argv[1]
worst = None
for proto in sys.argv[2:]:
    p = os.path.join(work, proto + ".json")
    if not os.path.exists(p):
        continue
    try:
        d = json.load(open(p))
    except Exception:
        continue
    s, c = d.get("server_busy_cores"), d.get("client_busy_cores")
    if not s or c is None:
        continue
    r = c / s
    worst = r if worst is None else max(worst, r)
if worst is not None:
    print(f"{worst:.2f}")
PYEOF
)"
if [ -n "$RATIO_NOTE" ]; then
    note ""
    note "Client cost: $RATIO_NOTE client cores per busy server core, worst protocol."
    note "This run provisioned ${LOAD_RATIO}:1. A ratio of $(awk -v r="$RATIO_NOTE" \
        'BEGIN{printf "%.0f", (r*2 < 2 ? 2 : r*2)}') would keep a 2x margin over that."
fi

note ""
# The verdict. Anything under ~85% of the server's cores means the server
# was NOT the slowest part of the loop, and the number above is then a
# statement about whatever else was — the concurrency ceiling, the client,
# or the link.
# Two questions, in order: did the CLIENT run out (which invalidates
# everything), and only then did the server saturate. Answered over every
# protocol, worst case wins.
SATURATED="$(python3 - "$WORK" $PROTOCOLS <<'PYEOF' 2>/dev/null || echo unknown
import json, os, sys
work = sys.argv[1]
worst = None
client_peak = None
for proto in sys.argv[2:]:
    p = os.path.join(work, proto + ".json")
    if not os.path.exists(p):
        continue
    try:
        d = json.load(open(p))
    except Exception:
        continue
    busy, cores = d.get("server_busy_cores"), d.get("server_cores")
    cbusy, ccores = d.get("client_busy_cores"), d.get("client_cores")
    if cbusy is not None and ccores:
        f = cbusy / ccores
        client_peak = f if client_peak is None else max(client_peak, f)
    if busy is None or not cores:
        continue
    frac = busy / cores
    worst = frac if worst is None else min(worst, frac)
# The client running out is reported first and on its own: a run in that
# state has no server measurement in it to report.
if client_peak is not None and client_peak >= 0.85:
    print(f"client-bound {client_peak * 100:.0f}")
elif worst is None:
    print("unknown")
elif worst >= 0.85:
    print("saturated")
else:
    print(f"{worst * 100:.0f}")
PYEOF
)"
case "$SATURATED" in
    client-bound*)
        VERDICT_WARN=1
        note "CLIENT-BOUND — the load box peaked at ${SATURATED##* }% of its ${LOAD_CPUS_N} cores."
        note "The figures above are the LOAD GENERATOR's ceiling, not sarm's. Re-run with"
        note "a bigger client: --load-ratio $(( LOAD_RATIO * 2 )), or --load-type explicitly." ;;
    saturated)
        note "SERVER SATURATED — every protocol above kept the server's cores busy,"
        note "and the client stayed below 85% of its ${LOAD_CPUS_N} cores throughout."
        note "These are sarm's numbers: the load box had room to push harder and sarm could not take it." ;;
    unknown)
        note "Could not read the server's CPU time, so nothing here says whether"
        note "sarm was the bottleneck. Treat every figure above as a lower bound." ;;
    *)
        VERDICT_WARN=1
        note "NOT SATURATED — the quietest protocol left the server at ${SATURATED}% of its cores."
        note "Something other than sarm was binding. In order of likelihood:"
        note "  * the concurrency ceiling: raise --max-streams above $MAX_STREAMS"
        note "  * too few connections for $SERVER_CPUS_N cores: raise --conns-per-core above $CONNS_PER_CORE"
        note "  * the server is too big to fill: --server-type ${SERVER_TYPE%%.*}.large"
        # The one that cost a whole run to find. A server sitting well
        # below its cores while the client is idle too is the shape of a
        # network limit, not of a server with nothing to do.
        note "  * the NIC, not the CPU: a burstable-network family (c7g and"
        note "    friends) runs out of packets first on small responses."
        note "    c6gn/c7gn have dedicated bandwidth — see the header." ;;
esac

fetch_results
if [ "$VERDICT_WARN" = 1 ]; then
    warn "read the verdict above before quoting any of these figures"
fi

# cleanup() terminates both instances on the way out
