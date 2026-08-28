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
#   1. SSH key pair (yours if you have one, else ephemeral) + security
#      group locked to your public IP
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
#   ./scripts/aws/quick_test_ec2.sh --timeout 5400
#   ./scripts/aws/quick_test_ec2.sh --keep                 # leave it running
#   ./scripts/aws/quick_test_ec2.sh --sweep-only           # just drain the
#                                                          # deferred SG list
#
# Needs: awscli v2 with credentials, ssh, scp, git. c6g.metal counts 64
# vCPUs against the "Running On-Demand Standard instances" quota in the
# target region — if that quota is still the default 5, that region is
# skipped during the plan rather than failing mid-launch. Capacity itself
# cannot be queried, only attempted: the launch walks every zone of the
# chosen region and then the next region, and nothing is billed until one
# of those attempts succeeds.

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"

# ── options ───────────────────────────────────────────────────────────
# Candidate regions, in preference order. The script probes each one for
# image + instance-type offering + vCPU quota before it launches anything,
# and falls through to the next when a region turns out to have no
# capacity. --region pins it to exactly one.
REGION_CANDIDATES="${SARM_EC2_REGIONS:-ap-southeast-4 ap-southeast-2 us-east-1 us-west-2}"
                        # Melbourne, Sydney, N. Virginia, Oregon
REGION=""               # chosen from the above during the plan
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

# Security groups awaiting deletion, one "<region> <sg-id> <tag>" per line.
PENDING_SG_FILE="${SARM_PENDING_SG_FILE:-${XDG_CACHE_HOME:-$HOME/.cache}/sarm/pending-security-groups}"

while [ $# -gt 0 ]; do
    case "$1" in
        --region)      REGION_CANDIDATES="$2"; shift ;;
        --regions)     REGION_CANDIDATES="$2"; shift ;;
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

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '\033[1;33m   WARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

for tool in aws ssh scp git; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done

RUNID="$(date +%Y%m%d-%H%M%S)"
TAG="sarm-quicktest-$RUNID"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sarm-ec2-XXXXXX")"
KEYFILE=""
LOCAL_OUT="$REPO/perf-results/ec2-$RUNID"
AWSC=()                 # rebuilt once the region is chosen

INSTANCE_ID=""
SG_ID=""
KEY_EPHEMERAL=0     # 1 only when this run created the key pair in AWS
WATCHDOG=""
STARTED=$(date +%s)
RESULTS_FETCHED=0

# ── deferred security-group deletion ──────────────────────────────────
# A security group is still attached to a terminating instance for as long
# as that instance takes to disappear, which on bare metal is minutes. We
# refuse to pay for that wall-clock, so instead of waiting we write the
# group down and let a later run collect it. The list is plain text, one
# "<region> <sg-id> <tag>" per line, and is rewritten atomically so two
# scripts racing on it cannot leave it half-written.
defer_security_group() {
    local sg="$1"
    mkdir -p "$(dirname "$PENDING_SG_FILE")" 2>/dev/null || return 0
    printf '%s %s %s\n' "$REGION" "$sg" "$TAG" >> "$PENDING_SG_FILE" || return 0
    info "security group $sg queued for deletion on a later run"
}

# Try every group on the list; drop the ones that go away, keep the ones
# that are still held by an instance that has not finished dying. Entirely
# best-effort: this must never be a reason for a run to fail or to stall,
# so it never waits on anything and always returns 0.
sweep_pending_security_groups() {
    [ -s "$PENDING_SG_FILE" ] || return 0

    local tmp kept=0 gone=0 err region sg tag
    tmp="$(mktemp "${PENDING_SG_FILE}.XXXXXX")" || return 0

    while read -r region sg tag; do
        [ -n "${sg:-}" ] || continue
        if err="$(aws --region "$region" --output text \
                    ec2 delete-security-group --group-id "$sg" 2>&1)"; then
            gone=$((gone + 1))
        elif printf '%s' "$err" | grep -q 'InvalidGroup\.NotFound'; then
            # Already deleted by hand or by an earlier run: nothing to keep.
            gone=$((gone + 1))
        else
            printf '%s %s %s\n' "$region" "$sg" "${tag:-}" >> "$tmp"
            kept=$((kept + 1))
        fi
    done < "$PENDING_SG_FILE"

    if [ -s "$tmp" ]; then
        mv "$tmp" "$PENDING_SG_FILE"
    else
        rm -f "$tmp" "$PENDING_SG_FILE"
    fi

    [ "$gone" -gt 0 ] && info "deleted $gone deferred security group(s)"
    [ "$kept" -gt 0 ] && info "$kept still attached — will retry next run"
    return 0
}

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
    if rsh "cd \$HOME/sarm/perf-results && tar -czf - '$RUNID'" > "$WORK/results.tar.gz" 2>/dev/null \
        && [ -s "$WORK/results.tar.gz" ]; then
        tar -xzf "$WORK/results.tar.gz" -C "$LOCAL_OUT" --strip-components 1 2>/dev/null || \
            warn "results tarball arrived but would not unpack"
        info "$(du -sh "$LOCAL_OUT" | cut -f1) retrieved"
    else
        warn "could not retrieve the results directory — keeping what we have locally"
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
            [ -n "$SG_ID" ] && defer_security_group "$SG_ID"
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

    # The security group cannot be deleted while the instance still holds
    # it, and we are not waiting for that. Onto the list it goes.
    if [ -n "$SG_ID" ]; then
        defer_security_group "$SG_ID"
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
    if [ -s "$PENDING_SG_FILE" ]; then
        info "still pending in $PENDING_SG_FILE:"
        sed 's/^/     /' "$PENDING_SG_FILE"
    else
        info "no security groups pending deletion"
    fi
    exit 0
fi

# ── 0. where to rent ──────────────────────────────────────────────────
# Bare metal of one type is not offered everywhere, and where it is
# offered a given zone can still be out of it. So rather than hard-coding
# one region, walk a preference list and keep the ones that survive three
# cheap, free API checks:
#
#   * Canonical publishes the Ubuntu arm64 image there,
#   * the instance type is offered in at least one availability zone,
#   * the On-Demand vCPU quota is big enough for the type.
#
# None of that proves there is capacity — only run-instances can, and the
# answer changes minute to minute. So this is a shortlist, not a decision:
# the launch below walks the zones of the winning region, and then the
# next region, until one actually hands over a machine.
#
# The order is deliberate: Melbourne and Sydney are close (latency matters
# only for the upload, but egress and instance price differ per region),
# and the US regions are the deep capacity pool that almost always has
# metal free when ap-southeast-4 does not.
# Region codes are unreadable at a glance, and picking the wrong side of
# the planet is an easy mistake to make in a hurry. The common ones are
# spelled out here; anything else is asked of AWS, which publishes the
# long names in SSM under a global path (readable from any region, so
# us-east-1 is a convention here, not a dependency on that region).
region_name() {
    case "$1" in
        ap-southeast-4) printf 'Melbourne' ;;
        ap-southeast-2) printf 'Sydney' ;;
        ap-southeast-1) printf 'Singapore' ;;
        ap-northeast-1) printf 'Tokyo' ;;
        us-east-1)      printf 'N. Virginia' ;;
        us-east-2)      printf 'Ohio' ;;
        us-west-1)      printf 'N. California' ;;
        us-west-2)      printf 'Oregon' ;;
        eu-west-1)      printf 'Ireland' ;;
        eu-central-1)   printf 'Frankfurt' ;;
        *)
            local long
            long="$(aws --region us-east-1 --output text ssm get-parameters \
                      --names "/aws/service/global-infrastructure/regions/$1/longName" \
                      --query 'Parameters[].Value' 2>/dev/null || true)"
            case "$long" in
                ''|None)  printf '%s' "$1" ;;
                # "Asia Pacific (Melbourne)" -> "Melbourne"
                *\(*\)*)  printf '%s' "${long#*(}" | tr -d ')' ;;
                *)        printf '%s' "$long" ;;
            esac ;;
    esac
}

# Its stdout is the machine-readable result line and nothing else — the
# caller captures it — so progress messages here go to stderr.
probe_region() {
    local region="$1" ami azs quota vcpus label
    label="$(printf '%-16s %-14s' "$region" "$(region_name "$region")")"
    local awsc=(aws --region "$region" --output text)

    ami="$AMI"
    if [ -z "$ami" ]; then
        ami="$("${awsc[@]}" ssm get-parameters --names "$AMI_SSM" \
                 --query 'Parameters[].Value' 2>/dev/null || true)"
    fi
    if [ -z "$ami" ] || [ "$ami" = "None" ]; then
        info "$label no Ubuntu $UBUNTU arm64 image" >&2
        return 1
    fi

    # Every zone that offers the type, not just the first: the launch loop
    # needs the alternatives when zone one is out of capacity.
    azs="$("${awsc[@]}" ec2 describe-instance-type-offerings \
             --location-type availability-zone \
             --filters "Name=instance-type,Values=$ITYPE" \
             --query 'InstanceTypeOfferings[].Location' 2>/dev/null | tr '\t' ' ' || true)"
    azs="$(printf '%s' "$azs" | tr -s ' ' | sed 's/^ *//; s/ *$//')"
    if [ -z "$azs" ] || [ "$azs" = "None" ]; then
        info "$label $ITYPE not offered" >&2
        return 1
    fi

    # The quota is per region and counts vCPUs, not instances, so a
    # 64-core metal box needs 64 against a default that is often 5. This
    # is the failure that otherwise appears as VcpuLimitExceeded several
    # minutes and one security group into the run.
    vcpus="$("${awsc[@]}" ec2 describe-instance-types --instance-types "$ITYPE" \
               --query 'InstanceTypes[0].VCpuInfo.DefaultVCpus' 2>/dev/null || true)"
    quota="$(aws --region "$region" --output text service-quotas get-service-quota \
               --service-code ec2 --quota-code L-1216C47A \
               --query 'Quota.Value' 2>/dev/null || true)"
    # An unreadable quota (no servicequotas:GetServiceQuota permission) is
    # not evidence of a small one — only a known-too-small one disqualifies.
    if [ -n "$quota" ] && [ "$quota" != "None" ] && [ -n "$vcpus" ] && [ "$vcpus" != "None" ]; then
        if [ "${quota%%.*}" -lt "$vcpus" ]; then
            info "$label On-Demand vCPU quota ${quota%%.*} < $vcpus" >&2
            return 1
        fi
    fi

    printf '%s|%s|%s\n' "$region" "$ami" "$azs"
    return 0
}

say "Choosing a region"
# An AMI id belongs to exactly one region, so pinning one pins the region.
if [ -n "$AMI" ] && [ "$(printf '%s' "$REGION_CANDIDATES" | wc -w)" -gt 1 ]; then
    REGION_CANDIDATES="${REGION_CANDIDATES%% *}"
    warn "--ami is region-specific; only $REGION_CANDIDATES will be tried"
fi
AMI_SSM="/aws/service/canonical/ubuntu/server/$UBUNTU/stable/current/arm64/hvm/ebs-gp3/ami-id"
CANDIDATES=()
for region in $REGION_CANDIDATES; do
    entry="$(probe_region "$region" || true)"
    case "$entry" in "$region|ami-"*) ;; *) continue ;; esac
    CANDIDATES+=("$entry") \
        && info "$(printf '%-16s %-14s' "$region" "$(region_name "$region")") ok — $(printf '%s' "${entry##*|}" | wc -w | tr -d ' ') zone(s) offering $ITYPE"
done

if [ "${#CANDIDATES[@]}" = 0 ]; then
    die "none of the candidate regions can run $ITYPE on Ubuntu $UBUNTU arm64:
       $REGION_CANDIDATES
   Pick one explicitly with --region, or a different type with --type.
   List what Canonical publishes in a region with:
     aws --region <region> ssm get-parameters-by-path --recursive \\
         --path /aws/service/canonical/ubuntu/server --query 'Parameters[].Name' \\
       | tr '\\t' '\\n' | grep 'current/arm64/hvm/ebs-gp3'"
fi

# The first survivor is the plan; the rest are the fallbacks.
REGION="${CANDIDATES[0]%%|*}"
AMI="$(printf '%s' "${CANDIDATES[0]}" | cut -d'|' -f2)"
AZS="${CANDIDATES[0]##*|}"
AZ="${AZS%% *}"
AWSC=(aws --region "$REGION" --output text)

# ── 0b. plan ──────────────────────────────────────────────────────────
say "Plan"
printf '   %-14s %s\n' region "$REGION — $(region_name "$REGION")" type "$ITYPE" az "$AZ" \
    ubuntu "$UBUNTU" ami "$AMI" \
    suite "run_perf_suite.sh $SUITE_ARGS" timeout "${TIMEOUT}s (deadman ${DEADMAN}m)" \
    results "$LOCAL_OUT"
printf '   %-14s %s\n' zones "$AZS"
if [ "${#CANDIDATES[@]}" -gt 1 ]; then
    fallbacks=""
    for entry in "${CANDIDATES[@]:1}"; do
        fallbacks="$fallbacks ${entry%%|*} ($(region_name "${entry%%|*}")),"
    done
    fallbacks="${fallbacks%,}"
    printf '   %-14s %s\n' fallbacks "${fallbacks# } (used only if $REGION is out of capacity)"
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
# Preference order: the key pair named above if this machine actually has
# its private half and AWS still has it in this region, otherwise a fresh
# ephemeral one. An explicit --key-name/--key-file is an instruction, not
# a preference, so it fails rather than falling back.
#
# Both of these are per-region, so they are functions rather than
# straight-line code: failing over to the next region means doing them
# again against the new one.
KEY_NAME_REQUESTED="$KEY_NAME"
KEY_FILE_REQUESTED="$KEY_FILE"

setup_keypair() {
    KEY_NAME="$KEY_NAME_REQUESTED"
    KEY_FILE="$KEY_FILE_REQUESTED"
    KEY_EPHEMERAL=0
    KEYFILE=""
    if [ -n "$KEY_NAME" ] && [ -n "$KEY_FILE" ]; then
        if [ ! -r "$KEY_FILE" ]; then
            [ "$KEY_EXPLICIT" = 1 ] && die "no readable private key at $KEY_FILE"
            info "no private key at $KEY_FILE — falling back to an ephemeral pair"
            KEY_NAME=""
        elif ! "${AWSC[@]}" ec2 describe-key-pairs --key-names "$KEY_NAME" \
                --query 'KeyPairs[0].KeyName' >/dev/null 2>&1; then
            [ "$KEY_EXPLICIT" = 1 ] && die "AWS has no key pair named $KEY_NAME in $REGION"
            info "AWS has no key pair $KEY_NAME in $REGION — falling back to an ephemeral pair"
            KEY_NAME=""
        else
            KEYFILE="$KEY_FILE"
            # ssh refuses a private key the rest of the world can read, and
            # a .pem straight out of the console often arrives 0644.
            case "$(ls -l "$KEYFILE" | cut -c5-10)" in
                ------) ;;
                *) warn "$KEYFILE is group/world readable; ssh will refuse it. chmod 600 it." ;;
            esac
            info "using your key pair $KEY_NAME ($KEYFILE)"
        fi
    fi
    if [ -z "$KEY_NAME" ]; then
        KEYFILE="$WORK/id_ed25519"
        [ -f "$KEYFILE" ] || ssh-keygen -q -t ed25519 -N '' -C "$TAG" -f "$KEYFILE"
        KEY_NAME="$TAG"
        "${AWSC[@]}" ec2 import-key-pair --key-name "$KEY_NAME" \
            --public-key-material "fileb://${KEYFILE}.pub" --query 'KeyName' >/dev/null
        KEY_EPHEMERAL=1
        info "ephemeral key pair $KEY_NAME (private key lives only in $WORK)"
    fi
}

# Several independent sources, because a single one is a single point of
# failure: DNS filtering, a split-tunnel VPN or a captive resolver can take
# out one echo service while the AWS API itself still works. The 1.1.1.1
# and OpenDNS probes need no working name resolution for the echo host.
detect_public_ip() {
    local raw ip
    for src in \
        "curl -fsS --max-time 8 https://checkip.amazonaws.com" \
        "curl -fsS --max-time 8 https://api.ipify.org" \
        "curl -fsS --max-time 8 https://icanhazip.com" \
        "curl -fsS --max-time 8 --resolve one.one.one.one:443:1.1.1.1 https://one.one.one.one/cdn-cgi/trace" \
        "dig -4 +short +time=3 +tries=1 myip.opendns.com @208.67.222.222"
    do
        raw="$($src 2>/dev/null | tr -d '\r')" || true
        [ -n "$raw" ] || continue
        # cdn-cgi/trace answers key=value lines; everything else answers
        # the bare address.
        ip="$(printf '%s\n' "$raw" | sed -n 's/^ip=//p' | head -1)"
        [ -n "$ip" ] || ip="$(printf '%s\n' "$raw" | head -1 | tr -d '[:space:]')"
        if printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
            printf '%s' "$ip"; return 0
        fi
    done
    return 1
}

if [ -z "$SSH_CIDR" ]; then
    MYIP="$(detect_public_ip || true)"
    if [ -z "${MYIP:-}" ]; then
        die "could not determine your public IPv4 address from any of five sources.
        Nothing has been launched. Either pass the address explicitly:
            $0 --ssh-cidr \$(curl -s https://checkip.amazonaws.com)/32
        or, if this network has no stable IPv4 (IPv6-only, or a rotating
        egress), open SSH wider — key-only auth, no password:
            $0 --ssh-cidr 0.0.0.0/0"
    fi
    SSH_CIDR="$MYIP/32"
fi

case "$SSH_CIDR" in
    0.0.0.0/0) warn "port 22 will be open to the entire internet (key-only auth)" ;;
esac

setup_security_group() {
    VPC_ID="$("${AWSC[@]}" ec2 describe-vpcs --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId')"
    [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ] || die "no default VPC in $REGION"
    SG_ID="$("${AWSC[@]}" ec2 create-security-group --group-name "$TAG" \
        --description "ephemeral sarm benchmark box" --vpc-id "$VPC_ID" --query 'GroupId')"
    "${AWSC[@]}" ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr "$SSH_CIDR" >/dev/null
    info "security group $SG_ID — port 22 from $SSH_CIDR only"
    info "the load generator runs on the box itself, so nothing else is exposed"
}

# Undo a region that would not give us a machine. Nothing is attached to
# these — the launch failed — so the security group deletes immediately
# rather than going on the deferred list.
release_region() {
    if [ -n "$SG_ID" ]; then
        "${AWSC[@]}" ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1 \
            || defer_security_group "$SG_ID"
        SG_ID=""
    fi
    if [ "$KEY_EPHEMERAL" = 1 ] && [ -n "$KEY_NAME" ]; then
        "${AWSC[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || true
        KEY_EPHEMERAL=0
    fi
}

# ── 2. launch ─────────────────────────────────────────────────────────
# Two independent kill switches, because the local trap only fires while
# this shell is alive: the instance shuts itself down after $DEADMAN
# minutes, and shutdown means terminate.
cat > "$WORK/user-data.sh" <<USERDATA
#!/bin/bash
# Deadman switch written by quick_test_ec2.sh — if the orchestrating
# laptop disappears, this instance still terminates itself.
shutdown -h +${DEADMAN}
USERDATA

# One region's worth of attempts: every zone that offers the type, in
# order, because "no capacity" is a property of a zone and not of a
# region. Returns 0 with INSTANCE_ID set, 1 if the whole region is out.
launch_in_region() {
    local az subnet out rc
    for az in $AZS; do
        subnet="$("${AWSC[@]}" ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$az" \
            --query 'Subnets[0].SubnetId')"
        if [ -z "$subnet" ] || [ "$subnet" = "None" ]; then
            info "$az — no default subnet, skipping"
            continue
        fi

        info "trying $az"
        # set -e must not fire here: a capacity error is an expected
        # answer, not a failure of the script.
        set +e
        out="$("${AWSC[@]}" ec2 run-instances \
            --image-id "$AMI" \
            --instance-type "$ITYPE" \
            --key-name "$KEY_NAME" \
            --subnet-id "$subnet" \
            --security-group-ids "$SG_ID" \
            --associate-public-ip-address \
            --instance-initiated-shutdown-behavior terminate \
            --monitoring 'Enabled=true' \
            --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
            --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${VOLUME_GB},VolumeType=gp3,DeleteOnTermination=true}" \
            --user-data "file://$WORK/user-data.sh" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG},{Key=Purpose,Value=sarm-benchmark},{Key=Ephemeral,Value=true}]" \
            --query 'Instances[0].InstanceId' 2>&1)"
        rc=$?
        set -e

        if [ "$rc" = 0 ] && [ -n "$out" ] && [ "$out" != "None" ]; then
            INSTANCE_ID="$out"
            AZ="$az"
            SUBNET_ID="$subnet"
            return 0
        fi

        case "$out" in
            *InsufficientInstanceCapacity*|*InsufficientHostCapacity*|*Unsupported*)
                warn "$az has no $ITYPE capacity right now" ;;
            *VcpuLimitExceeded*|*InstanceLimitExceeded*)
                # A quota is regional; no other zone will answer differently.
                warn "$REGION quota refused the launch: $(printf '%s' "$out" | tail -1)"
                return 1 ;;
            *)
                # An unexpected error is worth surfacing rather than
                # silently walking the remaining zones with it.
                warn "$az: $(printf '%s' "$out" | tail -1)" ;;
        esac
    done
    return 1
}

LAUNCHED=0
for entry in "${CANDIDATES[@]}"; do
    REGION="${entry%%|*}"
    AMI="$(printf '%s' "$entry" | cut -d'|' -f2)"
    AZS="${entry##*|}"
    AWSC=(aws --region "$REGION" --output text)

    say "Launching $ITYPE in $REGION / $(region_name "$REGION") (bare metal takes several minutes to POST)"
    setup_keypair
    setup_security_group
    if launch_in_region; then LAUNCHED=1; break; fi

    warn "no $ITYPE available anywhere in $REGION ($(region_name "$REGION"))"
    release_region
done

if [ "$LAUNCHED" != 1 ]; then
    INSTANCE_ID=""
    die "no $ITYPE capacity in any candidate region ($REGION_CANDIDATES).
   Nothing is running and nothing is billed. Options: wait and re-run,
   try another type with --type, or name a region directly with --region."
fi
info "$INSTANCE_ID in $AZ — $(region_name "$REGION")"

# The watchdog is armed only now — before this point there is nothing to
# leak, and after it the trap does the right thing on TERM.
( sleep "$TIMEOUT"; kill -TERM $$ 2>/dev/null ) &
WATCHDOG=$!

"${AWSC[@]}" ec2 wait instance-running --instance-ids "$INSTANCE_ID"
PUBLIC_IP="$("${AWSC[@]}" ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress')"
info "running at $PUBLIC_IP"

SSH_OPTS=(-i "$KEYFILE" -o StrictHostKeyChecking=accept-new
          -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10
          -o ServerAliveInterval=30 -o ServerAliveCountMax=10 -o LogLevel=ERROR)
REMOTE="ubuntu@$PUBLIC_IP"
rsh() { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }

say "Waiting for sshd"
for i in $(seq 1 90); do
    if rsh true 2>/dev/null; then info "up after $((i*10))s"; break; fi
    sleep 10
    [ "$i" = 90 ] && die "no ssh after 15 minutes"
done

# ── 3. upload the working tree ────────────────────────────────────────
# Tracked files as they are on disk, not HEAD — so a local edit is what
# gets measured. Untracked build inputs (certs, error pages) are
# regenerated on the box by setup_ec2_metal.sh.
say "Uploading the working tree"
# macOS bsdtar stores xattrs (com.apple.provenance and friends) as
# LIBARCHIVE.* pax headers, and GNU tar on the instance then warns about
# every one of them. Drop them at the source. The flags are probed rather
# than assumed so this still works when driven from a Linux box.
TAR_C=(tar)
for opt in --no-xattrs --no-mac-metadata; do
    tar "$opt" --help >/dev/null 2>&1 && TAR_C+=("$opt")
done
git ls-files -z | COPYFILE_DISABLE=1 "${TAR_C[@]}" --null -T - -czf "$WORK/sarm.tar.gz"
info "$(du -h "$WORK/sarm.tar.gz" | cut -f1) of tracked files"
scp "${SSH_OPTS[@]}" -q "$WORK/sarm.tar.gz" "$REMOTE:/tmp/sarm.tar.gz"
rsh 'rm -rf ~/sarm && mkdir -p ~/sarm && tar -xzf /tmp/sarm.tar.gz -C ~/sarm && rm -f /tmp/sarm.tar.gz'
info "unpacked to ~/sarm"

# ── provenance ────────────────────────────────────────────────────────
# The tarball is `git ls-files` output, so ~/sarm has no .git and every
# `git` call on the instance fails. run_perf_suite.sh's environment
# section noticed that only for the commit line, which it degraded to
# "not a checkout"; the dirty count next to it silently became `git
# status | wc -l` over a failed command, which is 0. So EVERY run in
# perf-results/ claims a clean tree, whatever was actually measured —
# false where it matters most, because the whole point of uploading the
# working tree rather than HEAD is that a local edit is what gets
# measured. Stamp both facts here, where the .git still exists, and let
# the suite read them back.
{
    echo "commit    : $(git log --oneline -1 2>/dev/null || echo 'unknown')"
    echo "dirty     : $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') modified files"
    git status --porcelain 2>/dev/null | sed 's/^/modified  : /'
} > "$WORK/provenance"
scp "${SSH_OPTS[@]}" -q "$WORK/provenance" "$REMOTE:sarm/.perf-provenance"
info "stamped $(git log --oneline -1 2>/dev/null | cut -c1-9)$(
    [ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' (dirty)')"

# ── 4. bootstrap ──────────────────────────────────────────────────────
say "Bootstrapping (toolchain, kernel tuning, build, smoke test)"
rsh 'chmod +x ~/sarm/scripts/aws/*.sh ~/sarm/certs/generate.sh 2>/dev/null; SARM_DIR=$HOME/sarm ~/sarm/scripts/aws/setup_ec2_metal.sh' \
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
        grep -E 'per core:|IPC ' "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' || true

        say "Where the cycles went"
        grep -E 'totals: sarm|frontend|backend|branch-misses|cache-misses' \
            "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' | head -20 || true

        say "Throughput (read this LAST, and only if sarm saturated)"
        grep -E 'req/s' "$LOCAL_OUT/summary.txt" 2>/dev/null | sed 's/^ *//;s/^/   /' | head -6 || true
    fi
fi

# cleanup() terminates on the way out
