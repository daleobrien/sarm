#!/usr/bin/env bash
# quick_test_ec2.sh — rent a c6g.metal in Melbourne, run the quick perf
# suite on it, bring the results home, and give the machine back.
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
#   1. ephemeral SSH keypair + security group locked to your public IP
#   2. launch c6g.metal on the latest Ubuntu arm64 (AMI resolved from SSM)
#   3. upload this working tree (tracked files, as they are on disk)
#   4. scripts/aws/setup_c6g_metal.sh   — toolchain, tuning, build, smoke
#   5. scripts/aws/run_perf_suite.sh --quick
#   6. pull the results into ./perf-results/ec2-<timestamp>/
#   7. terminate, and delete the keypair and security group
#
# Usage:
#   ./scripts/aws/quick_test_ec2.sh
#   ./scripts/aws/quick_test_ec2.sh --yes                  # no confirmation
#   ./scripts/aws/quick_test_ec2.sh --suite-args '--duration 30 --repeat 7'
#   ./scripts/aws/quick_test_ec2.sh --ubuntu 24.04         # previous LTS
#   ./scripts/aws/quick_test_ec2.sh --timeout 5400
#   ./scripts/aws/quick_test_ec2.sh --keep                 # leave it running
#
# Needs: awscli v2 with credentials, ssh, scp, git. c6g.metal counts 64
# vCPUs against the "Running On-Demand Standard instances" quota in the
# target region — if that quota is still the default 5, the launch fails
# with VcpuLimitExceeded and nothing is billed.

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"

# ── options ───────────────────────────────────────────────────────────
REGION="${AWS_REGION_OVERRIDE:-ap-southeast-4}"     # Melbourne
ITYPE="c6g.metal"
AMI=""
UBUNTU="26.04"          # latest release (Resolute, an LTS)
VOLUME_GB=40
SUITE_ARGS="--quick"
TIMEOUT=3600            # local watchdog, seconds
DEADMAN=90              # in-instance self-destruct, minutes
SSH_CIDR=""
ASSUME_YES=0
KEEP=0
SKIP_SUITE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --region)      REGION="$2"; shift ;;
        --type)        ITYPE="$2"; shift ;;
        --ami)         AMI="$2"; shift ;;
        --ubuntu)      UBUNTU="$2"; shift ;;
        --volume-gb)   VOLUME_GB="$2"; shift ;;
        --suite-args)  SUITE_ARGS="$2"; shift ;;
        --timeout)     TIMEOUT="$2"; shift ;;
        --deadman)     DEADMAN="$2"; shift ;;
        --ssh-cidr)    SSH_CIDR="$2"; shift ;;
        --setup-only)  SKIP_SUITE=1 ;;
        --keep)        KEEP=1 ;;
        -y|--yes)      ASSUME_YES=1 ;;
        -h|--help)     sed -n '2,/^set -euo/p' "$0" | sed -E 's/^#[[:space:]]?//;$d'; exit 0 ;;
        *) echo "$0: unknown flag $1" >&2; exit 2 ;;
    esac
    shift
done

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
KEYFILE="$WORK/id_ed25519"
LOCAL_OUT="$REPO/perf-results/ec2-$RUNID"
AWSC=(aws --region "$REGION" --output text)

INSTANCE_ID=""
SG_ID=""
KEY_NAME=""
WATCHDOG=""
STARTED=$(date +%s)

# ── cleanup: the reason this script exists ────────────────────────────
# Runs on every exit path — success, failure (set -e), Ctrl-C, watchdog
# TERM. Each step is independently best-effort: a failure deleting the
# security group must never skip terminating the instance.
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    [ -n "$WATCHDOG" ] && kill "$WATCHDOG" 2>/dev/null || true

    if [ -n "$INSTANCE_ID" ]; then
        if [ "$KEEP" = 1 ]; then
            say "Leaving $INSTANCE_ID running (--keep)"
            warn "you are being billed. Terminate with:"
            warn "  aws ec2 terminate-instances --region $REGION --instance-ids $INSTANCE_ID"
            warn "it will self-terminate after ${DEADMAN} minutes regardless."
            info "ssh key kept at $KEYFILE"
            info "ssh -i $KEYFILE ubuntu@${PUBLIC_IP:-<ip>}"
            printf '\n'
            exit "$rc"
        fi
        say "Terminating $INSTANCE_ID"
        "${AWSC[@]}" ec2 terminate-instances --instance-ids "$INSTANCE_ID" \
            --query 'TerminatingInstances[].CurrentState.Name' 2>&1 | sed 's/^/   /' || \
            warn "terminate call failed — CHECK THE CONSOLE for $INSTANCE_ID"
        info "waiting for it to actually be gone"
        "${AWSC[@]}" ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" 2>/dev/null || \
            warn "stopped waiting — CHECK THE CONSOLE for $INSTANCE_ID"
    fi

    # The security group cannot be deleted while an instance still holds
    # it, which is why this comes after the terminated wait.
    if [ -n "$SG_ID" ]; then
        "${AWSC[@]}" ec2 delete-security-group --group-id "$SG_ID" 2>/dev/null \
            && info "deleted security group $SG_ID" \
            || warn "could not delete security group $SG_ID — delete it by hand"
    fi
    if [ -n "$KEY_NAME" ]; then
        "${AWSC[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 \
            && info "deleted key pair $KEY_NAME" || warn "could not delete key pair $KEY_NAME"
    fi
    rm -rf "$WORK"

    local mins=$(( ($(date +%s) - STARTED) / 60 ))
    info "elapsed: ${mins} min of ${ITYPE} time"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ── 0. plan ───────────────────────────────────────────────────────────
say "Plan"
# Canonical publishes a "current" pointer per release, so this always picks
# up the newest daily build of that release rather than a frozen serial.
AMI_SSM="/aws/service/canonical/ubuntu/server/$UBUNTU/stable/current/arm64/hvm/ebs-gp3/ami-id"
[ -z "$AMI" ] && AMI="$("${AWSC[@]}" ssm get-parameters --names "$AMI_SSM" \
    --query 'Parameters[].Value')"
[ -n "$AMI" ] && [ "$AMI" != "None" ] || die "no Ubuntu $UBUNTU arm64 image in $REGION.
   List what Canonical publishes there with:
     aws --region $REGION ssm get-parameters-by-path --recursive \\
         --path /aws/service/canonical/ubuntu/server --query 'Parameters[].Name' \\
       | tr '\\t' '\\n' | grep 'current/arm64/hvm/ebs-gp3'"

AZ="$("${AWSC[@]}" ec2 describe-instance-type-offerings \
        --location-type availability-zone \
        --filters "Name=instance-type,Values=$ITYPE" \
        --query 'InstanceTypeOfferings[0].Location')"
[ -n "$AZ" ] && [ "$AZ" != "None" ] || die "$ITYPE is not offered in $REGION"

printf '   %-14s %s\n' region "$REGION" type "$ITYPE" az "$AZ" \
    ubuntu "$UBUNTU" ami "$AMI" \
    suite "run_perf_suite.sh $SUITE_ARGS" timeout "${TIMEOUT}s (deadman ${DEADMAN}m)" \
    results "$LOCAL_OUT"

if [ "$ASSUME_YES" != 1 ]; then
    printf '\n   Bare metal is billed per second from boot. Launch? [y/N] '
    read -r reply
    case "$reply" in [yY]*) ;; *) INSTANCE_ID=""; die "aborted" ;; esac
fi

# ── 1. keypair and security group ─────────────────────────────────────
say "Creating an ephemeral key pair and security group"
ssh-keygen -q -t ed25519 -N '' -C "$TAG" -f "$KEYFILE"
KEY_NAME="$TAG"
"${AWSC[@]}" ec2 import-key-pair --key-name "$KEY_NAME" \
    --public-key-material "fileb://${KEYFILE}.pub" --query 'KeyName' >/dev/null
info "key pair $KEY_NAME (private key lives only in $WORK)"

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
VPC_ID="$("${AWSC[@]}" ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId')"
[ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ] || die "no default VPC in $REGION"
SUBNET_ID="$("${AWSC[@]}" ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$AZ" \
    --query 'Subnets[0].SubnetId')"
[ -n "$SUBNET_ID" ] && [ "$SUBNET_ID" != "None" ] || die "no default subnet in $AZ"

SG_ID="$("${AWSC[@]}" ec2 create-security-group --group-name "$TAG" \
    --description "ephemeral sarm benchmark box" --vpc-id "$VPC_ID" --query 'GroupId')"
"${AWSC[@]}" ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "$SSH_CIDR" >/dev/null
info "security group $SG_ID — port 22 from $SSH_CIDR only"
info "the load generator runs on the box itself, so nothing else is exposed"

# ── 2. launch ─────────────────────────────────────────────────────────
# Two independent kill switches, because the local trap only fires while
# this shell is alive: the instance shuts itself down after $DEADMAN
# minutes, and shutdown means terminate.
say "Launching $ITYPE (bare metal takes several minutes to POST)"
cat > "$WORK/user-data.sh" <<USERDATA
#!/bin/bash
# Deadman switch written by quick_test_ec2.sh — if the orchestrating
# laptop disappears, this instance still terminates itself.
shutdown -h +${DEADMAN}
USERDATA

INSTANCE_ID="$("${AWSC[@]}" ec2 run-instances \
    --image-id "$AMI" \
    --instance-type "$ITYPE" \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --associate-public-ip-address \
    --instance-initiated-shutdown-behavior terminate \
    --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${VOLUME_GB},VolumeType=gp3,DeleteOnTermination=true}" \
    --user-data "file://$WORK/user-data.sh" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG},{Key=Purpose,Value=sarm-benchmark},{Key=Ephemeral,Value=true}]" \
    --query 'Instances[0].InstanceId')"
[ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ] || die "run-instances returned no instance id"
info "$INSTANCE_ID"

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
# regenerated on the box by setup_c6g_metal.sh.
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

# ── 4. bootstrap ──────────────────────────────────────────────────────
say "Bootstrapping (toolchain, kernel tuning, build, smoke test)"
rsh 'chmod +x ~/sarm/scripts/aws/*.sh ~/sarm/certs/generate.sh 2>/dev/null; SARM_DIR=$HOME/sarm ~/sarm/scripts/aws/setup_c6g_metal.sh' \
    2>&1 | tee "$WORK/setup.log"

if [ "$SKIP_SUITE" = 1 ]; then
    say "--setup-only: stopping before the suite"
else
    # ── 5. the quick test ─────────────────────────────────────────────
    say "Running run_perf_suite.sh $SUITE_ARGS"
    rsh "cd ~/sarm && ./scripts/aws/run_perf_suite.sh $SUITE_ARGS --out \$HOME/sarm/perf-results/$RUNID" \
        2>&1 | tee "$WORK/suite.log"

    # ── 6. bring the results home ─────────────────────────────────────
    say "Downloading results"
    mkdir -p "$LOCAL_OUT"
    # Streamed as a tarball rather than scp -r: recent scp speaks SFTP and
    # will not expand a remote glob, and perf.data files are worth the gzip.
    if rsh "cd \$HOME/sarm/perf-results && tar -czf - '$RUNID'" > "$WORK/results.tar.gz"; then
        tar -xzf "$WORK/results.tar.gz" -C "$LOCAL_OUT" --strip-components 1
        info "$(du -sh "$LOCAL_OUT" | cut -f1) retrieved"
    else
        warn "could not retrieve the results directory"
    fi
    cp "$WORK/setup.log" "$WORK/suite.log" "$LOCAL_OUT/" 2>/dev/null || true
    rsh 'uname -a; nproc; cat /proc/cpuinfo | head -20' > "$LOCAL_OUT/host.txt" 2>/dev/null || true

    say "Results in $LOCAL_OUT"
    ls -1 "$LOCAL_OUT" | sed 's/^/   /'
    if [ -f "$LOCAL_OUT/summary.txt" ]; then
        printf '\n'
        grep -E 'req/s|IPC|cycles|^━━' "$LOCAL_OUT/summary.txt" 2>/dev/null | head -30 | sed 's/^/   /' || true
    fi
fi

# cleanup() terminates on the way out
