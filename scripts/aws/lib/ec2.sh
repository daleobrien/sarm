# ec2.sh — key pair, security group, and the launch loop.
#
# Requires: common.sh, region.sh, pricing.sh, pending_sg.sh.
# Caller sets: TAG, WORK, REGION, AWSC, AMI, AZS, AZ, ITYPES, IROLES,
#              VOLUME_GB, SPOT, SPOT_AZS, KEY_NAME_REQUESTED,
#              KEY_FILE_REQUESTED, KEY_EXPLICIT, SSH_CIDR,
#              SG_INTERNAL (1 to let the instances talk to each other),
#              PLACEMENT (1 to put them in one cluster placement group).

[ -n "${SARM_AWS_EC2_SH:-}" ] && return 0
SARM_AWS_EC2_SH=1

# ── key pair ──────────────────────────────────────────────────────────
# AN AWS KEY PAIR BELONGS TO ONE REGION. The same name in another region
# is simply not there, so a single hard-coded default is right in exactly
# one place and silently degrades to a freshly minted ephemeral pair
# everywhere else — which works, but means the box cannot be reached from
# any other terminal, and a --keep'd instance is only as reachable as the
# temp directory this run is holding.
#
# So the key follows the region. Override the table with
#   SARM_EC2_KEYS="ap-southeast-2=DaleSydney us-west-2=DaleOregon"
# and a name here is paired with ~/.ssh/<name>.pem unless --key-file says
# otherwise. A region with no entry falls back to $KEY_NAME_REQUESTED,
# and then to an ephemeral pair.
REGION_KEYS="${SARM_EC2_KEYS:-ap-southeast-4=DaleMelbourne ap-southeast-2=DaleSydney}"
region_key_name() {
    local entry
    for entry in $REGION_KEYS; do
        case "$entry" in "$1="*) printf '%s' "${entry#*=}"; return 0 ;; esac
    done
    return 1
}

# Preference order: the key pair this region maps to if this machine
# actually has its private half and AWS still has it there, otherwise a
# fresh ephemeral one. An explicit --key-name/--key-file is an
# instruction, not a preference, so it fails rather than falling back.
#
# Per region, hence a function rather than straight-line code: failing
# over to the next region means doing this again against the new one.
setup_keypair() {
    local regional
    KEY_NAME="$KEY_NAME_REQUESTED"
    KEY_FILE="$KEY_FILE_REQUESTED"
    # The table wins over the built-in default, and loses to an explicit
    # flag — which is the only one of the three the user typed.
    if [ "$KEY_EXPLICIT" != 1 ] && regional="$(region_key_name "$REGION")"; then
        KEY_NAME="$regional"
        KEY_FILE="$HOME/.ssh/$regional.pem"
        info "$REGION maps to key pair $KEY_NAME"
    fi
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

# ── this machine's public address ─────────────────────────────────────
# Several independent sources, because a single one is a single point of
# failure: DNS filtering, a split-tunnel VPN or a captive resolver can take
# out one echo service while the AWS API itself still works. The 1.1.1.1
# and OpenDNS probes need no working name resolution for the echo host.
detect_public_ip() {
    local raw ip src
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

# $SSH_CIDR, resolved. Called before anything is launched so a machine
# with no detectable public address costs nothing.
resolve_ssh_cidr() {
    if [ -z "$SSH_CIDR" ]; then
        local myip
        myip="$(detect_public_ip || true)"
        if [ -z "$myip" ]; then
            die "could not determine your public IPv4 address from any of five sources.
        Nothing has been launched. Either pass the address explicitly:
            $0 --ssh-cidr \$(curl -s https://checkip.amazonaws.com)/32
        or, if this network has no stable IPv4 (IPv6-only, or a rotating
        egress), open SSH wider — key-only auth, no password:
            $0 --ssh-cidr 0.0.0.0/0"
        fi
        SSH_CIDR="$myip/32"
    fi
    case "$SSH_CIDR" in
        0.0.0.0/0) warn "port 22 will be open to the entire internet (key-only auth)" ;;
    esac
}

# ── security group ────────────────────────────────────────────────────
# Port 22 from one address, and — when the run holds more than one
# instance — every TCP port from the group to itself, which is how the
# load generator reaches the server without opening anything to the
# internet. A self-referencing rule covers exactly the instances this run
# created and nothing else.
setup_security_group() {
    VPC_ID="$("${AWSC[@]}" ec2 describe-vpcs --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId')"
    [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ] || die "no default VPC in $REGION"
    SG_ID="$("${AWSC[@]}" ec2 create-security-group --group-name "$TAG" \
        --description "ephemeral sarm benchmark box" --vpc-id "$VPC_ID" --query 'GroupId')"
    "${AWSC[@]}" ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr "$SSH_CIDR" >/dev/null
    info "security group $SG_ID — port 22 from $SSH_CIDR only"
    if [ "${SG_INTERNAL:-0}" = 1 ]; then
        "${AWSC[@]}" ec2 authorize-security-group-ingress --group-id "$SG_ID" \
            --protocol tcp --port 0-65535 --source-group "$SG_ID" >/dev/null
        info "plus every TCP port from the group to itself — the load box"
        info "reaches the server on its private address; nothing is public"
    else
        info "the load generator runs on the box itself, so nothing else is exposed"
    fi
}

# Undo a region that would not give us a machine. Nothing is attached to
# these — the launch failed — so the security group deletes immediately
# rather than going on the deferred list.
release_region() {
    local region="$REGION"
    if [ -n "$PG_NAME" ]; then
        # Nothing is in it — the launch failed — so this normally deletes
        # outright, and the deferred list catches the case where it does not.
        "${AWSC[@]}" ec2 delete-placement-group --group-name "$PG_NAME" >/dev/null 2>&1 \
            || defer_placement_group "$PG_NAME" "$region"
        PG_NAME=""
    fi
    if [ -n "$SG_ID" ]; then
        "${AWSC[@]}" ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1 \
            || defer_security_group "$SG_ID" "$region"
        SG_ID=""
    fi
    if [ "$KEY_EPHEMERAL" = 1 ] && [ -n "$KEY_NAME" ]; then
        "${AWSC[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || true
        KEY_EPHEMERAL=0
    fi
}

# ── placement group ───────────────────────────────────────────────────
# A cluster placement group asks EC2 to put these instances close together
# on the network — same rack-adjacent segment, full bisection bandwidth,
# the lowest round-trip the VPC can offer. For a two-box benchmark that is
# the one knob that actually moves the number, because a closed-loop
# client's throughput is concurrency divided by latency: shaving tens of
# microseconds off the round trip raises req/s at the same concurrency.
#
# It is not free of consequences. Asking for a cluster group narrows where
# EC2 can find capacity, so a launch is likelier to be refused — which is
# why the caller can turn it off, and why the group is created per region
# alongside the security group rather than once up front.
PG_NAME=""
setup_placement_group() {
    [ "${PLACEMENT:-0}" = 1 ] || return 0
    PG_NAME="$TAG"
    if "${AWSC[@]}" ec2 create-placement-group --group-name "$PG_NAME" \
            --strategy cluster >/dev/null 2>&1; then
        info "cluster placement group $PG_NAME — the two boxes get the"
        info "shortest network path EC2 will give them"
    else
        warn "could not create a cluster placement group; launching without one"
        warn "  (the run still works — the link is just an ordinary VPC hop)"
        PG_NAME=""
    fi
}

# ── launching ─────────────────────────────────────────────────────────
# One instance. Echoes its id on success; on failure echoes nothing and
# leaves the API's own words in $LAUNCH_ERR for the caller to classify.
LAUNCH_ERR=""
launch_one() {  # launch_one <itype> <role> <az> <subnet>
    local itype="$1" role="$2" az="$3" subnet="$4" out rc name
    local market=() tagspec=() placement=() tags use_spot=0

    name="$TAG${role:+-$role}"
    tags="Tags=[{Key=Name,Value=$name},{Key=Run,Value=$TAG},{Key=Role,Value=${role:-single}},{Key=Purpose,Value=sarm-benchmark},{Key=Ephemeral,Value=true}]"
    # One flag, many values: a repeated --tag-specifications would replace
    # the earlier one rather than add to it.
    tagspec=(--tag-specifications "ResourceType=instance,$tags")

    # Per zone, not once for the run: the fallthrough can land in a zone
    # where spot is at parity with on-demand, and taking the interruption
    # risk there buys nothing.
    if [ "$SPOT" = 1 ]; then
        case " $SPOT_AZS " in *" $az "*) use_spot=1 ;; esac
    fi
    [ -n "$PG_NAME" ] && placement=(--placement "GroupName=$PG_NAME")

    if [ "$use_spot" = 1 ]; then
        # One-time spot, terminating on interruption: a persistent request
        # would try to replace the instance behind our back, long after
        # this script has stopped watching.
        market=(--instance-market-options
            'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}')
        # The request is tagged in the same call that creates it, so
        # cleanup can find and cancel it by tag even on the paths where
        # this script never learns the instance id.
        tagspec+=("ResourceType=spot-instances-request,$tags")
    fi

    # set -e must not fire here: a capacity error is an expected answer,
    # not a failure of the script.
    set +e
    out="$("${AWSC[@]}" ec2 run-instances \
        --image-id "$AMI" \
        --instance-type "$itype" \
        ${market[@]+"${market[@]}"} \
        ${placement[@]+"${placement[@]}"} \
        --key-name "$KEY_NAME" \
        --subnet-id "$subnet" \
        --security-group-ids "$SG_ID" \
        --associate-public-ip-address \
        --instance-initiated-shutdown-behavior terminate \
        --monitoring 'Enabled=true' \
        --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
        --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${VOLUME_GB},VolumeType=gp3,DeleteOnTermination=true}" \
        --user-data "file://$WORK/user-data.sh" \
        ${tagspec[@]+"${tagspec[@]}"} \
        --query 'Instances[0].InstanceId' 2>&1)"
    rc=$?
    set -e

    if [ "$rc" = 0 ] && [ -n "$out" ] && [ "$out" != "None" ]; then
        LAUNCH_ERR=""
        printf '%s' "$out"
        return 0
    fi
    # A refusal usually arrives as an API error, and the caller classifies
    # it by matching on the text. But run-instances can also exit 0 having
    # printed nothing, or print "None" — and the caller then warned
    # "<zone>: " with an empty reason, which says only that something went
    # wrong and nothing about what. Give those cases words of their own.
    LAUNCH_ERR="$out"
    if [ -z "$out" ] || [ "$out" = "None" ]; then
        LAUNCH_ERR="run-instances exited $rc without returning an instance id${out:+ (printed: $out)}"
    fi
    return 1
}

# One region's worth of attempts: every zone that offers the types, in
# order, because "no capacity" is a property of a zone and not of a
# region. Every instance the run needs goes into the SAME zone — on a
# two-box run a cross-zone link is slower, less predictable and billed per
# gigabyte, and would be measured instead of the server.
#
# Returns 0 with LAUNCHED_IDS set (parallel to $ITYPES / $IROLES), AZ and
# SUBNET_ID; 1 if the whole region is out. A partial launch is rolled back
# before the next zone is tried.
LAUNCHED_IDS=()
launch_group_in_region() {
    local az subnet i n id ok quota_stop=0
    local -a types roles
    # shellcheck disable=SC2206
    types=($ITYPES)
    # shellcheck disable=SC2206
    roles=($IROLES)
    n=${#types[@]}

    for az in $AZS; do
        subnet="$("${AWSC[@]}" ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$az" \
            --query 'Subnets[0].SubnetId')"
        if [ -z "$subnet" ] || [ "$subnet" = "None" ]; then
            info "$az — no default subnet, skipping"
            continue
        fi

        info "trying $az"
        if [ "$SPOT" = 1 ]; then
            case " $SPOT_AZS " in
                *" $az "*) ;;
                *) info "$az is not cheaper on spot — on-demand here" ;;
            esac
        fi

        LAUNCHED_IDS=()
        ok=1
        i=0
        while [ "$i" -lt "$n" ]; do
            if id="$(launch_one "${types[$i]}" "${roles[$i]:-}" "$az" "$subnet")"; then
                LAUNCHED_IDS+=("$id")
                # Only worth naming when there is more than one: a
                # single-instance run has already said what it launched.
                if [ "$n" -gt 1 ]; then
                    info "  ${roles[$i]:-instance}: $id (${types[$i]})"
                fi
            else
                ok=0
                case "$LAUNCH_ERR" in
                    *InsufficientInstanceCapacity*|*InsufficientHostCapacity*|*Unsupported*)
                        warn "$az has no ${types[$i]} capacity right now$(
                            [ -n "$PG_NAME" ] && printf ' (in a cluster placement group — try --no-placement-group)')" ;;
                    *MaxSpotInstanceCountExceeded*|*SpotMaxPriceTooLow*)
                        warn "$az refused the spot request: $(printf '%s' "$LAUNCH_ERR" | tail -1)" ;;
                    *VcpuLimitExceeded*|*InstanceLimitExceeded*)
                        # A quota is regional; no other zone will answer
                        # differently.
                        warn "$REGION quota refused the launch: $(printf '%s' "$LAUNCH_ERR" | tail -1)"
                        quota_stop=1 ;;
                    *)
                        # An unexpected error is worth surfacing rather
                        # than silently walking the remaining zones with it.
                        # tail -1 on a multi-line API error; the ${...:-}
                        # guard is because a reason we cannot read is still
                        # worth reporting as one.
                        # Blank lines dropped BEFORE tail -1: an API
                        # error often ends with one, and tailing it gave
                        # "<zone> refused <type>: " with no reason at all
                        # — which is what the 2026-08-29 runs printed.
                        warn "$az refused ${types[$i]}: $(printf '%s' "$LAUNCH_ERR" \
                            | sed '/^[[:space:]]*$/d' | tail -1 | sed 's/^ *//')" ;;
                esac
                break
            fi
            i=$((i + 1))
        done

        if [ "$ok" = 1 ]; then
            AZ="$az"
            SUBNET_ID="$subnet"
            return 0
        fi

        # Half a pair is no use and is still billed. Give it back before
        # trying the next zone.
        if [ ${#LAUNCHED_IDS[@]} -gt 0 ]; then
            warn "rolling back ${#LAUNCHED_IDS[@]} instance(s) already launched in $az"
            "${AWSC[@]}" ec2 terminate-instances --instance-ids "${LAUNCHED_IDS[@]}" \
                >/dev/null 2>&1 || warn "rollback terminate failed — CHECK THE CONSOLE for ${LAUNCHED_IDS[*]}"
            LAUNCHED_IDS=()
        fi
        [ "$quota_stop" = 1 ] && return 1
    done
    LAUNCHED_IDS=()
    return 1
}

# ── spot requests: cancel what this run created ───────────────────────
# RunInstances with MarketType=spot creates a spot instance request that
# outlives the API call. Terminating the instance of a fulfilled one-time
# request does close it — but that only covers the paths where we hold an
# instance id. If the run-instances call is interrupted client-side (a
# Ctrl-C, a dropped connection, a timeout) the request can exist on AWS's
# side while this script never learns of it, and an *open* request will
# happily fulfil minutes later into an instance nobody is watching and
# nothing will terminate. So the requests are tagged at creation and
# cancelled here by tag, whether or not an instance was ever seen.
#
# $1.. are instance ids this run has already terminated.
cancel_spot_requests() {
    # SPOT_WANTED, not SPOT: a region priced down to on-demand after an
    # earlier region had already made a spot request would otherwise
    # leave that request behind.
    [ "$SPOT_WANTED" = 1 ] || return 0
    [ ${#AWSC[@]} -gt 0 ] || return 0     # region never chosen; nothing was asked for
    local ids orphan orphans known=" $* "

    ids="$("${AWSC[@]}" ec2 describe-spot-instance-requests \
        --filters "Name=tag:Run,Values=$TAG" "Name=state,Values=open,active" \
        --query 'SpotInstanceRequests[].SpotInstanceRequestId' 2>/dev/null)" || return 0
    [ -n "$ids" ] && [ "$ids" != None ] || return 0

    say "Cancelling spot request(s): $ids"
    # shellcheck disable=SC2086
    "${AWSC[@]}" ec2 cancel-spot-instance-requests --spot-instance-request-ids $ids \
        >/dev/null 2>&1 || warn "cancel failed — CHECK THE CONSOLE for $ids"

    # Cancelling a request never terminates an instance. One that was
    # fulfilled in the gap between the describe above and the cancel is
    # now running, un-tracked, and billing.
    # shellcheck disable=SC2086
    orphans="$("${AWSC[@]}" ec2 describe-spot-instance-requests \
        --spot-instance-request-ids $ids \
        --query 'SpotInstanceRequests[?InstanceId].InstanceId' 2>/dev/null || true)"
    for orphan in $orphans; do
        # None is the text-output spelling of an unfulfilled request; the
        # ids in $known were already terminated by the caller.
        case "$orphan" in None) continue ;; esac
        case "$known" in *" $orphan "*) continue ;; esac
        warn "spot request fulfilled while cancelling — terminating $orphan"
        "${AWSC[@]}" ec2 terminate-instances --instance-ids "$orphan" >/dev/null 2>&1 \
            || warn "terminate call failed — CHECK THE CONSOLE for $orphan"
    done
}

# ── the deadman switch ────────────────────────────────────────────────
# Two independent kill switches, because the local trap only fires while
# the orchestrating shell is alive: the instance shuts itself down after
# $1 minutes, and shutdown means terminate (see the run-instances flag).
write_user_data() {  # write_user_data <deadman-minutes>
    cat > "$WORK/user-data.sh" <<USERDATA
#!/bin/bash
# Deadman switch written by $(basename "$0") — if the orchestrating
# laptop disappears, this instance still terminates itself.
shutdown -h +${1}
USERDATA
}

# ── ssh ───────────────────────────────────────────────────────────────
ssh_opts() {  # ssh_opts — echoes the shared flags; caller keeps them in an array
    printf '%s\n' -i "$KEYFILE" -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10 \
        -o ServerAliveInterval=30 -o ServerAliveCountMax=10 -o LogLevel=ERROR
}

wait_for_ssh() {  # wait_for_ssh <label> <ssh-target> [<opts>...]
    local label="$1" target="$2"; shift 2
    local i
    for i in $(seq 1 90); do
        if ssh "$@" "$target" true 2>/dev/null; then
            info "$label up after $((i * 10))s"
            return 0
        fi
        sleep 10
    done
    die "no ssh to $label ($target) after 15 minutes"
}
