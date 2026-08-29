# region.sh — choosing a region that can actually run this benchmark.
#
# Bare metal (and, on a two-box run, an unusual pair of types) is not
# offered everywhere, and where it is offered a given zone can still be
# out of it. So rather than hard-coding one region, walk a preference list
# and keep the ones that survive three cheap, free API checks:
#
#   * Canonical publishes the Ubuntu arm64 image there,
#   * EVERY wanted instance type is offered in at least one shared zone,
#   * the vCPU quota is big enough for all of them at once.
#
# None of that proves there is capacity — only run-instances can, and the
# answer changes minute to minute. So this is a shortlist, not a decision:
# the launch walks the zones of the winning region, and then the next
# region, until one actually hands over the machines.
#
# Requires: common.sh.
#
# Caller sets, before calling next_region():
#   ITYPES          space-separated instance types the run needs, ALL of
#                   which must be offered in the same zone. One entry is
#                   the ordinary single-box case.
#   UBUNTU          release, e.g. 26.04
#   AMI_PINNED      an explicit --ami, or empty
#   SPOT_WANTED     1 if the run asked for spot (picks the quota to check)
#   PENDING_REGIONS the queue of candidate region codes
#
# It sets, on success: REGION, AMI, AZS, AZ, AWSC.

[ -n "${SARM_AWS_REGION_SH:-}" ] && return 0
SARM_AWS_REGION_SH=1

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
        ap-northeast-2) printf 'Seoul' ;;
        ap-south-1)     printf 'Mumbai' ;;
        us-east-1)      printf 'N. Virginia' ;;
        us-east-2)      printf 'Ohio' ;;
        us-west-1)      printf 'N. California' ;;
        us-west-2)      printf 'Oregon' ;;
        eu-west-1)      printf 'Ireland' ;;
        eu-west-2)      printf 'London' ;;
        eu-central-1)   printf 'Frankfurt' ;;
        ca-central-1)   printf 'Canada Central' ;;
        sa-east-1)      printf 'Sao Paulo' ;;
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

# Regions the account can actually use. Several of the candidates —
# Melbourne among them — are opt-in: they exist, they publish images and
# instance types, and every API call against them fails with AuthFailure
# until the account enables them in the console. Without this check that
# looks identical to "no image published here", which sends you hunting
# the wrong problem. One call, cached, and only made once a probe needs it.
ENABLED_REGIONS=""
region_enabled() {
    if [ -z "$ENABLED_REGIONS" ]; then
        ENABLED_REGIONS="$(aws --region us-east-1 --output text ec2 describe-regions \
            --query 'Regions[].RegionName' 2>/dev/null | tr '\t' ' ' || true)"
        # Unreadable (no ec2:DescribeRegions) is not evidence of anything,
        # so fall back to letting every candidate through.
        [ -n "$ENABLED_REGIONS" ] || ENABLED_REGIONS="ALL"
    fi
    [ "$ENABLED_REGIONS" = "ALL" ] && return 0
    case " $ENABLED_REGIONS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# vCPUs from the size suffix alone, without an API call and before any
# region has been chosen. Modern EC2 families are consistent about this —
# .large is 2, .4xlarge is 16 — which is what lets the pair be sized
# against each other while the bill is still zero. Anything unrecognised
# returns 1 (failure) and the caller asks AWS instead.
itype_vcpus_static() {
    case "${1##*.}" in
        medium)            printf 2 ;;   # c7g.medium is 1, but 2 is the
                                         #   safe direction for sizing a
                                         #   load box against it
        large)             printf 2 ;;
        xlarge)            printf 4 ;;
        2xlarge)           printf 8 ;;
        4xlarge)           printf 16 ;;
        8xlarge)           printf 32 ;;
        12xlarge)          printf 48 ;;
        16xlarge|metal)    printf 64 ;;
        24xlarge)          printf 96 ;;
        48xlarge|metal-48xl) printf 192 ;;
        *) return 1 ;;
    esac
}

# vCPUs of one instance type, or empty when the region cannot be asked.
itype_vcpus() {
    local v
    v="$(aws --region "$1" --output text ec2 describe-instance-types \
           --instance-types "$2" \
           --query 'InstanceTypes[0].VCpuInfo.DefaultVCpus' 2>/dev/null || true)"
    case "$v" in ''|None|*[!0-9]*) return 0 ;; esac
    printf '%s' "$v"
}

# Echoes "<quota> <vcpus>" when the region's vCPU quota is known to be too
# small for the WHOLE run — every type in $ITYPES at once, since a two-box
# run holds both instances simultaneously and they count against one
# quota. Silent when it is big enough or unreadable; an unreadable quota
# (no servicequotas:GetServiceQuota) is not evidence of a small one.
#
# Spot and on-demand are counted against SEPARATE quotas, so which one to
# ask about is a parameter rather than a constant: the price check can
# move a run to on-demand after its region was probed on spot, and the
# quota that was checked would then be the wrong one.
#   L-34B43A08  All Standard Spot Instance Requests
#   L-1216C47A  Running On-Demand Standard instances
vcpu_shortfall() {
    local region="$1" use_spot="$2" t v quota quota_code total=0 known=0
    for t in $ITYPES; do
        v="$(itype_vcpus "$region" "$t")"
        [ -n "$v" ] || continue
        total=$(( total + v ))
        known=1
    done
    [ "$known" = 1 ] || return 0
    quota_code=L-1216C47A
    [ "$use_spot" = 1 ] && quota_code=L-34B43A08
    quota="$(aws --region "$region" --output text service-quotas get-service-quota \
               --service-code ec2 --quota-code "$quota_code" \
               --query 'Quota.Value' 2>/dev/null || true)"
    [ -n "$quota" ] && [ "$quota" != "None" ] || return 0
    if [ "${quota%%.*}" -lt "$total" ]; then
        printf '%s %s\n' "${quota%%.*}" "$total"
    fi
}

# Its stdout is the machine-readable "<region>|<ami>|<zones>" result line
# and nothing else — the caller captures it — so progress messages here go
# to stderr.
#
# The zone list is the INTERSECTION across $ITYPES. On a two-box run the
# server and the load generator must share a zone: across zones the link
# is slower, less predictable, and billed per gigabyte, and the benchmark
# would be measuring the network rather than the server.
probe_region() {
    local region="$1" ami azs t offered label short
    label="$(printf '%-16s %-14s' "$region" "$(region_name "$region")")"
    local awsc=(aws --region "$region" --output text)

    if ! region_enabled "$region"; then
        info "$label not enabled on this account (opt-in region)" >&2
        return 1
    fi

    # AMI_PINNED, not AMI: AMI holds whatever the last probe resolved, and
    # in a fallback probe that is the previous region's image id — which
    # exists nowhere else. Only an explicit --ami pins across regions.
    ami="$AMI_PINNED"
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
    azs=""
    for t in $ITYPES; do
        offered="$("${awsc[@]}" ec2 describe-instance-type-offerings \
                     --location-type availability-zone \
                     --filters "Name=instance-type,Values=$t" \
                     --query 'InstanceTypeOfferings[].Location' 2>/dev/null | tr '\t' ' ' || true)"
        offered="$(printf '%s' "$offered" | tr -s ' ' | sed 's/^ *//; s/ *$//')"
        if [ -z "$offered" ] || [ "$offered" = "None" ]; then
            info "$label $t not offered" >&2
            return 1
        fi
        if [ -z "$azs" ]; then
            azs="$offered"
        else
            azs="$(intersect_words "$azs" "$offered")"
        fi
    done
    if [ -z "$azs" ]; then
        info "$label no single zone offers all of: $ITYPES" >&2
        return 1
    fi

    # A region with no DEFAULT VPC cannot be used by this script: the
    # security group and the subnet lookup are both built on it. us-east-1
    # is in the default candidate list and has no default VPC on this
    # account, and without this check a run that fell through to it died
    # outright — after the earlier regions had been probed, priced and
    # walked — rather than moving on to the next candidate. One call, and
    # it turns a fatal into a skip.
    local vpc
    vpc="$("${awsc[@]}" ec2 describe-vpcs --filters Name=isDefault,Values=true \
             --query 'Vpcs[0].VpcId' 2>/dev/null || true)"
    if [ -z "$vpc" ] || [ "$vpc" = "None" ]; then
        info "$label no default VPC" >&2
        return 1
    fi

    # The quota is per region and counts vCPUs, not instances, so a
    # 64-core metal box needs 64 against a default that is often 5. This
    # is the failure that otherwise appears as VcpuLimitExceeded several
    # minutes and one security group into the run.
    short="$(vcpu_shortfall "$region" "$SPOT_WANTED")"
    if [ -n "$short" ]; then
        info "$label $([ "$SPOT_WANTED" = 1 ] && echo spot || echo on-demand) vCPU quota ${short%% *} < ${short##* }" >&2
        return 1
    fi

    printf '%s|%s|%s\n' "$region" "$ami" "$azs"
    return 0
}

# Words present in both lists, in the order of the first.
intersect_words() {
    local w out=""
    for w in $1; do
        case " $2 " in *" $w "*) out="$out $w" ;; esac
    done
    printf '%s' "${out# }"
}

# Regions the price comparison already probed, as probe_region's own
# "<region>|<ami>|<zones>" lines. A probe is three round trips to the
# other side of the planet; having paid for them once, the capacity
# fallback should not pay again.
PROBED=""
probe_cached() {
    printf '%s\n' "$PROBED" | grep "^$1|" | head -1 || true
}

# Probing is lazy: the first region that passes is the one we use, and the
# rest are never asked about unless it turns out to have no capacity. Four
# regions x three API calls is a slow way to answer a question that the
# first region almost always settles, and every one of those calls is a
# round trip to the other side of the planet.
next_region() {
    local region entry
    while [ -n "$PENDING_REGIONS" ]; do
        region="${PENDING_REGIONS%% *}"
        case "$PENDING_REGIONS" in
            *' '*) PENDING_REGIONS="${PENDING_REGIONS#* }" ;;
            *)     PENDING_REGIONS="" ;;
        esac

        entry="$(probe_cached "$region")"
        if [ -z "$entry" ]; then
            entry="$(probe_region "$region" || true)"
            case "$entry" in "$region|ami-"*) PROBED="$PROBED$entry
" ;; esac
        fi
        case "$entry" in "$region|ami-"*) ;; *) continue ;; esac

        REGION="$region"
        AMI="$(printf '%s' "$entry" | cut -d'|' -f2)"
        AZS="${entry##*|}"
        AZ="${AZS%% *}"
        AWSC=(aws --region "$REGION" --output text)
        info "$(printf '%-16s %-14s' "$REGION" "$(region_name "$REGION")") ok — $(printf '%s' "$AZS" | wc -w | tr -d ' ') zone(s) offering $ITYPES"
        return 0
    done
    return 1
}

no_region_left() {
    die "no region can run $ITYPES on Ubuntu $UBUNTU arm64 — tried:
       $REGION_CANDIDATES
   The reason per region is listed above. The ones that repeat:
     * opt-in region    — enable it in the console (Account > AWS Regions)
     * not offered      — that type does not exist there; try --type
$([ "$(printf '%s' "$ITYPES" | wc -w)" -gt 1 ] && cat <<'MULTI'
     * no single zone   — the types all exist in the region but never in
                          one zone, and a multi-box run needs one zone
MULTI
)     * vCPU quota       — $([ "$SPOT_WANTED" = 1 ] && echo 'spot' || echo 'on-demand') limit is too small for every instance
                          this run holds at once, and spot and on-demand
                          are counted separately. Request a rise in
                          Service Quotas, or try --on-demand.
   Pick one explicitly with --region, or different types with --type.
   List what Canonical publishes in a region with:
     aws --region <region> ssm get-parameters-by-path --recursive \\
         --path /aws/service/canonical/ubuntu/server --query 'Parameters[].Name' \\
       | tr '\\t' '\\n' | grep 'current/arm64/hvm/ebs-gp3'"
}
