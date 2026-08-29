# pricing.sh — spot vs on-demand, per zone and per region.
#
# Spot is the same instance on the same hardware; what differs is that AWS
# can take it back with two minutes' notice, and that the price floats.
# The deadman shutdown and the cleanup traps already assume the box can
# vanish, so an interruption costs a re-run, not a leak — but a long suite
# is a bigger bet than a quick one.
#
# The price is per zone, and on metal the spread between zones in one
# region is routinely 2x, so on spot the zones are tried cheapest first
# rather than in AWS's order. One API call per zone per type, skipped
# entirely under --on-demand.
#
# EVERY FIGURE HERE COVERS THE WHOLE RUN, not one instance: prices are
# summed over $ITYPES. A two-box run is one bill, and the zone that is
# cheapest for the pair is not necessarily the cheapest for either half.
#
# Requires: common.sh, region.sh.
# Caller sets: ITYPES, PRICE_GROUP, SPOT_WANTED, PENDING_REGIONS.
# It maintains: SPOT, ONDEMAND, SPOT_AZS, AZS, AZ, REGION, AMI, AWSC.

[ -n "${SARM_AWS_PRICING_SH:-}" ] && return 0
SARM_AWS_PRICING_SH=1

# The on-demand rate for one instance type in one region, from the Pricing
# API — which lives only in a handful of endpoints, so the call goes to
# us-east-1 and names the region of interest as a filter rather than being
# made there.
#
# There is no --query path into the answer: the Pricing API returns each
# product as a *JSON string*, not as structure, so JMESPath sees one
# opaque blob. Hence the sed: cut the OnDemand term out of the blob
# before reading a price from it, or the first "USD" found would be
# whichever reserved-instance rate happened to be serialised first.
ondemand_price_one() {  # ondemand_price_one <itype> <region>
    aws --region us-east-1 --output text pricing get-products \
        --service-code AmazonEC2 \
        --filters "Type=TERM_MATCH,Field=instanceType,Value=$1" \
                  "Type=TERM_MATCH,Field=regionCode,Value=$2" \
                  "Type=TERM_MATCH,Field=operatingSystem,Value=Linux" \
                  "Type=TERM_MATCH,Field=tenancy,Value=Shared" \
                  "Type=TERM_MATCH,Field=preInstalledSw,Value=NA" \
                  "Type=TERM_MATCH,Field=capacitystatus,Value=Used" \
        --query 'PriceList[0]' 2>/dev/null \
        | sed 's/.*"OnDemand"//; s/"Reserved".*//' \
        | grep -o '"USD" *: *"[0-9.]*"' | head -1 | grep -o '[0-9.]*' || true
}

# The run's on-demand rate: every type in $ITYPES, added up. Empty if any
# one of them cannot be priced — a partial total would understate the bill
# and, worse, would make spot look more expensive than it is.
ondemand_price() {
    local region="${1:-$REGION}" t p total=0
    for t in $ITYPES; do
        p="$(ondemand_price_one "$t" "$region")"
        case "$p" in ''|*[!0-9.]*|*.*.*) return 0 ;; esac
        total="$(awk -v a="$total" -v b="$p" 'BEGIN{printf "%.10f", a+b}')"
    done
    printf '%s' "$total"
}

spot_price_one() {  # spot_price_one <itype> <az> <region>
    aws --region "$3" --output text ec2 describe-spot-price-history \
        --instance-types "$1" --product-descriptions "Linux/UNIX" \
        --availability-zone "$2" --start-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
        --query 'SpotPriceHistory[0].SpotPrice' 2>/dev/null | head -1 || true
}

# The run's spot rate in one zone. The zone is $1; the region defaults to
# $REGION but is a parameter, because the price comparison below quotes
# zones in a region this run has not moved to yet. Empty when any type in
# the run has no published price there: the pair is launched together, so
# a zone that can only price half of it cannot be compared on price.
spot_price() {
    local az="$1" region="${2:-$REGION}" t p total=0
    for t in $ITYPES; do
        p="$(spot_price_one "$t" "$az" "$region")"
        case "$p" in ''|*[!0-9.]*|*.*.*) return 0 ;; esac
        total="$(awk -v a="$total" -v b="$p" 'BEGIN{printf "%.10f", a+b}')"
    done
    printf '%s' "$total"
}

# Rewrites $AZS in ascending price order, dropping nothing: a zone with no
# published price still gets tried, just last.
#
# Written without a `case` inside the command substitution on purpose:
# bash 3.2, which is what macOS still ships as /bin/bash, fails to parse
# one at runtime even though `bash -n` accepts the file.
order_azs_by_price() {
    local az price prices sorted cheaper saving
    prices=""
    for az in $AZS; do
        # Anything that is not a bare decimal — "None", an error, or a
        # stray extra line — is treated as "no price": the field is fed
        # straight into a sort key, so a mangled value would silently
        # reshuffle or drop a zone rather than fail loudly.
        price="$(spot_price "$az")"
        case "$price" in
            ''|*[!0-9.]*|*.*.*) price=999 ;;   # sorts last, still gets tried
        esac
        prices="$prices$price $az
"
    done
    sorted="$(printf '%s' "$prices" | sort -n)"
    [ -n "$sorted" ] || return 0

    # Spot is only worth its interruption risk where it is actually
    # cheaper. AWS caps the spot price at the on-demand rate, so a zone
    # can sit at exact parity — all of the risk, none of the discount —
    # and those zones are launched on-demand instead. Zones qualifying
    # for spot are collected in $SPOT_AZS; the ordering is untouched, so
    # nothing is dropped from the capacity search either way.
    SPOT_AZS=""
    while read -r price az; do
        [ -n "$az" ] || continue
        if [ "$price" = 999 ]; then
            info "$(printf '%-18s' "$az") no published spot price — on-demand there"
        elif [ -z "$ONDEMAND" ]; then
            info "$(printf '%-18s' "$az") \$$(fmt_price "$price")/hr spot"
            SPOT_AZS="$SPOT_AZS $az"
        else
            cheaper="$(awk -v s="$price" -v o="$ONDEMAND" 'BEGIN{print (s<o)?1:0}')"
            saving="$(awk -v s="$price" -v o="$ONDEMAND" 'BEGIN{printf "%.0f", (o-s)*100/o}')"
            if [ "$cheaper" = 1 ]; then
                info "$(printf '%-18s' "$az") \$$(fmt_price "$price")/hr spot — ${saving}% under on-demand"
                SPOT_AZS="$SPOT_AZS $az"
            else
                info "$(printf '%-18s' "$az") \$$(fmt_price "$price")/hr spot — no saving, on-demand there"
            fi
        fi
    done <<PRICES
$sorted
PRICES

    SPOT_AZS="${SPOT_AZS# }"        # comparable with $AZS below
    AZS="$(printf '%s' "$sorted" | awk '{printf "%s ", $2}' | sed 's/ *$//')"
    AZ="${AZS%% *}"
}

# The cheapest published spot price across a region's zones, and nothing
# else on stdout. Empty when no zone in it publishes one — which is not
# the same as cheap, so callers must not read it as zero.
region_min_spot() {
    local region="$1" az price best=""
    for az in $2; do
        price="$(spot_price "$az" "$region")"
        case "$price" in ''|*[!0-9.]*|*.*.*) continue ;; esac
        if [ -z "$best" ] || lt_decimal "$price" "$best"; then
            best="$price"
        fi
    done
    printf '%s' "$best"
}

# The regions in $PRICE_GROUP are compared on price rather than taken in
# list order — see the callers. next_region() has already settled on one
# of them by list order; this runs before anything has been created in it,
# so switching is free, and it only ever moves the run WITHIN the group.
#
# The cost is one probe (three calls) plus one call per zone per type for
# each peer, paid once, only on spot, and only when the chosen region is
# in the group. The probe is cached for the capacity fallback, so a peer
# that loses on price is not re-probed if the winner runs out of metal.
GROUP_COMPARED=0
cheapest_price_group() {
    local peer entry azs price rest saving
    local best_region best_price best_entry home_price
    [ "$GROUP_COMPARED" = 0 ] || return 0
    GROUP_COMPARED=1
    case " $PRICE_GROUP " in *" $REGION "*) ;; *) return 0 ;; esac

    rest=""
    for peer in $PENDING_REGIONS; do
        case " $PRICE_GROUP " in *" $peer "*) rest="$rest $peer" ;; esac
    done
    [ -n "$rest" ] || return 0

    say "Cheapest spot in the region group"
    best_region="$REGION"
    best_price="$(region_min_spot "$REGION" "$AZS")"
    best_entry=""
    home_price="$best_price"        # kept for the comparison in the move
    if [ -n "$best_price" ]; then
        info "$(printf '%-18s' "$(region_name "$REGION")") \$$(fmt_price "$best_price")/hr at its cheapest zone"
    else
        info "$(printf '%-18s' "$(region_name "$REGION")") no published spot price"
    fi

    for peer in $rest; do
        entry="$(probe_region "$peer" || true)"
        case "$entry" in "$peer|ami-"*) ;; *) continue ;; esac
        PROBED="$PROBED$entry
"
        azs="${entry##*|}"
        price="$(region_min_spot "$peer" "$azs")"
        if [ -z "$price" ]; then
            info "$(printf '%-18s' "$(region_name "$peer")") no published spot price"
            continue
        fi
        info "$(printf '%-18s' "$(region_name "$peer")") \$$(fmt_price "$price")/hr at its cheapest zone"
        if [ -z "$best_price" ] || lt_decimal "$price" "$best_price"; then
            best_region="$peer"; best_price="$price"; best_entry="$entry"
        fi
    done

    if [ "$best_region" = "$REGION" ]; then
        info "staying in $REGION — nothing cheaper in the group"
        return 0
    fi

    # The region being left is probed, viable, and now the natural first
    # fallback: cheaper is only better while the cheap one has metal.
    rest=""
    for peer in $PENDING_REGIONS; do
        [ "$peer" = "$best_region" ] || rest="$rest $peer"
    done
    PENDING_REGIONS="$REGION$rest"

    if [ -n "$home_price" ]; then
        saving="$(awk -v n="$best_price" -v h="$home_price" \
            'BEGIN{printf "%.0f", (h-n)*100/h}')"
        info "moving to $best_region — $(region_name "$best_region"), ${saving}% cheaper on spot"
    else
        info "moving to $best_region — $(region_name "$best_region") publishes a price and $REGION does not"
    fi
    REGION="$best_region"
    AMI="$(printf '%s' "$best_entry" | cut -d'|' -f2)"
    AZS="${best_entry##*|}"
    AZ="${AZS%% *}"
    AWSC=(aws --region "$REGION" --output text)
}

# Everything above, applied to whichever region the run is in. Called
# again after a capacity fallback, because none of it carries over: the
# zone order, the spot-vs-on-demand verdict and the on-demand rate itself
# are all per region, and a fallback that kept the first region's answers
# would launch on-demand in every zone of the second (its zones are not
# in $SPOT_AZS) while claiming otherwise in the plan.
price_region() {
    local short
    SPOT="$SPOT_WANTED"
    ONDEMAND=""
    SPOT_AZS=""
    [ "$SPOT" = 1 ] || return 0

    cheapest_price_group

    say "Spot pricing in $REGION"
    ONDEMAND="$(ondemand_price "$REGION")"
    if [ -n "$ONDEMAND" ]; then
        info "$(printf '%-18s' 'on-demand') \$$(fmt_price "$ONDEMAND")/hr — the bar spot has to beat"
    else
        warn "could not read the on-demand rate; taking spot in every zone"
        warn "  (spot is capped at on-demand, so this cannot cost more — it"
        warn "   just means a zone at parity will not be spotted)"
    fi
    order_azs_by_price
    if [ -z "$SPOT_AZS" ]; then
        SPOT=0
        warn "no zone is cheaper on spot — running on-demand instead"
    fi

    # A zone that just dropped to on-demand is billed against a different
    # quota than the one the region was probed against, and an unchecked
    # quota is exactly how VcpuLimitExceeded arrives minutes into a run.
    if [ "$SPOT_AZS" != "$AZS" ]; then
        short="$(vcpu_shortfall "$REGION" 0)"
        if [ -n "$short" ]; then
            warn "on-demand vCPU quota ${short%% *} < ${short##* } in $REGION"
            warn "  staying on spot in every zone: AWS caps the spot price at"
            warn "  the on-demand rate, so a zone at parity costs no more than"
            warn "  on-demand would have — it just carries the interruption risk"
            SPOT=1
            SPOT_AZS="$AZS"
        fi
    fi
}

# What the launch loop will actually ask for. Not a single answer any
# more: spot is taken only in the zones where it beats on-demand, so a
# run can be spot in its first choice and on-demand in its fallback.
market_summary() {
    if [ "$SPOT" != 1 ]; then
        echo "on-demand$([ -n "$ONDEMAND" ] && echo " at \$$(fmt_price "$ONDEMAND")/hr")"
    elif [ "$SPOT_AZS" = "$AZS" ]; then
        echo "spot in every zone — interruptible on 2 minutes notice"
    else
        echo "spot in ${SPOT_AZS:-none} — interruptible on 2 minutes notice; on-demand elsewhere"
    fi
}
