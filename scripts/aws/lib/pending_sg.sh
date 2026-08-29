# pending_sg.sh — the deferred deletion lists.
#
# A security group cannot be deleted while an instance still holds it, and
# a terminating bare-metal instance can take many minutes to let go. We
# refuse to pay for that wall-clock, so instead of waiting the group is
# written down and a later run collects it. The list is plain text, one
# "<region> <sg-id> <tag>" per line, and is rewritten atomically so two
# scripts racing on it cannot leave it half-written.
#
# Requires: common.sh, and $TAG set by the caller.

[ -n "${SARM_AWS_PENDING_SG_SH:-}" ] && return 0
SARM_AWS_PENDING_SG_SH=1

PENDING_SG_FILE="${SARM_PENDING_SG_FILE:-${XDG_CACHE_HOME:-$HOME/.cache}/sarm/pending-security-groups}"
# Placement groups have the same problem for the same reason: a cluster
# placement group cannot be deleted while an instance is still in it.
PENDING_PG_FILE="${SARM_PENDING_PG_FILE:-${XDG_CACHE_HOME:-$HOME/.cache}/sarm/pending-placement-groups}"

defer_placement_group() {
    local pg="$1" region="${2:-$REGION}"
    mkdir -p "$(dirname "$PENDING_PG_FILE")" 2>/dev/null || return 0
    printf '%s %s %s\n' "$region" "$pg" "${TAG:-}" >> "$PENDING_PG_FILE" || return 0
    info "placement group $pg queued for deletion on a later run ($region)"
}

# Same shape as the security-group sweep: try each one, drop what goes
# away, keep what is still held. A placement group is named rather than
# id'd, and its "already gone" error reads differently, which is the only
# reason this is not one function with the other.
sweep_pending_placement_groups() {
    [ -s "$PENDING_PG_FILE" ] || return 0

    local tmp kept=0 gone=0 err region pg tag
    tmp="$(mktemp "${PENDING_PG_FILE}.XXXXXX")" || return 0

    while read -r region pg tag; do
        [ -n "${pg:-}" ] && [ -n "${region:-}" ] || continue
        if err="$(aws --region "$region" --output text \
                    ec2 delete-placement-group --group-name "$pg" 2>&1)"; then
            gone=$((gone + 1))
        elif printf '%s' "$err" | grep -q 'InvalidPlacementGroup\.Unknown'; then
            gone=$((gone + 1))
        else
            printf '%s %s %s\n' "$region" "$pg" "${tag:-}" >> "$tmp"
            kept=$((kept + 1))
        fi
    done < "$PENDING_PG_FILE"

    if [ -s "$tmp" ]; then
        mv "$tmp" "$PENDING_PG_FILE"
    else
        rm -f "$tmp" "$PENDING_PG_FILE"
    fi

    [ "$gone" -gt 0 ] && info "deleted $gone deferred placement group(s)"
    [ "$kept" -gt 0 ] && info "$kept placement group(s) still in use — will retry next run"
    return 0
}

# The region is on the line because a group id means nothing without one:
# a later run may well be launching somewhere else entirely, and the
# region a group was created in is not necessarily the region this run
# ends in — the launch walks a candidate list and abandons a region that
# has no capacity, leaving a group behind in it. So the region is passed
# in by the caller rather than read from $REGION, which by then has moved
# on. It still defaults to $REGION for the common case.
defer_security_group() {
    local sg="$1" region="${2:-$REGION}"
    mkdir -p "$(dirname "$PENDING_SG_FILE")" 2>/dev/null || return 0
    printf '%s %s %s\n' "$region" "$sg" "${TAG:-}" >> "$PENDING_SG_FILE" || return 0
    info "security group $sg queued for deletion on a later run ($region)"
}

# Try every group on the list; drop the ones that go away, keep the ones
# that are still held by an instance that has not finished dying. Entirely
# best-effort: this must never be a reason for a run to fail or to stall,
# so it never waits on anything and always returns 0.
sweep_pending_security_groups() {
    # One entry point for the callers: a run that never made a placement
    # group still cleans up after one that did. First, because the early
    # return below is about the security-group list only.
    sweep_pending_placement_groups
    [ -s "$PENDING_SG_FILE" ] || return 0

    local tmp kept=0 gone=0 err region sg tag
    tmp="$(mktemp "${PENDING_SG_FILE}.XXXXXX")" || return 0

    while read -r region sg tag; do
        # Both fields are required: a line missing the region cannot be
        # acted on at all, since a group id is only unique within one.
        [ -n "${sg:-}" ] && [ -n "${region:-}" ] || continue
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

# The --sweep-only path, shared by every orchestrator that has one.
report_pending_security_groups() {
    if [ -s "$PENDING_SG_FILE" ]; then
        info "still pending in $PENDING_SG_FILE:"
        sed 's/^/     /' "$PENDING_SG_FILE"
    else
        info "no security groups pending deletion"
    fi
    if [ -s "$PENDING_PG_FILE" ]; then
        info "still pending in $PENDING_PG_FILE:"
        sed 's/^/     /' "$PENDING_PG_FILE"
    fi
}
