# common.sh — output helpers and small utilities shared by the EC2
# orchestration scripts. Sourced, never executed.
#
# Everything in scripts/aws/lib/ runs on the LAPTOP (the machine driving
# the run), not on the instance; the instance-side counterparts live in
# scripts/aws/setup/.

# Guard against double-sourcing: these files are sourced in a fixed order
# by each orchestrator, and a helper that is sourced twice would redefine
# functions the caller may already have overridden.
[ -n "${SARM_AWS_COMMON_SH:-}" ] && return 0
SARM_AWS_COMMON_SH=1

say()  { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '\033[1;33m   WARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m   FATAL: %s\033[0m\n' "$*" >&2; exit 1; }

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
    done
}

# A non-negative integer, or a message naming the flag it came from.
require_uint() {  # require_uint <value> <flag>
    case "$1" in
        ''|*[!0-9]*) echo "$0: $2 must be a non-negative integer" >&2; exit 2 ;;
    esac
}

# Display only — the Pricing API pads to ten decimal places and the spot
# history to six, and neither reads as money. The unrounded values are
# what the comparisons use; nothing numeric goes through here.
fmt_price() {
    printf '%s' "$1" | sed 's/\(\.[0-9]*[1-9]\)0*$/\1/; s/\.0*$//'
}

# a < b, on decimals. [ -lt ] is integers only and every price here is not.
lt_decimal() {
    [ "$(awk -v a="$1" -v b="$2" 'BEGIN{print (a<b)?1:0}')" = 1 ]
}
