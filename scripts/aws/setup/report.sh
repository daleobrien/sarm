#!/usr/bin/env bash
# report.sh [role] — what this box ended up with.
#
# Run on the instance, last. Reads /tmp/sarm-pmu if profiling.sh left one.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROLE="${1:-metal}"
DEST="$SARM_DEST"

say "Ready"
printf '   %-22s %s\n' "role"        "$ROLE"
printf '   %-22s %s\n' "CPUs"        "$(nproc)"
if [ "$ROLE" != "load" ]; then
    printf '   %-22s %s\n' "sarm"    "$DEST"
    printf '   %-22s %s\n' "binary"  "$DEST/sarm"
fi
if [ "$ROLE" = "metal" ]; then
    printf '   %-22s %s\n' "PMU" \
        "$([ "$(cat /tmp/sarm-pmu 2>/dev/null)" = available ] \
            && echo 'available' || echo 'UNAVAILABLE — sampling only')"
fi
printf '   %-22s %s\n' "apt log" "/tmp/sarm-apt.log"

case "$ROLE" in
    load)  TOOLS="wrk h2load curl" ;;
    server) TOOLS="curl h2load" ;;
    *)     TOOLS="perf wrk h2load bpftrace valgrind" ;;
esac
for t in $TOOLS; do
    printf '   %-22s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo '— not installed')"
done

case "$ROLE" in
    metal)
        cat <<NEXT

   Next:
     cd $DEST
     ./scripts/aws/run_perf_suite.sh

   Log out and back in first if you want the raised ulimits in your shell.
NEXT
        ;;
    server)
        cat <<NEXT

   This box builds and runs sarm; the load comes from somewhere else.
   Start it by hand with:
     $DEST/sarm <port> --workers auto
NEXT
        ;;
    load)
        cat <<NEXT

   This box generates load and has no sarm binary of its own. Point it at
   a server with:
     cd $HOME/sarm
     ./scripts/benchmarks/rps_bench.sh --target <host>:<port>
NEXT
        ;;
esac
