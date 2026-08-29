#!/usr/bin/env bash
# setup_ec2_metal.sh — provision an Ubuntu arm64 c6g.metal box for
# measuring and optimising sarm.
#
# Installs the measurement toolchain, fetches and builds sarm, tunes the
# kernel for a one-process-per-connection server under load, and verifies
# that the Neoverse N1 PMU is actually readable (the whole reason to rent
# metal rather than a shared instance).
#
# This is now a thin driver over the steps in scripts/aws/setup/, which is
# what lets the two-box RPS run (scripts/aws/rps_two_box_ec2.sh) provision
# a sarm-only box and a load-generator-only box from the same code without
# either of them paying for the other's toolchain:
#
#   setup/packages.sh metal   toolchain, profiler, load generators
#   setup/tuning.sh   metal   sysctl + ulimits, perf_event_paranoid
#   setup/loadgen.sh          wrk (built when not packaged), h2load
#   setup/build_sarm.sh       sources, certs, build, three-protocol smoke
#   setup/profiling.sh        perf, FlameGraph, PMU verification
#   setup/report.sh   metal   what the box ended up with
#
# It therefore needs the repository next to it — it is no longer a single
# file you can curl on its own. Get the tree first:
#
#   git clone https://github.com/daleobrien/sarm.git
#   ./sarm/scripts/aws/setup_ec2_metal.sh
#
# (scripts/aws/quick_test_ec2.sh uploads the tree for you and then runs
# this, which is the usual path.)
#
# Environment overrides:
#   SARM_REPO=<git url>     default https://github.com/daleobrien/sarm.git
#   SARM_BRANCH=<branch>    default main
#   SARM_DIR=<path>         default $HOME/sarm
#
# Reboot is not required. Re-running is safe and idempotent.

set -euo pipefail
STEPS="$(cd "$(dirname "$0")" && pwd)/setup"
. "$STEPS/lib.sh"

check_host metal
"$STEPS/packages.sh"   metal
"$STEPS/tuning.sh"     metal
"$STEPS/loadgen.sh"
"$STEPS/build_sarm.sh"
"$STEPS/profiling.sh"
"$STEPS/report.sh"     metal
