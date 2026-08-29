#!/usr/bin/env bash
# setup_ec2_load.sh — provision a box whose only job is to GENERATE load.
#
# The client half of a two-box benchmark (scripts/aws/rps_two_box_ec2.sh):
# wrk, h2load, and the socket limits a machine holding tens of thousands
# of connections needs. sarm is never built here — the binary under test
# lives on the other box, and this one is sized so that it is never the
# thing that runs out.
#
# It still wants the repository, because scripts/benchmarks/rps_bench.sh
# is what drives the load and scripts/benchmarks/pipeline.lua is what wrk
# reads for --pipeline.
#
# Run on the instance. Safe to re-run.

set -euo pipefail
STEPS="$(cd "$(dirname "$0")" && pwd)/setup"
. "$STEPS/lib.sh"

check_host load
"$STEPS/packages.sh" load
"$STEPS/tuning.sh"   load
"$STEPS/loadgen.sh"
"$STEPS/report.sh"   load
