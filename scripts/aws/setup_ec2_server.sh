#!/usr/bin/env bash
# setup_ec2_server.sh — provision a box whose only job is to RUN sarm.
#
# The server half of a two-box benchmark (scripts/aws/rps_two_box_ec2.sh):
# a compiler, sarm's build inputs, the kernel limits a
# one-process-per-connection server needs, and nothing else. No profiler,
# no FlameGraph, no load generator — this box is deliberately the small,
# cheap one, and every package it skips is provisioning time not paid.
#
# There is no PMU here and none is looked for. If you want counters, rent
# metal and use setup_ec2_metal.sh.
#
# Environment overrides:
#   SARM_REPO=<git url>     default https://github.com/daleobrien/sarm.git
#   SARM_BRANCH=<branch>    default main
#   SARM_DIR=<path>         default $HOME/sarm
#
# Run on the instance. Safe to re-run.

set -euo pipefail
STEPS="$(cd "$(dirname "$0")" && pwd)/setup"
. "$STEPS/lib.sh"

check_host server
"$STEPS/packages.sh"   server
"$STEPS/tuning.sh"     server
"$STEPS/build_sarm.sh"
"$STEPS/report.sh"     server
