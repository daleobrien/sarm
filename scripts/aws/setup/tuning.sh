#!/usr/bin/env bash
# tuning.sh [role] — kernel limits for a benchmark host.
#
# sarm forks a process per connection, so the limits that matter on the
# server are process-table limits, not the usual thread/fd ones. Defaults
# for pid_max are low enough to become the bottleneck being measured.
#
# The load generator needs the other half: ephemeral ports and file
# descriptors, because it is the side holding tens of thousands of
# sockets. Both sets are applied on both roles — they cost nothing on the
# box that does not need them, and a benchmark that silently ran into the
# wrong side's limit would be indistinguishable from a slow server.
#
# `perf_event_paranoid` is only lowered on the metal role: it is what lets
# perf read hardware events unprivileged, and it is not something to leave
# behind on a box that has no reason to profile.
#
# Run on the instance. Safe to re-run.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROLE="${1:-metal}"

say "Tuning the kernel for the benchmark ($ROLE)"

{
cat <<'SYSCTL'
# Written by scripts/aws/setup/tuning.sh — benchmark host tuning.

# sarm forks one process per connection: the default pid_max becomes the
# ceiling being measured long before the server does.
kernel.pid_max = 400000
kernel.threads-max = 400000

# Accept queue and ephemeral ports, so the load generator rather than the
# socket layer decides the offered rate.
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10

fs.file-max = 2000000
fs.nr_open = 2000000
SYSCTL

if [ "$ROLE" = "metal" ]; then
cat <<'SYSCTL'

# Let perf read hardware events and kernel symbols without sudo on every
# invocation. Appropriate for a dedicated benchmark box, not for a shared
# or production host.
kernel.perf_event_paranoid = -1
kernel.kptr_restrict = 0
SYSCTL
fi

if [ "$ROLE" = "load" ]; then
cat <<'SYSCTL'

# The client end of a two-box run holds every connection and opens them
# fast. A conntrack-free path and a large socket buffer keep the network
# stack from being the thing that saturates.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
SYSCTL
fi
} | sudo tee /etc/sysctl.d/99-sarm-bench.conf >/dev/null

sudo sysctl -q --system
info "applied /etc/sysctl.d/99-sarm-bench.conf"

sudo tee /etc/security/limits.d/99-sarm.conf >/dev/null <<'LIMITS'
*  soft  nofile  1000000
*  hard  nofile  1000000
*  soft  nproc   400000
*  hard  nproc   400000
LIMITS
info "applied /etc/security/limits.d/99-sarm.conf (takes effect on next login)"
