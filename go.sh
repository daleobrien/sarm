#!/usr/bin/env bash
# go.sh — build and run ymawky in a scratch container.
#
# Usage:
#   ./go.sh              # build, then run on port 8080
#   ./go.sh 9090         # build, then run on port 9090
set -euo pipefail

PORT="${1:-8080}"
IMAGE="ymawky:latest"

echo "==> building ${IMAGE} …"
docker build --platform linux/arm64 -t "$IMAGE" .

echo "==> running on http://127.0.0.1:${PORT}"
docker run --rm -p "${PORT}:8080" "$IMAGE"
