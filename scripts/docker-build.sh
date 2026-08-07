#!/usr/bin/env bash
# ── scripts/docker-build.sh ───────────────────────────────────────────────────
# Build and optionally push the Docker image locally.
#
# Usage:
#   ./scripts/docker-build.sh               # build only, tag as :dev
#   ./scripts/docker-build.sh push          # build + push to GHCR
#   GHCR_USER=yourname ./scripts/docker-build.sh push
#
set -euo pipefail

GHCR_USER="${GHCR_USER:-niski84}"
IMAGE="ghcr.io/${GHCR_USER}/unifi-smash-deck"
TAG="${TAG:-dev}"

# Use podman if docker isn't available (Linux workstations).
DOCKER="${DOCKER:-$(command -v podman 2>/dev/null || command -v docker)}"

cd "$(dirname "$0")/.."

echo "=== Building ${IMAGE}:${TAG} ==="
"$DOCKER" build --platform linux/amd64 -t "${IMAGE}:${TAG}" .
echo "✓ Build complete"

# Always prune dangling images after a build — the Go builder stage is ~13GB
# and accumulates fast. This only removes layers not referenced by any tag.
echo "=== Pruning dangling layers ==="
"$DOCKER" image prune -f
echo "✓ Pruned"

if [[ "${1:-}" == "push" ]]; then
  echo "=== Pushing ${IMAGE}:${TAG} ==="
  "$DOCKER" push "${IMAGE}:${TAG}"
  echo "✓ Pushed"
fi
