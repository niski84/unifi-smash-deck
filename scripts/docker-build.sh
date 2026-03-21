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

cd "$(dirname "$0")/.."

echo "=== Building ${IMAGE}:${TAG} ==="
docker build --platform linux/amd64 -t "${IMAGE}:${TAG}" .
echo "✓ Build complete"

if [[ "${1:-}" == "push" ]]; then
  echo "=== Pushing ${IMAGE}:${TAG} ==="
  docker push "${IMAGE}:${TAG}"
  echo "✓ Pushed"
fi
