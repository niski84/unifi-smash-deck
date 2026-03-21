#!/usr/bin/env bash
# ── scripts/deploy-nas.sh ─────────────────────────────────────────────────────
# SSH into the NAS and update the running container to the latest image.
#
# Pre-requisites on the NAS:
#   1. docker-compose.yml copied to NAS_DEPLOY_DIR (see below)
#   2. SSH key-based auth configured (or use NAS_SSH_PASS with sshpass)
#   3. Docker / Podman installed
#
# Usage:
#   NAS_HOST=192.168.0.x NAS_USER=admin NAS_DEPLOY_DIR=/volume1/docker/unifideck \
#     ./scripts/deploy-nas.sh
#
set -euo pipefail

NAS_HOST="${NAS_HOST:?Set NAS_HOST to your NAS IP address}"
NAS_USER="${NAS_USER:-admin}"
NAS_DEPLOY_DIR="${NAS_DEPLOY_DIR:-/volume1/docker/unifideck}"
COMPOSE_CMD="${COMPOSE_CMD:-docker compose}"

echo "=== Deploying to ${NAS_USER}@${NAS_HOST}:${NAS_DEPLOY_DIR} ==="

# Ensure the deploy directory and docker-compose.yml exist on the NAS.
scp -q docker-compose.yml "${NAS_USER}@${NAS_HOST}:${NAS_DEPLOY_DIR}/docker-compose.yml"

ssh -o StrictHostKeyChecking=accept-new "${NAS_USER}@${NAS_HOST}" bash -s <<EOF
  set -e
  cd "${NAS_DEPLOY_DIR}"
  echo "  Pulling latest image…"
  ${COMPOSE_CMD} pull
  echo "  Restarting container…"
  ${COMPOSE_CMD} up -d --remove-orphans
  echo "  Container status:"
  ${COMPOSE_CMD} ps
EOF

echo "✓ Deploy complete — http://${NAS_HOST}:8099"
