#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
go build -o unifi-smash-deck ./cmd/unifideck
echo "Build OK: $PROJECT_DIR/unifi-smash-deck"
