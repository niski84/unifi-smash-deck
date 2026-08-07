#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/sidecar/.venv"

if [ ! -d "$VENV" ]; then
  echo "virtualenv not found — run setup first:"
  echo "  python3 -m venv sidecar/.venv && source sidecar/.venv/bin/activate && pip install -r sidecar/requirements.txt"
  exit 1
fi

source "$VENV/bin/activate"
cd "$ROOT/sidecar"
exec uvicorn main:app --host 127.0.0.1 --port 8103 --workers 1
