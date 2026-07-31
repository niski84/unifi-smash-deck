#!/bin/bash
set -euo pipefail

_reload_ok_double_beep() {
	local _n
	for _n in 1 2; do
		printf '\a' 2>/dev/null || true
		sleep 0.12
	done
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/unifi-smash-deck"

echo "=== UniFi Smash Deck reload ==="
echo "→ Stopping existing process..."
_stopped=0
if [[ -f "$PROJECT_DIR/unifi-smash-deck.pid" ]]; then
  _pid="$(tr -cd '0-9' < "$PROJECT_DIR/unifi-smash-deck.pid")"
  if [[ -n "$_pid" ]] && [[ -e "/proc/$_pid/exe" ]] && [[ "$(readlink "/proc/$_pid/exe" 2>/dev/null || true)" == "$BINARY"* ]]; then
    kill "$_pid" 2>/dev/null || true
    _stopped=1
    for _i in $(seq 1 50); do
      kill -0 "$_pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
fi
if [[ "$_stopped" -eq 0 ]]; then
	for _pid in $(pgrep -f "^${BINARY//./\\.}$" 2>/dev/null || true); do
		kill "$_pid" 2>/dev/null || true
		_stopped=1
		for _i in $(seq 1 50); do
			kill -0 "$_pid" 2>/dev/null || break
			sleep 0.1
		done
	done
fi
if [[ "$_stopped" -eq 0 ]]; then
	echo "  (none running)"
fi

# ── vault: pull fresh secrets from Infisical before sourcing .env ─────────────
_VAULT_SYNC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../../infrastructure && pwd)/sync-secrets.sh"
if [[ -f "$_VAULT_SYNC" ]] && [[ -n "${INFISICAL_CLIENT_ID:-}" ]]; then
  echo "→ Pulling secrets from vault (unifi-smash-deck)..."
  "$_VAULT_SYNC" --pull unifi-smash-deck 2>/dev/null || echo "  ⚠  Vault pull skipped (using cached .env)"
fi
# ─────────────────────────────────────────────────────────────────────────────

if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$PROJECT_DIR/.env"
    set +a
fi

echo "→ Building..."
cd "$PROJECT_DIR"
go build -o "$BINARY" ./cmd/unifideck
echo "  Build OK: $BINARY"

# ── single source of truth for the port: data/unifideck-settings.json (.port) ──
# Falls back to $PORT from .env, then 8099. The app (main.go → LoadAppConfig) reads
# the same settings.json, so reload, healthcheck, and the server always agree.
_SETTINGS="$PROJECT_DIR/data/unifideck-settings.json"
_SETTINGS_PORT=""
if [ -f "$_SETTINGS" ]; then
  _SETTINGS_PORT="$(python3 -c "import json;print(json.load(open('$_SETTINGS')).get('port','') or '')" 2>/dev/null || true)"
fi
PORT="${_SETTINGS_PORT:-${PORT:-8099}}"
export PORT

# ── port-conflict guard: fail loudly with the culprit, never crash cryptically ─
_holder="$(ss -tlnp 2>/dev/null | awk -v p=":${PORT}\$" '$4 ~ p {print $0}')"
if [[ -n "$_holder" ]] && ! echo "$_holder" | grep -q "$BINARY"; then
  echo "✗ Port ${PORT} is already held by another process:"
  echo "    $_holder"
  echo "  Refusing to start. Change \"port\" in $_SETTINGS or stop the other service."
  exit 1
fi

echo "→ Starting on :${PORT}..."
nohup env PORT="$PORT" "$BINARY" >"$PROJECT_DIR/unifi-smash-deck.log" 2>&1 &
echo $! >"$PROJECT_DIR/unifi-smash-deck.pid"

for i in $(seq 1 30); do
  sleep 0.2
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    echo "✓ UniFi Smash Deck at http://127.0.0.1:${PORT}/"
    _reload_ok_double_beep
    exit 0
  fi
done
echo "✗ Server did not respond — check unifi-smash-deck.log"
exit 1
