# UniFi Smash Deck

A self-hosted web dashboard for managing and monitoring a **UniFi UDM Pro** (or any UniFi OS device).  Written in Go with a zero-dependency frontend — a single binary serves both the API and the UI.

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fniski84%2Funifi--smash--deck-2496ED?logo=docker&logoColor=white)

---

## Features

| Tab | What it does |
|-----|-------------|
| **Networks** | List VLANs/networks, enable or disable them with one click |
| **Automations** | Schedule a network to be shut off (and optionally re-enabled) at a specific time — supports days-of-week, timezone, skip-weekends, and end dates |
| **Cameras** → Live View | Live snapshot grid for all UniFi Protect cameras; click any image to open a full-screen lightbox with zoom, pan, and auto-refresh |
| **Cameras** → Timeline | Scheduled snapshot capture (default 10:30 AM + 7:00 PM daily); browse per-camera thumbnail strips, launch a slideshow, or view any image in the lightbox |
| **Log** | Scrollable activity log of all automation runs and network changes |
| **Settings** | Configure your UniFi host URL, API key, site, and port — persisted across restarts |

---

## Quick Start (Docker)

```bash
# 1. Copy the compose file onto your NAS / server
curl -O https://raw.githubusercontent.com/niski84/unifi-smash-deck/main/docker-compose.yml

# 2. Start it
docker compose up -d

# 3. Open the UI
open http://<your-server-ip>:8099
```

Then go to the **Settings** tab and enter your:
- **UniFi Host** — e.g. `https://192.168.0.1`
- **API Key** — created in UniFi OS under *Settings → Control Plane → Integrations*
- **Site** — usually `default`

### Updating

Settings and automations are stored in a named Docker volume (`unifideck-data`) and survive upgrades:

```bash
docker compose pull && docker compose up -d
```

> **Warning:** `docker compose down -v` deletes the volume and all your data.  
> Use plain `docker compose down` when stopping or redeploying.

---

## Building from Source

Requires Go 1.22+.

```bash
git clone https://github.com/niski84/unifi-smash-deck.git
cd unifi-smash-deck

# Run locally (serves on :8099)
go run ./cmd/unifideck

# Or use the reload helper
./scripts/reload.sh
```

Configuration is read from the Settings UI or from environment variables / `.env`:

```bash
cp .env.example .env
# Edit .env if you want env-var overrides; otherwise leave it as-is and use the UI
```

---

## Building the Docker Image

```bash
# Local build (current platform)
./scripts/docker-build.sh

# Multi-platform (amd64 + arm64) and push to GHCR
./scripts/docker-build.sh --push
```

The included GitHub Actions workflow (`.github/workflows/build.yml`) builds and pushes a multi-arch image to `ghcr.io/niski84/unifi-smash-deck` on every push to `main` and on version tags (`v*.*.*`).

---

## Deploying to a NAS via SSH

```bash
NAS_HOST=192.168.0.x NAS_USER=admin NAS_DEPLOY_DIR=/volume1/docker/unifideck \
  ./scripts/deploy-nas.sh
```

---

## Architecture

```
cmd/unifideck/main.go          ← entry point, signal handling
internal/unifideck/
  config.go                    ← AppConfig, load/save settings
  unifi_client.go              ← HTTP client for UniFi Network + Protect APIs
  automation.go                ← automation types, scheduler, store, logger
  snapshot_store.go            ← scheduled snapshot capture, storage, index
  http_server.go               ← route wiring, thin handlers
web/
  embed.go                     ← //go:embed — static assets baked into binary
  unifideck/index.html         ← single-page UI (vanilla JS, no build step)
```

- **Backend:** Go stdlib only (`net/http`, `encoding/json`) — no web framework.
- **Frontend:** Vanilla JS + `fetch` — no bundler, no npm.
- **Persistence:** JSON files in `./data/` (or `$DATA_DIR`).
- **Auth:** UniFi local API key via `X-API-KEY` header — no session cookies.

---

## UniFi API Key

Create the key in your UDM Pro under:

> **UniFi OS → Settings → Control Plane → Integrations → Add API Key**

The same key works for both the Network API (VLANs/automations) and the Protect API (cameras/snapshots).

---

## Data Backup

All persistent data lives in the `unifideck-data` Docker volume:

```bash
# Backup
docker run --rm \
  -v unifideck-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/unifideck-backup.tar.gz -C /data .

# Restore
docker run --rm \
  -v unifideck-data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/unifideck-backup.tar.gz -C /data
```

---

## License

MIT
