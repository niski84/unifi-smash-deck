# UniFi Smash Deck

A self-hosted web dashboard for managing and monitoring UniFi gear (UDM Pro and other UniFi OS devices).

Part of the [Smash Deck](https://github.com/niski84/smash-deck-catalog) family - self-hosted dashboards built in Go for the homelab.

## What It Does

Talks to the UniFi controller API to surface networks, clients, and Protect cameras in a single dashboard. You can list VLANs and toggle them on or off with one click, browse connected clients with sortable columns and search, and watch an auto-refreshing snapshot grid for any UniFi Protect cameras on the system.

It also includes a scheduler for VLAN automations (enable or disable a network on a recurring time, day-of-week, and timezone basis) and a camera timeline that captures snapshots on an interval or at fixed daily times so you can scrub back through the day.

The whole thing is one Go binary with the UI embedded. State and settings live in a local JSON file under `data/`.

## Tech Stack

- Go (single binary, no runtime dependencies)
- Embedded vanilla HTML, CSS, and JavaScript (no framework)
- Docker / Compose support included

## Running

```bash
go build -o unifideck ./cmd/unifideck
./unifideck
```

Configure via environment variables (see `.env.example`) or fill in UniFi host, API key, and site through the Settings tab in the UI. Default port is 8099.

## Status

Active development.

## License

MIT
