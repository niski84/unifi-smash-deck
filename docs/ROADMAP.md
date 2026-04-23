# UniFi Smash Deck — Product Roadmap

_Last updated: 2026-04-23_

---

## What This App Is (and Is Not)

The UniFi dashboard tells you what is happening **right now at one site**. Smash Deck tells you **what will happen next across every site** — and what to do about it.

This is a read-only API companion for managing a fleet of 700+ UniFi sites. It does not replace the native controller; it fills the gaps the controller was never designed to fill: cross-site aggregation, historical trending, proactive anomaly detection, and actionable remediation guidance that survives a page refresh.

---

## Architecture Decision: Background Polling + SQLite Cache

**Short answer: background goroutines, SQLite, 15-minute poll cadence.**

Fetching data on-demand from 700 sites on every page load would be unusable (30–120 second waits, high API rate-limit risk). The right model, already proven with the UISP companion app, is:

```
  Background goroutine pool (N=20 concurrent)
      │
      ├── Poll each site every 15 min via UniFi API
      ├── Write snapshots to SQLite (device_snapshots, usage_daily, etc.)
      └── Expire rows older than 30–90 days

  HTTP handlers (instant)
      │
      └── Read from SQLite, return pre-aggregated JSON to the UI
```

**Why SQLite over PostgreSQL:**
- Zero ops — ships inside the container, no external dependency
- Sufficient for a single-writer / many-reader workload at this scale
- WAL mode handles concurrent reads without blocking writes
- Upgrade path to Postgres is a thin driver swap if the operator count ever scales

**Site concurrency model:**
- Semaphore-gated goroutine pool (20 concurrent) prevents hammering any single controller
- Each site gets a 30-second timeout; failures are logged and skipped without stalling the pool
- Cache TTL is per-report-type: real-time health data is 5 min, historical aggregates are pre-computed at poll time

---

## What Is Already Built

| Feature | Status |
|---|---|
| Single-site dashboard (devices, clients, SSIDs) | ✅ Live |
| Real-time SSE stream for live updates | ✅ Live |
| Security event feed + threat polling | ✅ Live |
| Network health checks + one-click fixes | ✅ Live |
| IoT WLAN diagnostics + remediation | ✅ Live |
| Firewall rule audit | ✅ Live |
| VLAN audit + labeling | ✅ Live |
| Config snapshot history + diff | ✅ Live |
| Switch port visibility | ✅ Live |
| Network insights (topology, client stats) | ✅ Live |
| Camera feed integration | ✅ Live |
| UDM deploy + sysconfig tooling | ✅ Live |
| Multi-site management (site selector) | ✅ Live |

---

## Phase 1 — Cross-Site Polling Infrastructure
_Foundation that everything else depends on. No new UI tabs until this is solid._

### 1.1 — Multi-Site Background Poller
- Extend the existing single-site client to iterate all sites in the site list
- Goroutine pool (semaphore of 20) with per-site 30-second timeout
- Persist raw snapshots to SQLite: `site_snapshots`, `device_snapshots`, `client_snapshots`
- Poll cadence: 15 minutes. Configurable per-site if a site needs more or less aggressive polling
- Poller health visible in the dashboard: last poll time, sites OK / failed / skipped

### 1.2 — Data Retention & Pruning
- `device_snapshots`: keep 90 days (PoE trends, memory leaks require long windows)
- `client_snapshots`: keep 30 days (data heavy hitters, new device detection)
- `usage_daily` rollup table: keep 365 days (YoY comparisons, customer reports)
- Nightly prune job runs at 02:00 local time to keep DB size bounded

### 1.3 — Fleet Overview Tab
- New "Fleet" tab replacing the current single-site focus on the Overview page
- Aggregate counters: total sites, total devices, total clients, sites with active alerts
- Site health grid: each site as a card showing status, client count, and top alert
- Click a site card → drops into that site's existing detailed view

---

## Phase 2 — Configuration Drift & Security Auditing
_UniFi is bad at enforcing a gold standard across hundreds of sites. This is the first genuinely differentiating feature._

### 2.1 — Gold Standard Profile
- Operator-defined "desired state" config stored locally: expected SSID names, security modes, channel width policy, IGMP snooping, fast-roaming setting, STP priority, DNS servers
- UI: simple form in Settings to define and save the profile

### 2.2 — Drift Detection Engine
- On each poll, compare each site's live config against the gold standard
- Score each site 0–100 (100 = fully compliant). Persist score per site per poll
- Flag specific deviations with plain-English descriptions:
  - "Auto-Optimize Network is ON — known to cause IoT client drops on 2.4GHz"
  - "Fast Roaming is ON — can break older clients with slow 802.11r handshake"
  - "WPA2-only mode detected — WPA3 transition mode is available on this hardware"
  - "SSH is enabled with password auth — recommend key-only or disabled"
  - "STP priority is default (32768) — set a deliberate value to prevent topology flaps"

### 2.3 — Drift Report Tab
- Fleet-wide compliance score (average across all sites)
- Sites ranked by compliance score, lowest first
- Per-site expandable: each failing check, severity (warn/critical), and a remediation suggestion
- "What changed" delta: highlight sites whose score dropped since the last poll
- Export to CSV for customer-facing audit reports

---

## Phase 3 — Predictive Capacity & Hardware Lifecycle
_Turn time-series data into an early-warning system._

### 3.1 — PoE Budget Trending
- Poll switch PoE draw per-port from UniFi API, store in `device_snapshots`
- Compute 30/60/90 day trend lines (linear regression over stored samples)
- Flag: switch is projected to exceed PoE budget within N days at current growth rate
- Suggestion: "Core-A is at 92% PoE budget, running 10°C above fleet average temperature. Schedule upgrade before adding additional cameras or APs."

### 3.2 — Memory Leak Detection
- Track per-device RAM utilization over time
- Flag: device RAM has climbed steadily for 14+ days without a restart (correlated with firmware version)
- Suggestion: "U6-Enterprise at Site 42 shows steady memory growth since firmware v6.5.x was applied across 50 sites. Recommend pausing further rollouts and scheduling a rolling restart."

### 3.3 — Hardware Lifecycle Report
- Maintain an EOL/EOS date table for UniFi hardware models (maintained manually or via a YAML file in the repo)
- Generate a "Hardware Replacement Roadmap" per site: which devices reach EOL within 12 months
- Sort fleet-wide by nearest EOL date — becomes a prioritized upgrade list
- Export as a customer-deliverable PDF-ready HTML report

### 3.4 — Capacity Report Tab
- PoE headroom per switch (current vs budget, trend arrow)
- Memory pressure leaderboard: devices with highest sustained RAM %
- Hardware EOL timeline: a visual calendar showing which sites have expiring hardware when
- "At-risk" badge on site cards in the Fleet tab when any capacity alert is active

---

## Phase 4 — Deep RF Health & Environmental Analytics
_UniFi's auto-optimization is a black box. This makes it a glass box._

### 4.1 — DFS Strike Tracking
- Poll AP event logs for DFS radar events, persist with timestamp and channel
- Fleet-wide DFS heatmap: which APs are hit most, which 5GHz channels are most affected in each geographic region
- Suggestion: "Warehouse-West has been forced off its 5GHz channel by radar 12 times this week. Suggestion: Lock to a non-DFS channel (36 or 149)."

### 4.2 — Retry Rate Analytics
- Track per-AP Rx/Tx retry rates from the UniFi stats endpoint over time
- Correlate high retry rates with client type (Apple, Android, IoT) via OUI lookup
- Suggestion: "Apple clients at Site 12 show 15% Tx retry rate. Adjacent APs may have overlapping coverage at excessive power — consider reducing 5GHz transmit power."

### 4.3 — Channel Optimization History
- Record each AP's channel/power configuration at every poll
- Detect when UniFi's auto-optimizer makes a change (before → after diff)
- Track whether client metrics improved or degraded after each auto-change
- Insight: "Auto-optimization changed Warehouse-East from ch 149→153 on 2026-03-14. Client retry rates increased 22% in the 48h after. Consider locking this AP."

### 4.4 — RF Health Tab
- Per-site RF summary: 5GHz channel distribution, DFS strike count (7d), avg retry rate
- Fleet-wide channel conflict heatmap (already partially built in the UISP companion)
- "Problematic APs" list: ranked by retry rate + DFS strikes + unstable channel history

---

## Phase 5 — ISP Performance Aggregation
_The "Blame the ISP" report. Turns scattered per-site WAN data into a provable SLA case._

### 5.1 — WAN Health Polling
- Poll WAN latency, packet loss, and uptime from each site's UDM/gateway at every tick
- Store time-series: `wan_health(site_id, ts, latency_ms, loss_pct, dns_fail_count, uptime_s)`
- Detect micro-drops: any loss > 0% event lasting < 60 seconds (these are invisible in native UI)

### 5.2 — ISP Attribution
- Each site config has an ISP label (configurable: "Comcast Business", "CenturyLink", "Starlink", etc.)
- Group WAN health data by ISP label and geographic region
- Correlation engine: "Are sites sharing the same ISP in the same zip code having simultaneous drops?"

### 5.3 — ISP Performance Report Tab
- Per-ISP monthly SLA summary: uptime %, avg latency, micro-drop count, peak drop window
- Side-by-side comparison: Provider X vs Provider Y at sites where both exist
- "Incident timeline" view: a scrollable log of every drop event, which sites were affected, duration
- Export: monthly PDF-ready report formatted for presenting to an ISP or a customer

### 5.4 — Smart Alerts
- Trigger an in-app alert (SSE toast) when 3+ sites on the same ISP drop within a 5-minute window
- This is a "regional ISP outage" signal — fire before your customer calls you

---

## Phase 6 — Fleet-Wide Firmware Management
_700 devices, 12 firmware versions, and a memory leak in one of them — this is a management problem, not a technology problem._

### 6.1 — Firmware Inventory
- Build on the existing single-site firmware view
- Fleet-wide table: every device, current firmware, latest available, upgrade eligibility
- Group by firmware version: "How many U6-Enterprise are on v6.5.x?"

### 6.2 — Firmware Correlation Engine
- Cross-reference firmware version with device health metrics (RAM %, crash count, uptime resets)
- Flag: "Devices on firmware X are showing statistically higher RAM usage than devices on firmware Y"
- This turns a suspected firmware bug into a provable, fleet-wide data point

### 6.3 — Safe Rollout Planner
- Operator marks a firmware version as "staged" — target N% of sites as a canary
- App tracks which sites are on the canary version and monitors their health for a configurable window (e.g., 7 days)
- Health gate: if canary sites show degraded metrics, the app surfaces a "PAUSE ROLLOUT" warning
- When the canary window passes cleanly, the app marks the firmware as "safe for fleet" and shows which sites still need updating

### 6.4 — Firmware Tab
- Fleet firmware distribution pie/bar chart
- "Upgrade candidates" table filtered by safe-to-upgrade status
- Canary deployment tracker with health gate status
- One-click "schedule upgrade" that queues upgrades via the UniFi API (respecting maintenance windows configured per site)

---

## Phase 7 — Data Heavy Hitters & Usage Intelligence
_Customer-facing insight: who is consuming what, for how long, and what it means._

### 7.1 — Client Usage Trending
- Extend existing client snapshot storage to include per-client `tx_bytes` / `rx_bytes` deltas per poll
- Roll up into `usage_daily(client_mac, site_id, day, dl_gb, ul_gb)`
- Retain 90 days

### 7.2 — Heavy Hitters Report
- Fleet-wide top consumers: ranked by 30-day download GB
- Filterable by site, VLAN, and device type (wired vs wireless)
- Flag: "Client 00:1A:2B:... at Site 42 downloaded 1.2TB in the last 30 days — 8× the site average"
- Cross-reference with the DHCP hostname and OUI to label device type automatically

### 7.3 — Capacity Saturation Alerts
- Alert when a site's total client throughput exceeds a configurable % of WAN capacity for more than N minutes
- "Site 42 WAN (100Mbps) is at 94% sustained utilization for 22 minutes. Top consumer: AppleTV (00:1A:2B)"

---

## UX Principles to Maintain Across All Phases

These patterns are already established and must be consistent in every new tab:

1. **Tab description block** at the top of every tab — plain English explanation of what is being shown and what the flagging criteria is. No jargon without a definition.
2. **Summary cards row** — 3–5 at-a-glance metrics before any tables or detail views
3. **Collapsible group sections** for site-grouped data — don't dump 700 rows into a flat table
4. **Actionable suggestion text** on every flagged item — not just "problem detected" but "here is what to do about it and why"
5. **↗ Deep link** into the UniFi controller on every device row — this app is read-only; make it trivial to act
6. **📉 History button** on every device with polled historical data
7. **↻ Refresh button** with timestamp on every tab — lazy load on first visit, manual refresh available
8. **Dark theme by default**, exact color palette: `--bg:#0b0f1a`, `--card:#131929`, `--border:#1e2d4a`, `--accent:#006FFF`, `--text:#e8edf8`, `--muted:#8a9cbd`, `--ok:#3ddba5`, `--warn:#f5a623`, `--err:#ff6b6b`
9. **Export** on any report that a customer might want to see — CSV minimum, HTML/PDF for lifecycle and ISP reports

---

## Tab Sequence (Final Navigation Order)

```
Overview (fleet summary)
├── Sites (grid of all sites, health scores)
├── Config Drift (compliance scores, deviations)
├── RF Health (DFS, retries, channel history)
├── Capacity (PoE, RAM, EOL hardware)
├── Firmware (inventory, rollout tracker)
├── ISP Performance (WAN health by provider)
├── Heavy Hitters (data usage by client)
├── Disconnected
├── Security (existing threat feed)
└── Settings
```

---

## Open Questions / Decisions to Make

| Question | Current thinking |
|---|---|
| SQLite vs Postgres | SQLite + WAL for now. Postgres if the operator count scales to multiple servers. |
| Where does the poller run? | Same process as the HTTP server, goroutine pool. No external scheduler. |
| How do we handle 700-site auth? | Per-site API key stored in SQLite `sites` table, encrypted at rest. |
| Alert delivery (beyond in-app toast)? | Phase 2+: webhook → Slack / PagerDuty. Config in Settings. |
| Customer-facing reports | Phase 3+: server-side rendered HTML → print-to-PDF via browser. No headless chrome. |
| Rate limit handling | Exponential backoff per site. Sites that return 429 get a 60-min cool-down before retry. |
