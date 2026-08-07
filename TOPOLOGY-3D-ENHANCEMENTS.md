# 3D Topology — Enhancement Plan

Live network viz at `unifi-smash-deck:8214/topology-3d.html`. Current state: SSE-streamed,
persistent scene with interpolated rates, real per-link bandwidth (switch-port `rx_bytes-r`),
cameras as real nodes, packet balls **sized by bandwidth**, and an IoT→external red-ring overlay
fed by `/api/flows` (UDM conntrack over SSH).

Four enhancements, ordered by value × build-confidence:

## Phase 1 — Suricata IPS overlay (the *real* "suspicious")  ★ do first
**Why:** the current red ring is a port heuristic. Suricata is the UDM's actual IDS — when it
fires, that's a confirmed signal, not a guess. This is the gold-standard security view.
**Data:** `/var/log/suricata/eve.json` on the UDM (SSH, same pattern as `/api/flows`). Filter
`event_type=="alert"` → `{src_ip, dest_ip, signature, severity, timestamp}`.
**Backend:** `GET /api/ips` — SSH `tail -n 2000 eve.json`, parse alerts, return recent ones.
**Frontend:** correlate `src_ip`/`dest_ip` → node; flash that node a hard red + show the
signature in the panel + HUD count. Distinct from the heuristic ring (this = "IDS fired").
**Risk:** low — mirrors the proven conntrack endpoint. Verify eve.json is populated first.

## Phase 2 — Exfil packets stream off-network  ★ visual, frontend-only
**Why:** make a suspicious/IPS node literally *shoot a red packet toward the internet* so
exfiltration is visceral.
**How:** add a synthetic "INTERNET" anchor above the WAN node. For each flagged node, spawn
red balls from the node → that anchor (reuse the particle engine with a special link).
**Risk:** low — pure frontend, builds on the existing pool.

## Phase 3 — Click a trunk → top flows through it
**Why:** inspect what's actually riding a hot pipe.
**How:** make link lines pickable (raycast against Line2, or invisible fat cylinders for hit-
testing). On click, show the top flows whose path crosses that link — for a switch uplink, the
flows of all devices in its subtree (correlate `/api/flows` src IPs to the subtree).
**Risk:** medium — link picking + subtree correlation.

## Phase 4 — Color packets by traffic type (DPI)
**Why:** see *what kind* of data flows — video vs cloud-sync vs web vs gaming — in different hues.
**Data:** UniFi DPI per-client app/category. Source TBD: `mca-dump` on the UDM, or the DPI stats
API (`/proxy/network/api/s/default/stat/dpi` / `stat/sta` dpi fields). Verify which exposes
per-client category bytes before building.
**Frontend:** tint each link's balls by its dominant app category; legend of categories.
**Risk:** medium — depends on DPI data shape; needs a feasibility probe first.

---
### Build order
1. Verify suricata eve.json → build Phase 1 (IPS overlay).
2. Phase 2 (exfil packets) — quick visual win on top of Phase 1's flags.
3. Phase 3 (trunk click → flows).
4. Probe DPI feasibility → Phase 4 (packet coloring).
