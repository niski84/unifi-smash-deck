# GusNet — Network Insights & API Capabilities
_Updated 2026-04-07 · UniFi Network 10.2.105 · UDM Pro 5.0.16_

---

## Infrastructure at a Glance

| Device | Model | CPU | Mem | Uptime | Clients |
|--------|-------|-----|-----|--------|---------|
| Wiggerton Router | UDM Pro | 23% | **85%** | 14.7d | 47 |
| Garage AP | U6 Enterprise | 3% | 80% | 28.1d | 9 |
| Main TV Switch | USW Mini | 2% | 80% | 28.1d | 3 |
| Attic Switch | USW-Mission-Critical-8-PoE | 8% | 74% | 43.9d | 6 |
| Server Room AP | U6-Pro | 10% | 66% | 47.3d | **30** |
| **Squirrel Box Switch** | US-8-60W | **58%** | 44% | 28.1d | 0 |
| Server Rack Switch | USW-16-PoE | 12% | 37% | 13.9d | 1 |
| Dining Room AP | U6-IW | 3% | 29% | 28.1d | 0 |

**Total managed clients:** 49

---

## Physical Topology

```
Wiggerton Router (UDM-Pro)
└── Server Rack Switch (USW-16-PoE)  — uplink on port 1
    ├── Port 3  → Server Room AP (U6-Pro)          trunk/default
    ├── Port 5  → unknown 82:48:2c:33:5d:5d        no VLAN assigned ⚠️
    ├── Port 7  → Squirrel Box Switch (US-8-60W)   Zone00 native
    └── Port 11 → unknown device                   Zone00, 10Mbps ⚠️
```

```
Squirrel Box Switch (US-8-60W)  — uplink: Server Rack port 7
├── Port 1  Zone00 (mgmt)  DOWN   Master Bedroom wall port
├── Port 2  Zone00 (mgmt)  DOWN   Front Bedroom wall port
├── Port 3  Media VLAN40   1Gbps  → Attic Switch (USM8P210)
├── Port 4  Zone00 (mgmt)  1Gbps  → Office
├── Port 6  Media VLAN40   1Gbps  → Garage AP (U6-Enterprise)
├── Port 7  Zone00 (trunk) 1Gbps  → Dining Room AP (U6-IW)
└── Port 8  Zone00 (trunk) 1Gbps  → Main TV Switch (USW-Mini)
```

```
Attic Switch (USM8P210)  — uplink: Squirrel Box port 3
├── Port 1  Cameras VLAN30  100Mbps  driveway (192.168.30.248)
├── Port 2  Cameras VLAN30  100Mbps  g5-turret-ultra (192.168.30.131)
├── Port 3  Cameras VLAN30  100Mbps  g5-turret-ultra (192.168.30.240)
├── Port 4  Cameras VLAN30  100Mbps  side-yard (192.168.30.244)
├── Port 5  Cameras VLAN30  100Mbps  side-yard-van (192.168.30.117)
├── Port 6  Cameras VLAN30  100Mbps  garage (192.168.30.163)
└── Port 8  trunk           1Gbps    uplink (PoE In)
```

```
Main TV Switch (USW-Mini)  — uplink: Squirrel Box port 8
├── Port 1  Zone00 (trunk)  1Gbps    uplink
├── Port 2  Media VLAN40    100Mbps  LGwebOSTV (192.168.4.153)
├── Port 3  Media VLAN40    100Mbps  sonyaudio (192.168.4.14)
└── Port 5  Cameras VLAN30  100Mbps  UFP-Viewport-0896 (192.168.30.135)
```

> **Note:** Squirrel Box ports 1 & 2 (bedroom wall ports) are configured Zone00 and currently down — likely need access VLAN overrides if they're ever used.

---

## Findings & Anomalies

### 🔴 UDM Pro Memory at 85–88%

The UDM Pro has 4 GB RAM. It's using ~3.5 GB. This is common but worth understanding:

**What's eating it:**
- **UniFi Network Controller (Java + MongoDB)** — the single biggest consumer; MongoDB alone holds ~1–1.5 GB for event/stat history. The controller is configured to keep 90 days of data retention.
- **UniFi Protect NVR** — caches camera stream metadata, motion events, and thumbnails in RAM for fast access; grows with camera count (you have 6 cameras + the g4-instant and "backdoor" on management VLAN).
- **UniFi OS base** — Linux kernel, routing engine, ZBF firewall conntrack table (tracks all stateful connections across all VLANs), and system daemons.

**What you can do:**
- Reduce `data_retention_days` from 90 to 30 in Network Settings → System → Data Retention. MongoDB will shrink significantly on next cleanup cycle.
- The API doesn't expose process-level `top` output — that requires SSH (`ssh root@192.168.0.1` then `top` or `ps aux | sort -k4 -rn`). The UDM Pro runs UniFi OS which is a container host; each application (Network, Protect) runs in its own podman container.
- **API call to monitor:** `GET /api/status` returns cloud connectivity + device state; `stat/device` gives the sys_stats (loadavg + mem) shown above.

### 🟠 Squirrel Box Switch CPU at 58%

The US-8-60W (Squirrel Box Switch) is running at 58% CPU — unusually high for a switch with 0 wireless clients. Possible causes:
- This switch had a **VLAN trunk misconfiguration** (Cameras VLAN was in `excluded_networkconf_ids`) that was fixed during the camera outage incident. High CPU may be a residual effect of that or ongoing STP/RSTP recalculation.
- PoE negotiation storms — if a PoE device is cycling (connecting/disconnecting), the switch renegotiates power repeatedly.
- Spanning Tree recalculation — check if port 3 (Attic Switch uplink) is flapping.

**What to check:** SSH to the switch or pull port error counters via `stat/device-ports` API.

### 🟠 Server Room AP Overloaded (30 clients)

The U6-Pro in the server room is carrying 30 clients. Recommended max per AP is 20–25 for good throughput. With 30 clients:
- Airtime contention is high — each client gets ~3% of airtime in the worst case.
- 5 GHz band steering may be failing, pushing clients to 2.4 GHz.

**Recommendation:** Add a second AP to the server room area or redistribute clients by adjusting AP TX power to shrink coverage cells.

### 🟡 Top Traffic Talker — Nebulord-7D50

`Nebulord-7D50` on Media VLAN (VLAN 40, 192.168.4.106) transmitted **19 GB in under 1 day**. This is likely a streaming/media server (Plex, Jellyfin, etc.) — 19 GB out suggests it's serving content to other devices on the network or streaming to the internet. This is expected if intentional, but worth monitoring.

**Via API:** `stat/sta` gives per-client tx/rx bytes since last association. Cross-reference with uptime to get rate.

### 🟡 Two Unidentified Devices on IoT VLAN

Two devices on VLAN 2 (IoT) have no hostnames:
- `192.168.2.184` — connected 13.8 days
- `192.168.2.223` — connected 13.3 days

These could be Wyze devices that don't advertise hostnames, or could be unknown devices. Worth auditing DHCP leases or checking MAC vendor prefixes.

**Via API:** `GET /proxy/network/api/s/default/stat/sta` — check `mac` field and look up OUI at api.macvendors.com.

### ✅ Protect Cameras — Now Correctly on Cameras VLAN

`g4-instant` (192.168.30.229), `backdoor` (192.168.30.249), and `UFP-Viewport-0896` (192.168.30.135) are all now on Cameras VLAN 30. The "Block Cameras→Internal" rule applies to all of them. Previously `g4-instant` and `backdoor` were on Zone00.

### 🟢 IoT Isolation — Good

22 Wyze devices (cameras, bulbs, chimes) are all on VLAN 2 (IoT). The "Block IoT to Zone00" rule is now enabled. The Wyze outbound rule permits cloud connectivity. This is a solid IoT segmentation posture.

---

## VLAN Population

| VLAN | Network | Clients | Notes |
|------|---------|---------|-------|
| — | Zone00 (management) | 0 wired | g4-instant + backdoor + viewport migrated to VLAN30 ✅ |
| 2 | IoT | ~17 | All Wyze devices via Server Room AP — good isolation |
| 10 | Work | 1 | Nicholas-s-S22 |
| 30 | Cameras | 9 | driveway, g5-turret-ultra ×2, side-yard, side-yard-van, garage (wired) + g4-instant, backdoor (WiFi) + UFP-Viewport-0896 |
| 40 | Media | ~18 | LG TV, Sony audio, Nebulord-7D50, phones, tablets, Wyze media |

---

## What Else We Can Do With API Access

### Programmatic Monitoring (build into Smash Deck)
| Idea | API | Value |
|------|-----|-------|
| **Memory pressure alerts** | `stat/device` → `sys_stats.mem_used/mem_total` | Alert when UDM Pro >85% or AP >90% |
| **CPU spike detection** | `system-stats.cpu` | Flag switches >30% or routers >50% |
| **Top talker dashboard** | `stat/sta` → sort by tx_bytes | Spot bandwidth hogs in real time |
| **Unknown device alerts** | `stat/sta` → no hostname + new MAC | Flag new devices on sensitive VLANs |
| **Client VLAN drift** | `stat/sta` → `vlan` field | Alert if a device appears on wrong VLAN |
| **AP client count** | `stat/device` → `num_sta` | Overloaded AP alerting |
| **Firewall audit** | `/v2/api/site/default/firewall-policies` | Already built — the FW Audit tab |
| **WAN health** | `stat/health` | Latency, packet loss, ISP failover events |
| **Port error counters** | `stat/device` → `port_table[].rx_errors` | Find bad cables / flapping ports |

### Automations Possible via API
| Automation | How |
|-----------|-----|
| **Isolate a device** | PUT to `wlanconf` to enable `l2_isolation` for a specific client group |
| **Block a client** | POST to `cmd/stamgr` with `cmd: block-sta` + MAC |
| **Firewall rule toggle** | PUT to `/v2/api/site/default/firewall-policies/{id}` with `enabled: true/false` |
| **Reorder rules** | PUT to `/v2/api/site/default/firewall-policies/batch-reorder` |
| **VLAN reassignment** | PUT to `rest/networkconf/{id}` |
| **Force client reconnect** | POST to `cmd/stamgr` with `cmd: kick-sta` |
| **AP radio restart** | POST to `cmd/devmgr` with `cmd: restart` |
| **Snapshot on demand** | GET `/proxy/protect/api/cameras/{id}/snapshot` |

### Process-Level UDM Pro Insight (requires SSH)
The UniFi API doesn't expose OS process data. To see what's using memory:
```bash
ssh root@192.168.1.201
# Show top memory consumers
ps aux --sort=-%mem | head -20
# Show container memory breakdown
podman stats --no-stream
# MongoDB memory
cat /proc/$(pgrep mongod)/status | grep VmRSS
```
The UDM Pro runs Network and Protect as podman containers. `podman stats` is the cleanest way to attribute memory to each application.

---

## Security Posture — Post-Audit Status

| Item | Status |
|------|--------|
| Harmful IoT→Trusted return-traffic rule | ✅ Deleted |
| Duplicate Trusted→IoT rule | ✅ Deleted |
| Drop-SiloX-to-Node7 (was disabled) | ✅ Re-enabled |
| Block IoT to Zone00 (was disabled) | ✅ Re-enabled |
| Cameras VLAN — no outbound rules | ✅ Block Cameras→Internal added |
| GusNet-Terminal AP client isolation | ✅ Already enabled (l2_isolation=true) |
| Default allow-all between VLANs | ⚠️ Still block-list model — default-deny conversion pending |
| Legacy "block work" rule | ⚠️ Needs manual deletion via UI |
| g4-instant + backdoor on Zone00 | ✅ Now on Cameras VLAN 30 |
| Squirrel Box Switch high CPU | ⚠️ Investigate port flapping / STP |

---

## API Reference for GusNet

All calls use `X-API-KEY: <key>` header to `https://192.168.0.1`.

```bash
# Device health
GET /proxy/network/api/s/default/stat/device

# All connected clients
GET /proxy/network/api/s/default/stat/sta

# Firewall policies (ZBF v2)
GET /proxy/network/v2/api/site/default/firewall-policies

# Networks
GET /proxy/network/api/s/default/rest/networkconf

# SSIDs
GET /proxy/network/api/s/default/rest/wlanconf

# Controller info + data retention settings
GET /proxy/network/api/s/default/stat/sysinfo

# Camera snapshots (Protect)
GET /proxy/protect/api/cameras/{id}/snapshot?quality=high

# UDM OS status
GET /api/status
```
