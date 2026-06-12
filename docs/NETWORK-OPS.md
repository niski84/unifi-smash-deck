# GusNet — Network Ops Log

_Running log of changes, incidents, and pending actions on the UDM Pro home network._

---

## Pending Actions

### Hardware

- [ ] **Garage camera (192.168.30.163) — offline**
  Attic Switch port 6. Camera goes offline at sunset when exterior LEDs turn on, comes back in the morning. Root cause: old Cat5 cable from attic to garage is marginal for PoE under load. Two options:
  1. Try a PoE port power-cycle first: Protect → Devices → Attic Switch → port 6 → Cycle Power
  2. If it keeps dropping: replace the Cat5 run with Cat6

- [ ] **Buy dedicated IDS box (Option 2)**
  When ready to move off the UDM Pro, grab an Intel N100 mini PC (~$150, e.g. Beelink EQ12 or Trigkey S5).
  Run Suricata + Zeek on it. Configure a port mirror on the UDM Pro to send WAN-side traffic to it passively — zero inline latency, no impact on the UDM Pro.

### UniFi UI (must do in browser — not API-accessible)

- [ ] **Create local admin account**
  Settings → Admins & Users → "+" → set username `nick` → toggle **Remote Access OFF** → role: Administrator.
  This gives you a local-only account that works even if Ubiquiti cloud is down.

- [ ] **Disable Face ID and LPR for legacy cameras on AI Key**
  Protect → System → Intelligence → uncheck Face ID and License Plate Recognition policies for the legacy cameras. Frees up AI Key compute.

### When Re-enabling IPS (future)

- [ ] **Re-enable IPS with Suricata v8**
  IPS is currently off. When you want to turn it back on (ideally after the dedicated IDS box is set up as primary, with UDM Pro as backup), edit the state file or toggle via the UI. It will start Suricata 8.0.2 since the upgrade was pre-applied.

---

## Session Log

### 2026-05-26 — IPS Disabled, Suricata v8 Staged

**Root cause discovered and fixed:** All devices had been stuck at `satisfaction: -1` since May 22. The inform-processing loop in the UniFi Network Java app was crashing every 10–30 seconds (414 exceptions total in `server.log`) due to a firewall policy document in MongoDB with `connection_state_type: "NEW"` — not a valid enum. Fixed via:

```javascript
// MongoDB: ace database
db.firewall_policy.updateOne(
  {_id: ObjectId("69d19658ba19c5447a8c922d")},
  {$set: {connection_state_type: "ALL", connection_states: []}}
);
```

**IPS disabled:** UDM Pro (4GB RAM) couldn't run Suricata v6 reliably — the upgrade check used `MemFree` not `MemAvailable`, so a cache-full system always failed the ~824MB threshold. Suricata RSS was ~368MB. Disabled by:
1. Setting `ips_mode: "disabled"` in `ace.setting` (MongoDB)
2. Setting `services.idsIps.enabled: false` in `/data/udapi-config/ubios-udapi-server/ubios-udapi-server.state`
3. Restarting `ubios-udapi-server` to apply cleanly

Memory recovered: 2.5Gi used → 2.0Gi used, ~1.0Gi free (was ~74Mi free).

**Suricata v8 staged:** The v8 binary (8.0.2) was already fully downloaded to `/usr/share/ubios-udapi-server/ips_8/`. Marked the upgrade complete:
- `/usr/share/ubios-udapi-server/ips/version.json` → `upgrade_suricata_status: success`, `current_version: 8`
- State file `suricataVersion` → `8`

If IPS is re-enabled, it will start v8 instead of v6.

**Attic Switch PoE "out of power" messages:** Were not real — they were a symptom of the inform exception bug above. Actual draw is ~87W of the 210W budget. Eight cameras on the switch (VLAN 30, 192.168.30.x).

**Garage camera confirmed offline at network layer:** ARP fails, 100% packet loss to 192.168.30.163. Physical issue (old Cat5 + PoE under load), not a controller bug.

**UniFi config backup repo created:** `github.com/niski84/unifi-backups` (private).
Script: `/home/nick/goprojects/unifi-backups/scripts/backup.sh`
Pulls: `.unf` autobackups, core YAML configs, smash-deck snapshots → commits and pushes.

---

### 2026-04 — Disk Space Incident

See `INCIDENT-DISK-SPACE-2026-04.md` in project root.
