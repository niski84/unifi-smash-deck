# Incident Report: Disk Space Exhaustion — Camera Snapshots
**Date:** 2026-04-28
**Severity:** High — 8.1 GB consumed by unbounded camera snapshot accumulation
**Status:** Identified; remediation plan below

---

## Summary

The `data/snapshots/` directory grew to **8.1 GB / 55,547 files** over 30 days. A 5-minute interval snapshot rule was enabled across all 9 cameras with no effective disk-space guard. One camera (Driveway) produces ~992 KB JPEG frames — roughly 20× larger than the others — and alone accounts for **6.8 GB (83%)** of the total.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-03-30 15:59 | First snapshot captured — `snapshots-schedule.json` active |
| 2026-03-30 → 2026-04-29 | Continuous 5-minute polling across all 9 cameras, 24/7 |
| 2026-04-28 | User notices disk exhaustion; 55,547 files / 8.1 GB present |

---

## Root Cause Analysis

### Primary: 5-minute interval rule applied to all cameras 24/7

`data/snapshots-schedule.json` contained:

```json
{
  "rules": [
    { "id": "r1", "enabled": true, "label": "Every 10 min",
      "mode": "interval", "interval_min": 5, "camera_ids": [] }
  ],
  "retain_days": 30
}
```

`camera_ids: []` means **all connected cameras**. At 5-minute intervals, 9 cameras, 24 hours/day:

```
9 cameras × (60 ÷ 5) per hour × 24 h × 30 days ≈ 77,760 expected captures
```

Actual: 55,543 (some cameras missed captures due to 429 rate-limiting or brief disconnects).

### Secondary: One camera produces 20× larger frames

The **Driveway** camera (id `6997ddbc`) captures at roughly 992 KB per JPEG — a high-resolution wide-angle lens with more scene content. The other 8 cameras average 25–40 KB each.

| Camera | Files | Total | Avg/file |
|--------|-------|-------|----------|
| Driveway | 6,983 | **6,768 MB** | 992 KB |
| Garage | 6,984 | 266 MB | 39 KB |
| BackYard 1 | 6,984 | 209 MB | 31 KB |
| BackYard2 | 6,983 | 195 MB | 29 KB |
| Side Yard | 6,985 | 185 MB | 27 KB |
| Side Yard Van | 6,986 | 174 MB | 26 KB |
| backdoor | 7,166 | 148 MB | 21 KB |
| G4 Instant | 6,380 | 148 MB | 24 KB |
| General IPC-K42A | 92 | 20 MB | 219 KB |
| **Total** | **55,543** | **8,113 MB** | — |

Driveway alone would produce **≈8.2 GB** at this cadence for 30 days.

### Contributing: `PruneOld()` is call-time-only, not scheduled independently

`PruneOld()` runs at the start of each `captureForRule()` invocation — meaning it only prunes when a capture fires. It never runs as a standalone background job. If captures were ever paused (service restart, disabling rules), no pruning would occur. More importantly, files are pruned based on `retain_days` but there is **no total-size cap**, so a large camera can still fill a disk within the retention window.

With `retain_days: 30` and a 30-day accumulation span, the pruning was working correctly by age, but **the steady-state size at 5-min intervals is itself 8+ GB** — far larger than likely intended.

---

## What Was Working Correctly

- The 30-day age retention policy pruned nothing because all files are within the 30-day window (first file: 2026-03-30, today: 2026-04-28).
- Rate-limiting backoff (429 retries) and the 1.5-second stagger between cameras were functioning, preventing UniFi Protect overload.
- The index file (`index.json`) is consistent with the filesystem.

---

## Remediation

### Immediate: Delete excess snapshots

The safest approach is to keep only the last N days of snapshots. All files are within the 30-day window, so a tighter retention is needed now.

```bash
# Preview: count files older than 7 days
find /home/nick/goprojects/unifi-smash-deck/data/snapshots -name "*.jpg" \
  -not -newer $(date -d '7 days ago' +%Y-%m-%d) | wc -l

# Delete files older than 7 days (frees ~5-6 GB)
find /home/nick/goprojects/unifi-smash-deck/data/snapshots -name "*.jpg" \
  -not -newer $(date -d '7 days ago' +%Y-%m-%d) -delete
```

Then rebuild the index via the API (`POST /api/snapshots/reindex` if available) or restart the service so `loadIndex()` picks up the current files.

### Fix 1: Reduce the capture interval

Change `interval_min` from 5 to something sensible for the use case.
Example — 30 minutes instead of 5 gives a 6× reduction:

```json
{ "id": "r1", "enabled": true, "label": "Every 30 min",
  "mode": "interval", "interval_min": 30, "camera_ids": [] }
```

Steady-state at 30 min, 9 cameras, 30 days = ~13,000 files. At 153 KB average: ~1.9 GB. Manageable.

### Fix 2: Exclude the Driveway camera from interval polling

The Driveway camera at 992 KB/frame produces 80× more data per capture than a small camera. Either exclude it from the interval rule, or resize its snapshots at write time.

```json
{ "camera_ids": ["<id-of-all-cameras-except-driveway>"] }
```

Or add a dedicated lower-frequency rule for the Driveway camera.

### Fix 3: Add a total-size cap to `PruneOld()`

In `snapshot_store.go`, after age-based pruning, enforce a maximum directory size:

```go
const maxSnapshotBytes = 2 * 1024 * 1024 * 1024 // 2 GB hard cap
```

Walk the index oldest-first and delete until under the cap. This protects against future misconfiguration.

### Fix 4: Add a background pruning goroutine

`PruneOld()` should run on a timer (e.g., every hour) independent of captures, so retention is enforced even when capture rules are paused or changed.

---

## Steady-State Projections

| Interval | 9 cameras | 30-day size (avg 153 KB) | Driveway only (992 KB) |
|----------|-----------|--------------------------|------------------------|
| 5 min (current) | 77,760 files | **11.2 GB** | **8.2 GB** |
| 15 min | 25,920 files | 3.7 GB | 2.7 GB |
| 30 min | 12,960 files | 1.9 GB | 1.4 GB |
| 60 min | 6,480 files | 940 MB | 680 MB |
| Times only (2×/day) | 540 files | 78 MB | 57 MB |

---

## Action Items

- [ ] Delete snapshots older than 7 days to immediately recover ~5-6 GB
- [ ] Change `interval_min` from 5 → 30 (or times-only) in `snapshots-schedule.json`
- [ ] Exclude Driveway camera from high-frequency rule, or add per-camera size cap
- [ ] Add total-size cap guard to `SnapshotStore.PruneOld()`
- [ ] Add hourly background pruning goroutine independent of capture schedule
