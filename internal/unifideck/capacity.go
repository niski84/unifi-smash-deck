package unifideck

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

// PoEReport summarises PoE utilisation for all switches on a site.
type PoEReport struct {
	SiteID   string      `json:"site_id"`
	SiteName string      `json:"site_name"`
	Switches []SwitchPoE `json:"switches"`
}

// SwitchPoE holds PoE draw/budget data for one switch.
type SwitchPoE struct {
	DeviceID   string  `json:"device_id"`
	Name       string  `json:"name"`
	DrawW      float64 `json:"draw_w"`
	BudgetW    float64 `json:"budget_w"`
	PctUsed    float64 `json:"pct_used"`
	AtRisk     bool    `json:"at_risk"` // >85% used
	Suggestion string  `json:"suggestion,omitempty"`
}

// MemoryReport summarises RAM pressure for all devices on a site.
type MemoryReport struct {
	SiteID   string      `json:"site_id"`
	SiteName string      `json:"site_name"`
	Devices  []DeviceRAM `json:"devices"`
}

// DeviceRAM holds RAM utilisation data for one device.
type DeviceRAM struct {
	DeviceID   string  `json:"device_id"`
	Name       string  `json:"name"`
	Model      string  `json:"model"`
	RAMPct     float64 `json:"ram_pct"`
	Trending   string  `json:"trending"` // "stable" | "rising" | "unknown"
	AtRisk     bool    `json:"at_risk"`  // >85% RAM
	Suggestion string  `json:"suggestion,omitempty"`
}

// EOLDevice represents a device that matches a known end-of-life model.
type EOLDevice struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	Model      string `json:"model"`
	SiteID     string `json:"site_id"`
	SiteName   string `json:"site_name"`
	EOLDate    string `json:"eol_date"`    // "YYYY-MM"
	MonthsLeft int    `json:"months_left"` // negative = already EOL
	Urgent     bool   `json:"urgent"`      // < 6 months
}

// CapacitySummary holds fleet-wide capacity metrics from the last 24 hours.
type CapacitySummary struct {
	SwitchesAtRisk int     `json:"switches_at_risk"`
	DevicesHighRAM int     `json:"devices_high_ram"`
	AvgPoePct      float64 `json:"avg_poe_pct"`
}

// ─────────────────────────────────────────────────────────────────────────────
// EOL data (model → "YYYY-MM")
// ─────────────────────────────────────────────────────────────────────────────

var eolDates = map[string]string{
	"UAP-AC-LITE": "2025-12",
	"UAP-AC-LR":   "2025-12",
	"UAP-AC-PRO":  "2026-06",
	"US-8":        "2025-09",
	"US-8-60W":    "2025-09",
	"US-24":       "2026-03",
	"US-48":       "2026-03",
	"UDM":         "2026-12",
}

// EOLList returns the full EOL map as a slice, sorted by date for convenience.
func EOLList() map[string]string {
	out := make(map[string]string, len(eolDates))
	for k, v := range eolDates {
		out[k] = v
	}
	return out
}

// monthsUntilEOL parses a "YYYY-MM" date string and returns months remaining
// from today. Negative values mean the EOL date is already past.
func monthsUntilEOL(eolDate string) int {
	parts := strings.SplitN(eolDate, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	year, err1 := strconv.Atoi(parts[0])
	month, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0
	}
	now := time.Now()
	// First day of EOL month.
	eol := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	diff := eol.Sub(now)
	// Convert duration to whole months (approximate).
	months := int(diff.Hours() / (24 * 30.44))
	return months
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeCapacity: live fetch + analysis
// ─────────────────────────────────────────────────────────────────────────────

// AnalyzeCapacity fetches current device data for a site and returns PoE + RAM
// reports using the same HTTP pattern as fleet_poller.go.
func AnalyzeCapacity(ctx context.Context, site SiteConnection) (*PoEReport, *MemoryReport, error) {
	siteName := siteNameOrDefault(site)

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device",
		strings.TrimRight(site.Host, "/"),
		siteName)

	rawBody, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch devices: %w", err)
	}

	var respData struct {
		Data []capacityDevice `json:"data"`
	}
	if err := json.Unmarshal(rawBody, &respData); err != nil {
		return nil, nil, fmt.Errorf("decode device list: %w", err)
	}

	poeReport := &PoEReport{SiteID: site.ID, SiteName: site.Name}
	memReport := &MemoryReport{SiteID: site.ID, SiteName: site.Name}

	for _, dev := range respData.Data {
		// ── RAM ──────────────────────────────────────────────────────────────
		ramPct := 0.0
		if dev.SysStats.MemTotal > 0 {
			ramPct = (dev.SysStats.MemUsed / dev.SysStats.MemTotal) * 100.0
		}
		devRAM := DeviceRAM{
			DeviceID: dev.ID,
			Name:     dev.Name,
			Model:    dev.Model,
			RAMPct:   ramPct,
			Trending: "unknown",
			AtRisk:   ramPct > 85,
		}
		if devRAM.AtRisk {
			devRAM.Suggestion = fmt.Sprintf(
				"RAM at %.0f%%. Consider rebooting %s or upgrading hardware.", ramPct, dev.Name)
		}
		memReport.Devices = append(memReport.Devices, devRAM)

		// ── PoE (switches only — must have a non-zero budget) ────────────────
		budget := dev.TotalMaxPower
		if budget <= 0 {
			continue
		}
		var draw float64
		for _, port := range dev.PortTable {
			if port.PoeEnable {
				if val, err := strconv.ParseFloat(port.PoePower, 64); err == nil {
					draw += val
				}
			}
		}
		pctUsed := 0.0
		if budget > 0 {
			pctUsed = (draw / budget) * 100.0
		}
		sw := SwitchPoE{
			DeviceID: dev.ID,
			Name:     dev.Name,
			DrawW:    draw,
			BudgetW:  budget,
			PctUsed:  pctUsed,
			AtRisk:   pctUsed > 85,
		}
		if sw.AtRisk {
			sw.Suggestion = fmt.Sprintf(
				"PoE at %.0f%% (%.1fW / %.1fW). Consider redistributing load or adding a PoE injector.", pctUsed, draw, budget)
		}
		poeReport.Switches = append(poeReport.Switches, sw)
	}

	log.Printf("[capacity] site=%s devices=%d switches_with_poe=%d",
		site.Name, len(respData.Data), len(poeReport.Switches))
	return poeReport, memReport, nil
}

// capacityDevice is the raw device shape returned by the stat/device endpoint.
// Mirrors the fields we care about (same as fleetDevice in fleet_poller.go).
type capacityDevice struct {
	ID            string  `json:"_id"`
	Name          string  `json:"name"`
	Model         string  `json:"model"`
	Type          string  `json:"type"`
	TotalMaxPower float64 `json:"total_max_power"`
	SysStats      struct {
		MemUsed  float64 `json:"mem_used"`
		MemTotal float64 `json:"mem_total"`
	} `json:"sys_stats"`
	PortTable []struct {
		PoeEnable bool   `json:"poe_enable"`
		PoePower  string `json:"poe_power"`
	} `json:"port_table"`
}

// ─────────────────────────────────────────────────────────────────────────────
// FleetDB.QueryCapacitySummary
// ─────────────────────────────────────────────────────────────────────────────

// QueryCapacitySummary returns fleet-wide capacity metrics from device snapshots
// recorded in the last 24 hours.
func (f *FleetDB) QueryCapacitySummary() (*CapacitySummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	dayAgo := time.Now().Add(-24 * time.Hour).Unix()
	summary := &CapacitySummary{}

	// Switches at risk: most-recent snapshot per device where poe_budget_w > 0
	// and draw/budget > 0.85.
	err := f.db.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT device_id, MAX(ts) AS max_ts
			FROM fleet_device_snapshots
			WHERE ts > ? AND poe_budget_w > 0
			GROUP BY device_id
		) latest
		JOIN fleet_device_snapshots fds
		  ON fds.device_id = latest.device_id AND fds.ts = latest.max_ts
		WHERE CAST(fds.poe_draw_w AS REAL) / fds.poe_budget_w > 0.85
	`, dayAgo).Scan(&summary.SwitchesAtRisk)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query switches at risk: %w", err)
	}

	// Devices with high RAM: most-recent snapshot per device where ram_pct > 85.
	err = f.db.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT device_id, MAX(ts) AS max_ts
			FROM fleet_device_snapshots
			WHERE ts > ?
			GROUP BY device_id
		) latest
		JOIN fleet_device_snapshots fds
		  ON fds.device_id = latest.device_id AND fds.ts = latest.max_ts
		WHERE fds.ram_pct > 85
	`, dayAgo).Scan(&summary.DevicesHighRAM)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query high RAM devices: %w", err)
	}

	// Average PoE utilisation across all snapshots in last 24h where budget > 0.
	var avgPoe sql.NullFloat64
	err = f.db.QueryRow(`
		SELECT AVG(CAST(poe_draw_w AS REAL) / poe_budget_w * 100)
		FROM fleet_device_snapshots
		WHERE ts > ? AND poe_budget_w > 0
	`, dayAgo).Scan(&avgPoe)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query avg poe: %w", err)
	}
	if avgPoe.Valid {
		summary.AvgPoePct = avgPoe.Float64
	}

	return summary, nil
}
