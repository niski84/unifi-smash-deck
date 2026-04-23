package unifideck

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// WANHealthPoint is one reading from a site's WAN.
type WANHealthPoint struct {
	TS        int64   `json:"ts"`
	LatencyMS float64 `json:"latency_ms"`
	LossPct   float64 `json:"loss_pct"`
	IsUp      bool    `json:"is_up"`
}

// ISPSummary aggregates WAN health by ISP label.
type ISPSummary struct {
	ISPLabel     string  `json:"isp_label"`
	SiteCount    int     `json:"site_count"`
	UptimePct    float64 `json:"uptime_pct"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	MicroDrops   int     `json:"micro_drops"` // events with loss > 0 but < 60s
	WorstSite    string  `json:"worst_site"`
}

// WANSiteStatus is the current WAN health for one site.
type WANSiteStatus struct {
	SiteID     string  `json:"site_id"`
	SiteName   string  `json:"site_name"`
	ISPLabel   string  `json:"isp_label"`
	LatencyMS  float64 `json:"latency_ms"`
	LossPct    float64 `json:"loss_pct"`
	IsUp       bool    `json:"is_up"`
	LastSeenTS int64   `json:"last_seen_ts"`
}

// FetchWANHealth fetches current WAN metrics for a site from the UniFi API.
// Uses GET /proxy/network/api/s/{siteName}/stat/health with X-API-KEY header.
// Returns latency in ms, packet loss %, and up/down status.
func FetchWANHealth(ctx context.Context, site SiteConnection) (*WANSnapshot, error) {
	siteName := siteNameOrDefault(site)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/health",
		strings.TrimRight(site.Host, "/"),
		siteName)

	body, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, fmt.Errorf("fetch wan health: %w", err)
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode health response: %w", err)
	}

	// Find the WAN subsystem entry
	for _, entry := range resp.Data {
		subsystem, _ := entry["subsystem"].(string)
		if subsystem != "wan" {
			continue
		}

		// Parse latency — may be float64 or int
		var latencyMS float64
		switch v := entry["latency"].(type) {
		case float64:
			latencyMS = v
		case int:
			latencyMS = float64(v)
		}

		// Parse uptime — positive uptime means link is up
		var uptime float64
		switch v := entry["uptime"].(type) {
		case float64:
			uptime = v
		case int:
			uptime = float64(v)
		}

		isUp := uptime > 0

		// If latency and uptime are both zero, mark as down
		var lossPct float64
		if latencyMS == 0 && uptime == 0 {
			isUp = false
			lossPct = 100.0
		}

		snap := &WANSnapshot{
			SiteID:    site.ID,
			TS:        time.Now().Unix(),
			LatencyMS: latencyMS,
			LossPct:   lossPct,
			DNSFails:  0,
			ISPLabel:  "", // populated externally from site config / ISP label field
			IsUp:      isUp,
		}
		return snap, nil
	}

	// No WAN subsystem found — treat as down
	log.Printf("[isp-health] site %s: no WAN subsystem in health response", site.Name)
	return &WANSnapshot{
		SiteID:    site.ID,
		TS:        time.Now().Unix(),
		LatencyMS: 0,
		LossPct:   100.0,
		DNSFails:  0,
		ISPLabel:  "",
		IsUp:      false,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// FleetDB WAN queries
// ─────────────────────────────────────────────────────────────────────────────

// QueryWANByISP returns a summary per ISP label for the last N days.
func (f *FleetDB) QueryWANByISP(days int) ([]ISPSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -days).Unix()

	rows, err := f.db.Query(`
		SELECT
			isp_label,
			COUNT(DISTINCT site_id),
			AVG(CASE WHEN is_up=1 THEN 100.0 ELSE 0.0 END),
			AVG(latency_ms),
			COUNT(CASE WHEN loss_pct > 0 AND is_up=1 THEN 1 END)
		FROM wan_health
		WHERE ts >= ?
		GROUP BY isp_label
		ORDER BY AVG(latency_ms) DESC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query wan by isp: %w", err)
	}
	defer rows.Close()

	var summaries []ISPSummary
	for rows.Next() {
		var s ISPSummary
		var ispLabel sql.NullString
		if err := rows.Scan(&ispLabel, &s.SiteCount, &s.UptimePct, &s.AvgLatencyMS, &s.MicroDrops); err != nil {
			return nil, fmt.Errorf("scan isp summary: %w", err)
		}
		s.ISPLabel = ispLabel.String
		if s.ISPLabel == "" {
			s.ISPLabel = "Unknown ISP"
		}
		// Find worst site (highest avg latency) for this ISP
		worstSite, err := f.queryWorstSiteForISP(ispLabel.String, cutoff)
		if err != nil {
			log.Printf("[isp-health] worst site query failed isp=%q err=%v", ispLabel.String, err)
		} else {
			s.WorstSite = worstSite
		}
		summaries = append(summaries, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if summaries == nil {
		summaries = []ISPSummary{}
	}
	return summaries, nil
}

// queryWorstSiteForISP returns the site_id with the highest avg latency for a given ISP label.
// Must be called without holding the mutex (internal helper).
func (f *FleetDB) queryWorstSiteForISP(ispLabel string, cutoff int64) (string, error) {
	var siteID string
	err := f.db.QueryRow(`
		SELECT site_id
		FROM wan_health
		WHERE isp_label = ? AND ts >= ?
		GROUP BY site_id
		ORDER BY AVG(latency_ms) DESC
		LIMIT 1
	`, ispLabel, cutoff).Scan(&siteID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return siteID, err
}

// QueryLatestWANStatus returns the most recent WAN reading per site.
func (f *FleetDB) QueryLatestWANStatus() ([]WANSiteStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rows, err := f.db.Query(`
		SELECT w.site_id, w.latency_ms, w.loss_pct, w.is_up, w.isp_label, w.ts
		FROM wan_health w
		INNER JOIN (
			SELECT site_id, MAX(ts) as max_ts
			FROM wan_health
			GROUP BY site_id
		) latest ON w.site_id = latest.site_id AND w.ts = latest.max_ts
		ORDER BY w.site_id
	`)
	if err != nil {
		return nil, fmt.Errorf("query latest wan status: %w", err)
	}
	defer rows.Close()

	// Also query latest site name from site_snapshots
	siteNames := map[string]string{}
	nameRows, nameErr := f.db.Query(`
		SELECT site_id, site_name
		FROM site_snapshots
		WHERE ts IN (SELECT MAX(ts) FROM site_snapshots GROUP BY site_id)
	`)
	if nameErr == nil {
		defer nameRows.Close()
		for nameRows.Next() {
			var id, name string
			if err := nameRows.Scan(&id, &name); err == nil {
				siteNames[id] = name
			}
		}
	}

	var statuses []WANSiteStatus
	for rows.Next() {
		var st WANSiteStatus
		var isUpInt int
		var ispLabel sql.NullString
		if err := rows.Scan(&st.SiteID, &st.LatencyMS, &st.LossPct, &isUpInt, &ispLabel, &st.LastSeenTS); err != nil {
			return nil, fmt.Errorf("scan wan status: %w", err)
		}
		st.IsUp = isUpInt == 1
		st.ISPLabel = ispLabel.String
		st.SiteName = siteNames[st.SiteID]
		statuses = append(statuses, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if statuses == nil {
		statuses = []WANSiteStatus{}
	}
	return statuses, nil
}

// QueryWANHistory returns time-series WAN data for one site over the last N hours.
func (f *FleetDB) QueryWANHistory(siteID string, hours int) ([]WANHealthPoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	rows, err := f.db.Query(`
		SELECT ts, latency_ms, loss_pct, is_up
		FROM wan_health
		WHERE site_id = ? AND ts >= ?
		ORDER BY ts ASC
	`, siteID, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query wan history: %w", err)
	}
	defer rows.Close()

	var points []WANHealthPoint
	for rows.Next() {
		var p WANHealthPoint
		var isUpInt int
		if err := rows.Scan(&p.TS, &p.LatencyMS, &p.LossPct, &isUpInt); err != nil {
			return nil, fmt.Errorf("scan wan history: %w", err)
		}
		p.IsUp = isUpInt == 1
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if points == nil {
		points = []WANHealthPoint{}
	}
	return points, nil
}

