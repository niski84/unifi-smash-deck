package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"net/http"
)

// dfsChannels is the set of 5GHz DFS channels (52–144).
var dfsChannels = map[int]bool{
	52: true, 56: true, 60: true, 64: true,
	100: true, 104: true, 108: true, 112: true,
	116: true, 120: true, 124: true, 128: true,
	132: true, 136: true, 140: true, 144: true,
}

// APChannel holds per-AP radio and RF metrics for one access point.
type APChannel struct {
	DeviceID     string  `json:"device_id"`
	Name         string  `json:"name"`
	Model        string  `json:"model"`
	SiteID       string  `json:"site_id"`
	SiteName     string  `json:"site_name"`
	Channel5G    int     `json:"channel_5g,omitempty"`
	Channel2G    int     `json:"channel_2g,omitempty"`
	TxRetryPct   float64 `json:"tx_retry_pct,omitempty"` // tx_retries / tx_packets * 100
	RxRetryPct   float64 `json:"rx_retry_pct,omitempty"`
	IsDFSChannel bool    `json:"is_dfs_channel"` // channel in 52-144 range (5GHz)
	TxPower      int     `json:"tx_power,omitempty"`
	Satisfaction int     `json:"satisfaction,omitempty"` // 0-100 from UniFi
}

// RFSiteReport is the full RF health analysis for one site.
type RFSiteReport struct {
	SiteID          string      `json:"site_id"`
	SiteName        string      `json:"site_name"`
	APs             []APChannel `json:"aps"`
	AnalyzedAt      time.Time   `json:"analyzed_at"`
	DFSAPCount      int         `json:"dfs_ap_count"`    // APs on DFS channels
	HighRetryCount  int         `json:"high_retry_count"` // APs with >10% retry
	AvgSatisfaction int         `json:"avg_satisfaction"`
}

// RFSuggestion is an actionable recommendation for a specific AP.
type RFSuggestion struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"` // "warn" | "critical"
	Issue      string `json:"issue"`
	Suggestion string `json:"suggestion"`
}

// ── raw API types ──────────────────────────────────────────────────────────────

type rfDevice struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Model string `json:"model"`

	RadioTable []struct {
		Name    string `json:"name"`     // "ng" = 2.4GHz, "na" = 5GHz
		Channel int    `json:"channel"`
		TxPower int    `json:"tx_power"`
	} `json:"radio_table"`

	RadioTableStats []struct {
		Name         string  `json:"name"`
		TxRetries    float64 `json:"tx_retries"`
		TxPackets    float64 `json:"tx_packets"`
		RxRetries    float64 `json:"rx_retries"`
		RxPackets    float64 `json:"rx_packets"`
		Satisfaction int     `json:"satisfaction"`
	} `json:"radio_table_stats"`
}

// AnalyzeRFHealth fetches AP radio data for a site and returns an RF health report.
// Uses GET /proxy/network/api/s/{siteName}/stat/device with X-API-KEY header.
func AnalyzeRFHealth(ctx context.Context, site SiteConnection) (*RFSiteReport, error) {
	siteName := siteNameOrDefault(site)

	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device",
		strings.TrimRight(site.Host, "/"),
		siteName)

	body, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, fmt.Errorf("fetch stat/device: %w", err)
	}

	var respData struct {
		Data []rfDevice `json:"data"`
	}
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("decode stat/device: %w", err)
	}

	report := &RFSiteReport{
		SiteID:     site.ID,
		SiteName:   site.Name,
		AnalyzedAt: time.Now(),
	}

	var totalSatisfaction int
	satisfactionCount := 0

	for _, dev := range respData.Data {
		if dev.Type != "uap" {
			continue
		}

		ap := APChannel{
			DeviceID: dev.ID,
			Name:     dev.Name,
			Model:    dev.Model,
			SiteID:   site.ID,
			SiteName: site.Name,
		}

		// Build channel and tx_power maps from radio_table (indexed by radio name)
		type radioConf struct {
			channel int
			txPower int
		}
		radioConfMap := map[string]radioConf{}
		for _, rt := range dev.RadioTable {
			radioConfMap[rt.Name] = radioConf{channel: rt.Channel, txPower: rt.TxPower}
		}

		// Set 2G / 5G channels and tx power from radio_table
		if ng, ok := radioConfMap["ng"]; ok {
			ap.Channel2G = ng.channel
		}
		if na, ok := radioConfMap["na"]; ok {
			ap.Channel5G = na.channel
			ap.TxPower = na.txPower // prefer 5GHz tx power
			ap.IsDFSChannel = dfsChannels[na.channel]
		}

		// Compute retry rates and satisfaction from radio_table_stats
		var bestSatisfaction int
		for _, rts := range dev.RadioTableStats {
			// Tx retry rate
			if rts.TxPackets > 0 {
				pct := (rts.TxRetries / rts.TxPackets) * 100.0
				// Use the highest retry pct across all radios (worst-case)
				if pct > ap.TxRetryPct {
					ap.TxRetryPct = pct
				}
			}
			// Rx retry rate
			if rts.RxPackets > 0 {
				pct := (rts.RxRetries / rts.RxPackets) * 100.0
				if pct > ap.RxRetryPct {
					ap.RxRetryPct = pct
				}
			}
			// Take the best (highest) satisfaction across radios
			if rts.Satisfaction > bestSatisfaction {
				bestSatisfaction = rts.Satisfaction
			}
		}
		ap.Satisfaction = bestSatisfaction

		// Accumulate for site averages
		if ap.Satisfaction > 0 {
			totalSatisfaction += ap.Satisfaction
			satisfactionCount++
		}

		report.APs = append(report.APs, ap)
	}

	// Compute summary fields
	for _, ap := range report.APs {
		if ap.IsDFSChannel {
			report.DFSAPCount++
		}
		if ap.TxRetryPct > 10.0 {
			report.HighRetryCount++
		}
	}
	if satisfactionCount > 0 {
		report.AvgSatisfaction = totalSatisfaction / satisfactionCount
	}

	return report, nil
}

// handleRFSite analyzes RF health for a single site.
// GET /api/rf/site?site_id=xxx
func (s *HTTPServer) handleRFSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required"})
		return
	}
	cfg := s.snapshotCfg()
	var site *SiteConnection
	for i := range cfg.Sites {
		if cfg.Sites[i].ID == siteID {
			site = &cfg.Sites[i]
			break
		}
	}
	if site == nil {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "site not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := AnalyzeRFHealth(ctx, *site)
	if err != nil {
		s.logger.Warn("RF health analysis failed site=%s err=%v", siteID, err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	suggestions := GenerateRFSuggestions(report)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"report":      report,
		"suggestions": suggestions,
	}})
}

// GenerateRFSuggestions produces actionable recommendations from an RFSiteReport.
func GenerateRFSuggestions(report *RFSiteReport) []RFSuggestion {
	var suggestions []RFSuggestion

	for _, ap := range report.APs {
		// DFS + elevated retries
		if ap.IsDFSChannel && ap.TxRetryPct > 5.0 {
			suggestions = append(suggestions, RFSuggestion{
				DeviceID:   ap.DeviceID,
				Name:       ap.Name,
				Severity:   "warn",
				Issue:      fmt.Sprintf("On DFS channel %d with %.1f%% Tx retry rate", ap.Channel5G, ap.TxRetryPct),
				Suggestion: "Consider locking to non-DFS channel (36 or 149) — DFS radar events may be causing channel changes and elevated retries",
			})
		}

		// Critical: very high retry rate
		if ap.TxRetryPct > 15.0 {
			suggestions = append(suggestions, RFSuggestion{
				DeviceID:   ap.DeviceID,
				Name:       ap.Name,
				Severity:   "critical",
				Issue:      fmt.Sprintf("Tx retry rate is %.1f%%", ap.TxRetryPct),
				Suggestion: "Tx retry rate is extremely high — check for overlapping coverage or client compatibility issues",
			})
		} else if ap.TxRetryPct > 10.0 {
			// Warn: elevated retry rate
			suggestions = append(suggestions, RFSuggestion{
				DeviceID:   ap.DeviceID,
				Name:       ap.Name,
				Severity:   "warn",
				Issue:      fmt.Sprintf("Elevated Tx retry rate (%.1f%%)", ap.TxRetryPct),
				Suggestion: "Consider reducing 5GHz transmit power to decrease co-channel interference",
			})
		}

		// Low satisfaction
		if ap.Satisfaction > 0 && ap.Satisfaction < 50 {
			suggestions = append(suggestions, RFSuggestion{
				DeviceID:   ap.DeviceID,
				Name:       ap.Name,
				Severity:   "warn",
				Issue:      fmt.Sprintf("Client satisfaction is %d/100", ap.Satisfaction),
				Suggestion: "Investigate interference or coverage gaps — consider adjusting AP placement or channel plan",
			})
		}
	}

	return suggestions
}
