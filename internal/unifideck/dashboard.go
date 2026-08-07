package unifideck

import (
	"net/http"
	"time"
)

// ── Dashboard aggregation ─────────────────────────────────────────────────────

// DashboardData is the response payload for GET /api/dashboard.
// All fields come from in-memory state — no external API calls — so it loads instantly.
type DashboardData struct {
	GeneratedAt    time.Time       `json:"generated_at"`
	Watchdog       WatchdogSummary `json:"watchdog"`
	Security       SecuritySummary `json:"security"`
	Clients        ClientSummary   `json:"clients"`
	Automations    AutoSummary     `json:"automations"`
	RecentActivity []string        `json:"recent_activity"`
}

type WatchdogSummary struct {
	Running      bool       `json:"running"`
	DryRun       bool       `json:"dry_run"`
	ThresholdMB  int        `json:"threshold_mb"`
	MemAvailMB   int        `json:"mem_avail_mb"`
	RestartCount int        `json:"restart_count_total"`
	LastCheckAt  *time.Time `json:"last_check_at,omitempty"`
}

type SecuritySummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Honeypot int `json:"honeypot"`
}

type ClientSummary struct {
	TotalKnown  int       `json:"total_known"`
	NewLast30d  int       `json:"new_last_30d"`
	LastUpdated time.Time `json:"last_updated"`
}

type AutoSummary struct {
	Total     int        `json:"total"`
	Enabled   int        `json:"enabled"`
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
}

// handleDashboard returns an aggregated snapshot of watchdog, security, and client status.
func (s *HTTPServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}

	// Watchdog (in-memory, instant)
	wd := s.watchdog.Status()
	wdSum := WatchdogSummary{
		Running:      wd.Running,
		DryRun:       wd.Config.DryRun,
		ThresholdMB:  wd.Config.ThresholdMB,
		MemAvailMB:   wd.LastMemAvail,
		RestartCount: wd.RestartCount,
		LastCheckAt:  wd.LastCheckAt,
	}

	// Security threats (in-memory, instant)
	total, critical, honeypot := s.threatStore.Summary()
	secSum := SecuritySummary{Total: total, Critical: critical, Honeypot: honeypot}

	// Clients (in-memory history, instant)
	newDevices := s.clientTracker.NewDevices(30)
	cliSum := ClientSummary{
		TotalKnown:  s.clientTracker.Count(),
		NewLast30d:  len(newDevices),
		LastUpdated: s.clientTracker.LastSnapshot(),
	}

	// Automations (in-memory, instant)
	automations := s.store.List()
	aSum := AutoSummary{Total: len(automations)}
	for _, a := range automations {
		if a.Enabled {
			aSum.Enabled++
		}
		if a.NextRunAt != nil && (aSum.NextRunAt == nil || a.NextRunAt.Before(*aSum.NextRunAt)) {
			aSum.NextRunAt = a.NextRunAt
		}
	}

	// Recent activity log (last 8 lines, in-memory, instant)
	activity := s.logger.Tail(8)

	writeJSON(w, http.StatusOK, apiResp{
		Success: true,
		Data: DashboardData{
			GeneratedAt:    time.Now().UTC(),
			Watchdog:       wdSum,
			Security:       secSum,
			Clients:        cliSum,
			Automations:    aSum,
			RecentActivity: activity,
		},
	})
}
