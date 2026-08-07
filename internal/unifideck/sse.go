package unifideck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ── Server-Sent Events stream ─────────────────────────────────────────────────
//
// GET /api/stream holds the HTTP connection open and pushes a compact JSON
// "pulse" every 10 seconds with the current in-memory state snapshot.  All
// data comes from in-process state (no SSH / UniFi API calls), so each tick
// is <1 ms.
//
// Event format (standard SSE):
//
//	event: pulse
//	data: {"threats":{"total":9,"critical":8,"honeypot":7},...}
//
// The client uses this to keep the Overview dashboard current and to fire
// toast notifications when critical conditions are detected.

// StreamPulse is the payload pushed to all SSE subscribers on every tick.
type StreamPulse struct {
	At           time.Time       `json:"at"`
	Threats      SecuritySummary `json:"threats"`
	MemAvailMB   int             `json:"mem_avail_mb"`
	WatchdogOn   bool            `json:"watchdog_running"`
	ClientCount  int             `json:"client_count"`
	NewDevices   int             `json:"new_devices_30d"`
	AutoNext     *time.Time      `json:"auto_next_run,omitempty"`
	LatestThreat *ThreatEvent    `json:"latest_threat,omitempty"`
}

func (s *HTTPServer) currentPulse() StreamPulse {
	total, critical, honeypot := s.threatStore.Summary()
	wd := s.watchdog.Status()
	newDev := s.clientTracker.NewDevices(30)

	var autoNext *time.Time
	for _, a := range s.store.List() {
		if a.Enabled && a.NextRunAt != nil {
			if autoNext == nil || a.NextRunAt.Before(*autoNext) {
				t := *a.NextRunAt
				autoNext = &t
			}
		}
	}

	latest := s.threatStore.Recent(1)
	var latestThreat *ThreatEvent
	if len(latest) > 0 {
		latestThreat = &latest[0]
	}
	return StreamPulse{
		At:           time.Now().UTC(),
		Threats:      SecuritySummary{Total: total, Critical: critical, Honeypot: honeypot},
		MemAvailMB:   wd.LastMemAvail,
		WatchdogOn:   wd.Running,
		ClientCount:  s.clientTracker.Count(),
		NewDevices:   len(newDev),
		AutoNext:     autoNext,
		LatestThreat: latestThreat,
	}
}

// handleStream is the SSE endpoint. It holds the connection and pushes a
// pulse every 10 seconds until the client disconnects.
func (s *HTTPServer) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported by this server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy

	sendPulse := func() {
		p := s.currentPulse()
		b, err := json.Marshal(p)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: pulse\ndata: %s\n\n", b)
		flusher.Flush()
	}

	// Send immediately so the client has data before the first 10 s tick.
	sendPulse()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			sendPulse()
		}
	}
}
