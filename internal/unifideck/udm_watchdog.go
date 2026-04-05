package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// WatchdogCfg holds persisted watchdog settings.
type WatchdogCfg struct {
	Enabled         bool `json:"enabled"`
	ThresholdMB     int  `json:"threshold_mb"`     // restart when MemAvailable < this; default 512
	IntervalSecs    int  `json:"interval_secs"`    // poll interval; default 240
	DryRun          bool `json:"dry_run"`           // log intent but skip restart
	MaxRestartsDay  int  `json:"max_restarts_day"`  // 0 = unlimited; default 3
}

func defaultWatchdogCfg() WatchdogCfg {
	return WatchdogCfg{
		Enabled:        false,
		ThresholdMB:    512,
		IntervalSecs:   240,
		DryRun:         false,
		MaxRestartsDay: 3,
	}
}

// WatchdogEventType classifies a log entry.
type WatchdogEventType string

const (
	WEvtCheck   WatchdogEventType = "check"
	WEvtWarn    WatchdogEventType = "warn"
	WEvtRestart WatchdogEventType = "restart"
	WEvtSkip    WatchdogEventType = "skip"   // dry-run or rate-limited
	WEvtError   WatchdogEventType = "error"
	WEvtStart   WatchdogEventType = "started"
	WEvtStop    WatchdogEventType = "stopped"
)

// WatchdogEvent is one entry in the event log.
type WatchdogEvent struct {
	At          time.Time         `json:"at"`
	Type        WatchdogEventType `json:"type"`
	MemAvailMB  int               `json:"mem_avail_mb,omitempty"`
	ThresholdMB int               `json:"threshold_mb,omitempty"`
	Message     string            `json:"message"`
}

// WatchdogStatus is the GET response payload.
type WatchdogStatus struct {
	Running      bool           `json:"running"`
	Config       WatchdogCfg    `json:"config"`
	LastCheckAt  *time.Time     `json:"last_check_at,omitempty"`
	LastMemAvail int            `json:"last_mem_avail_mb"`
	RestartCount int            `json:"restart_count_total"`
	Events       []WatchdogEvent `json:"events"` // most-recent first, capped at 100
}

// ── Daemon ────────────────────────────────────────────────────────────────────

const watchdogMaxEvents = 100

// UDMWatchdog is the memory watchdog daemon.
type UDMWatchdog struct {
	mu           sync.Mutex
	cfg          WatchdogCfg
	cfgPath      string
	appCfgFn     func() AppConfig
	events       []WatchdogEvent
	restartCount int
	restartTimes []time.Time // for daily rate limiting
	running      bool
	stopCh       chan struct{}
	lastMemMB    int
	lastCheckAt  *time.Time
}

// NewUDMWatchdog creates a watchdog that loads/saves config at cfgPath.
func NewUDMWatchdog(cfgPath string, appCfgFn func() AppConfig) *UDMWatchdog {
	w := &UDMWatchdog{
		cfgPath:  cfgPath,
		appCfgFn: appCfgFn,
		cfg:      defaultWatchdogCfg(),
	}
	w.loadCfg()
	return w
}

func (w *UDMWatchdog) loadCfg() {
	raw, err := os.ReadFile(w.cfgPath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &w.cfg)
}

func (w *UDMWatchdog) saveCfg() {
	_ = os.MkdirAll(filepath.Dir(w.cfgPath), 0o755)
	b, _ := json.MarshalIndent(w.cfg, "", "  ")
	_ = os.WriteFile(w.cfgPath, b, 0o600)
}

func (w *UDMWatchdog) addEvent(evt WatchdogEvent) {
	// prepend (most-recent first)
	w.events = append([]WatchdogEvent{evt}, w.events...)
	if len(w.events) > watchdogMaxEvents {
		w.events = w.events[:watchdogMaxEvents]
	}
}

func (w *UDMWatchdog) Status() WatchdogStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	evts := make([]WatchdogEvent, len(w.events))
	copy(evts, w.events)
	return WatchdogStatus{
		Running:      w.running,
		Config:       w.cfg,
		LastCheckAt:  w.lastCheckAt,
		LastMemAvail: w.lastMemMB,
		RestartCount: w.restartCount,
		Events:       evts,
	}
}

// Start begins the polling loop if not already running.
func (w *UDMWatchdog) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running {
		return fmt.Errorf("watchdog already running")
	}
	w.running = true
	w.stopCh = make(chan struct{})
	go w.loop(w.stopCh)
	w.addEvent(WatchdogEvent{
		At:      time.Now().UTC(),
		Type:    WEvtStart,
		Message: fmt.Sprintf("watchdog started — threshold %d MB, interval %ds, dry_run=%v", w.cfg.ThresholdMB, w.cfg.IntervalSecs, w.cfg.DryRun),
	})
	return nil
}

// Stop halts the polling loop.
func (w *UDMWatchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	close(w.stopCh)
	w.running = false
	w.addEvent(WatchdogEvent{
		At:      time.Now().UTC(),
		Type:    WEvtStop,
		Message: "watchdog stopped",
	})
}

// CheckNow runs a single check immediately (outside the poll loop).
func (w *UDMWatchdog) CheckNow(ctx context.Context) error {
	appCfg := w.appCfgFn()
	return w.doCheck(ctx, appCfg)
}

// UpdateConfig replaces the running config and persists it.
// If the watchdog is running, Stop+Start is NOT automatic — caller decides.
func (w *UDMWatchdog) UpdateConfig(cfg WatchdogCfg) {
	w.mu.Lock()
	w.cfg = cfg
	w.mu.Unlock()
	w.saveCfg()
}

// ── Poll loop ─────────────────────────────────────────────────────────────────

func (w *UDMWatchdog) loop(stop <-chan struct{}) {
	interval := func() time.Duration {
		w.mu.Lock()
		defer w.mu.Unlock()
		secs := w.cfg.IntervalSecs
		if secs < 30 {
			secs = 30
		}
		return time.Duration(secs) * time.Second
	}

	// Run once immediately on start, then on ticker.
	ctx := context.Background()
	appCfg := w.appCfgFn()
	_ = w.doCheck(ctx, appCfg)

	for {
		select {
		case <-stop:
			return
		case <-time.After(interval()):
			appCfg := w.appCfgFn()
			_ = w.doCheck(ctx, appCfg)
		}
	}
}

func (w *UDMWatchdog) doCheck(ctx context.Context, appCfg AppConfig) error {
	if appCfg.SSHHost == "" {
		return nil
	}

	client, err := udmSSHClient(appCfg)
	if err != nil {
		w.mu.Lock()
		w.addEvent(WatchdogEvent{
			At:      time.Now().UTC(),
			Type:    WEvtError,
			Message: "SSH connect failed: " + err.Error(),
		})
		w.mu.Unlock()
		return err
	}
	defer client.Close()

	memRaw, err := udmRun(client, "cat /proc/meminfo")
	if err != nil {
		w.mu.Lock()
		w.addEvent(WatchdogEvent{
			At:      time.Now().UTC(),
			Type:    WEvtError,
			Message: "meminfo read failed: " + err.Error(),
		})
		w.mu.Unlock()
		return err
	}

	memAvailKB := parseMemAvailable(memRaw)
	memAvailMB := int(memAvailKB / 1024)

	now := time.Now().UTC()
	w.mu.Lock()
	w.lastMemMB = memAvailMB
	w.lastCheckAt = &now
	threshold := w.cfg.ThresholdMB
	dryRun := w.cfg.DryRun
	maxPerDay := w.cfg.MaxRestartsDay
	w.mu.Unlock()

	if memAvailMB >= threshold {
		w.mu.Lock()
		w.addEvent(WatchdogEvent{
			At:          now,
			Type:        WEvtCheck,
			MemAvailMB:  memAvailMB,
			ThresholdMB: threshold,
			Message:     fmt.Sprintf("OK — %d MB available (threshold %d MB)", memAvailMB, threshold),
		})
		w.mu.Unlock()
		return nil
	}

	// Below threshold — check rate limit before restarting
	w.mu.Lock()
	restartAllowed := true
	if maxPerDay > 0 {
		cutoff := now.Add(-24 * time.Hour)
		recent := 0
		for _, t := range w.restartTimes {
			if t.After(cutoff) {
				recent++
			}
		}
		if recent >= maxPerDay {
			restartAllowed = false
		}
	}
	w.mu.Unlock()

	if !restartAllowed {
		w.mu.Lock()
		w.addEvent(WatchdogEvent{
			At:          now,
			Type:        WEvtSkip,
			MemAvailMB:  memAvailMB,
			ThresholdMB: threshold,
			Message:     fmt.Sprintf("Memory low (%d MB) but daily restart limit reached — skipping", memAvailMB),
		})
		w.mu.Unlock()
		return nil
	}

	if dryRun {
		w.mu.Lock()
		w.addEvent(WatchdogEvent{
			At:          now,
			Type:        WEvtSkip,
			MemAvailMB:  memAvailMB,
			ThresholdMB: threshold,
			Message:     fmt.Sprintf("DRY-RUN: would restart UniFi OS — %d MB available (threshold %d MB)", memAvailMB, threshold),
		})
		w.mu.Unlock()
		return nil
	}

	// Issue the restart
	w.mu.Lock()
	w.addEvent(WatchdogEvent{
		At:          now,
		Type:        WEvtWarn,
		MemAvailMB:  memAvailMB,
		ThresholdMB: threshold,
		Message:     fmt.Sprintf("Memory low: %d MB available — issuing unifi-os restart", memAvailMB),
	})
	w.mu.Unlock()

	out, _ := udmRun(client, "unifi-os restart")

	w.mu.Lock()
	w.restartCount++
	w.restartTimes = append(w.restartTimes, now)
	// trim old entries
	cutoff := now.Add(-25 * time.Hour)
	filtered := w.restartTimes[:0]
	for _, t := range w.restartTimes {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	w.restartTimes = filtered
	w.addEvent(WatchdogEvent{
		At:          now,
		Type:        WEvtRestart,
		MemAvailMB:  memAvailMB,
		ThresholdMB: threshold,
		Message:     fmt.Sprintf("unifi-os restart issued (total restarts: %d). Output: %s", w.restartCount, strings.TrimSpace(out)),
	})
	w.mu.Unlock()

	return nil
}

func parseMemAvailable(raw string) int64 {
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.TrimSuffix(parts[0], ":") == "MemAvailable" {
			var v int64
			fmt.Sscanf(parts[1], "%d", &v)
			return v
		}
	}
	return 0
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// handleUDMWatchdog handles GET/POST /api/udm-watchdog.
func (s *HTTPServer) handleUDMWatchdog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.watchdog.Status()})

	case http.MethodPost:
		// Body can include "action" (start|stop|update) + optional "config" object.
		var body struct {
			Action string       `json:"action"`
			Config *WatchdogCfg `json:"config,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}

		if body.Config != nil {
			// Validate
			if body.Config.ThresholdMB <= 0 {
				body.Config.ThresholdMB = 512
			}
			if body.Config.IntervalSecs < 30 {
				body.Config.IntervalSecs = 30
			}
			s.watchdog.UpdateConfig(*body.Config)
		}

		switch body.Action {
		case "start":
			if err := s.watchdog.Start(); err != nil {
				writeJSON(w, http.StatusConflict, apiResp{Success: false, Error: err.Error()})
				return
			}
		case "stop":
			s.watchdog.Stop()
		case "check":
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			if err := s.watchdog.CheckNow(ctx); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
		case "update":
			// config already updated above — nothing more to do
		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown action"})
			return
		}

		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.watchdog.Status()})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

