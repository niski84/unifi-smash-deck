package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BrakeRule is one scheduled on/off rule.
type BrakeRule struct {
	// HourOn and HourOff are local-time hours (0–23).
	HourOn  int `json:"hour_on"`  // default 1  (1 AM)
	HourOff int `json:"hour_off"` // default 7  (7 AM)
}

// ClientBrakeCfg is the persisted config for the upload brake.
type ClientBrakeCfg struct {
	Enabled        bool      `json:"enabled"`
	ClientDocID    string    `json:"client_doc_id"`    // UniFi _id for MYPC-03
	BrakeGroupID   string    `json:"brake_group_id"`   // "1AM Upload Brake" group _id
	DefaultGroupID string    `json:"default_group_id"` // "Default" group _id
	Rule           BrakeRule `json:"rule"`
}

func defaultBrakeCfg() ClientBrakeCfg {
	return ClientBrakeCfg{
		Enabled:        false,
		ClientDocID:    "684ae5872d75e03ca516d781",
		BrakeGroupID:   "6a21eced8df71d88e75703d3",
		DefaultGroupID: "683e4a0a5b7e7618b9a53503",
		Rule:           BrakeRule{HourOn: 1, HourOff: 7},
	}
}

// BrakeEventType classifies a log entry.
type BrakeEventType string

const (
	BrakeEvtApplied BrakeEventType = "applied"
	BrakeEvtLifted  BrakeEventType = "lifted"
	BrakeEvtSkip    BrakeEventType = "skip"
	BrakeEvtError   BrakeEventType = "error"
	BrakeEvtStart   BrakeEventType = "started"
	BrakeEvtStop    BrakeEventType = "stopped"
	BrakeEvtManual  BrakeEventType = "manual"
)

// BrakeEvent is one log entry.
type BrakeEvent struct {
	At      time.Time      `json:"at"`
	Type    BrakeEventType `json:"type"`
	Message string         `json:"message"`
}

// BrakeStatus is the GET response.
type BrakeStatus struct {
	Running     bool           `json:"running"`
	BrakeActive bool           `json:"brake_active"`
	NextOn      *time.Time     `json:"next_on,omitempty"`
	NextOff     *time.Time     `json:"next_off,omitempty"`
	Config      ClientBrakeCfg `json:"config"`
	Events      []BrakeEvent   `json:"events"`
}

const brakeMaxEvents = 100

// ClientBrake is the scheduled upload-throttle daemon.
type ClientBrake struct {
	mu          sync.Mutex
	cfg         ClientBrakeCfg
	cfgPath     string
	appCfgFn    func() AppConfig
	events      []BrakeEvent
	brakeActive bool
	running     bool
	stopCh      chan struct{}
}

// NewClientBrake creates a ClientBrake that persists config at cfgPath.
func NewClientBrake(cfgPath string, appCfgFn func() AppConfig) *ClientBrake {
	b := &ClientBrake{
		cfgPath:  cfgPath,
		appCfgFn: appCfgFn,
		cfg:      defaultBrakeCfg(),
	}
	b.loadCfg()
	return b
}

func (b *ClientBrake) loadCfg() {
	raw, err := os.ReadFile(b.cfgPath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &b.cfg)
}

func (b *ClientBrake) saveCfg() {
	_ = os.MkdirAll(filepath.Dir(b.cfgPath), 0o755)
	raw, _ := json.MarshalIndent(b.cfg, "", "  ")
	_ = os.WriteFile(b.cfgPath, raw, 0o600)
}

func (b *ClientBrake) addEvent(evt BrakeEvent) {
	b.events = append([]BrakeEvent{evt}, b.events...)
	if len(b.events) > brakeMaxEvents {
		b.events = b.events[:brakeMaxEvents]
	}
}

func (b *ClientBrake) Status() BrakeStatus {
	b.mu.Lock()
	running := b.running
	active := b.brakeActive
	cfg := b.cfg
	evts := make([]BrakeEvent, len(b.events))
	copy(evts, b.events)
	b.mu.Unlock()

	s := BrakeStatus{
		Running:     running,
		BrakeActive: active,
		Config:      cfg,
		Events:      evts,
	}
	if running {
		on, off := b.nextOnOff()
		s.NextOn = &on
		s.NextOff = &off
	}
	return s
}

// Start begins the scheduling loop.
func (b *ClientBrake) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running {
		return fmt.Errorf("client brake already running")
	}
	b.running = true
	b.stopCh = make(chan struct{})
	go b.loop(b.stopCh)
	b.addEvent(BrakeEvent{
		At:      time.Now(),
		Type:    BrakeEvtStart,
		Message: fmt.Sprintf("brake scheduler started — on at %02d:00, off at %02d:00", b.cfg.Rule.HourOn, b.cfg.Rule.HourOff),
	})
	return nil
}

// Stop halts the scheduling loop. It does NOT lift the brake if currently active.
func (b *ClientBrake) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.running {
		return
	}
	close(b.stopCh)
	b.running = false
	b.addEvent(BrakeEvent{At: time.Now(), Type: BrakeEvtStop, Message: "brake scheduler stopped"})
}

// ApplyNow forces the brake on immediately regardless of schedule.
func (b *ClientBrake) ApplyNow(ctx context.Context) error {
	appCfg := b.appCfgFn()
	return b.setBrake(ctx, appCfg, true, BrakeEvtManual)
}

// LiftNow forces the brake off immediately regardless of schedule.
func (b *ClientBrake) LiftNow(ctx context.Context) error {
	appCfg := b.appCfgFn()
	return b.setBrake(ctx, appCfg, false, BrakeEvtManual)
}

// UpdateConfig replaces the running config and persists it.
func (b *ClientBrake) UpdateConfig(cfg ClientBrakeCfg) {
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
	b.saveCfg()
}

// ── Scheduling ────────────────────────────────────────────────────────────────

// nextOnOff returns the next scheduled on and off times from now.
// Must be called without the lock (it reads cfg under lock internally).
func (b *ClientBrake) nextOnOff() (nextOn, nextOff time.Time) {
	b.mu.Lock()
	hourOn := b.cfg.Rule.HourOn
	hourOff := b.cfg.Rule.HourOff
	b.mu.Unlock()

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	on := today.Add(time.Duration(hourOn) * time.Hour)
	off := today.Add(time.Duration(hourOff) * time.Hour)

	if on.Before(now) {
		on = on.Add(24 * time.Hour)
	}
	if off.Before(now) {
		off = off.Add(24 * time.Hour)
	}
	return on, off
}

// shouldBrakeNow returns true if the current local time falls within the brake window.
func (b *ClientBrake) shouldBrakeNow() bool {
	b.mu.Lock()
	hourOn := b.cfg.Rule.HourOn
	hourOff := b.cfg.Rule.HourOff
	b.mu.Unlock()

	h := time.Now().Hour()
	if hourOn < hourOff {
		return h >= hourOn && h < hourOff
	}
	// wraps midnight (e.g. 22→6)
	return h >= hourOn || h < hourOff
}

func (b *ClientBrake) loop(stop <-chan struct{}) {
	// On startup, immediately reconcile state with the schedule.
	ctx := context.Background()
	appCfg := b.appCfgFn()
	want := b.shouldBrakeNow()
	b.mu.Lock()
	current := b.brakeActive
	b.mu.Unlock()
	if want != current {
		_ = b.setBrake(ctx, appCfg, want, "")
	}

	// Then tick every minute and flip when the hour changes.
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			appCfg = b.appCfgFn()
			want = b.shouldBrakeNow()
			b.mu.Lock()
			current = b.brakeActive
			b.mu.Unlock()
			if want != current {
				_ = b.setBrake(ctx, appCfg, want, "")
			}
		}
	}
}

// setBrake calls the UniFi API to assign or remove the brake usergroup.
func (b *ClientBrake) setBrake(ctx context.Context, appCfg AppConfig, on bool, evtType BrakeEventType) error {
	b.mu.Lock()
	clientDocID := b.cfg.ClientDocID
	brakeGroupID := b.cfg.BrakeGroupID
	defaultGroupID := b.cfg.DefaultGroupID
	b.mu.Unlock()

	groupID := defaultGroupID
	if on {
		groupID = brakeGroupID
	}

	uc := NewUnifiClient(appCfg.UnifiHost, appCfg.UnifiAPIKey, appCfg.UnifiSite)
	err := uc.SetClientUsergroup(ctx, clientDocID, groupID)

	b.mu.Lock()
	defer b.mu.Unlock()

	if evtType == "" {
		if on {
			evtType = BrakeEvtApplied
		} else {
			evtType = BrakeEvtLifted
		}
	}

	if err != nil {
		b.addEvent(BrakeEvent{
			At:      time.Now(),
			Type:    BrakeEvtError,
			Message: fmt.Sprintf("failed to %s brake: %v", map[bool]string{true: "apply", false: "lift"}[on], err),
		})
		return err
	}

	b.brakeActive = on
	action := "lifted (full speed restored)"
	if on {
		action = "applied (64 Kbps upload)"
	}
	b.addEvent(BrakeEvent{
		At:      time.Now(),
		Type:    evtType,
		Message: fmt.Sprintf("brake %s — group %s", action, groupID),
	})
	return nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// handleClientBrake reports brake status (GET) or starts, stops, applies, or lifts client bandwidth throttling (POST).
func (s *HTTPServer) handleClientBrake(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.clientBrake.Status()})

	case http.MethodPost:
		var body struct {
			Action string          `json:"action"`
			Config *ClientBrakeCfg `json:"config,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}

		if body.Config != nil {
			s.clientBrake.UpdateConfig(*body.Config)
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		switch body.Action {
		case "start":
			if err := s.clientBrake.Start(); err != nil {
				writeJSON(w, http.StatusConflict, apiResp{Success: false, Error: err.Error()})
				return
			}
		case "stop":
			s.clientBrake.Stop()
		case "apply":
			if err := s.clientBrake.ApplyNow(ctx); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
		case "lift":
			if err := s.clientBrake.LiftNow(ctx); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
		case "update":
			// config already applied above
		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown action"})
			return
		}

		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.clientBrake.Status()})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}
