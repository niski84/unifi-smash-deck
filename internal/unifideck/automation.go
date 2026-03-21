package unifideck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────

type AutomationType string

const (
	TypeVlanDisable AutomationType = "vlan_disable" // disable one or more VLANs
	TypeVlanEnable  AutomationType = "vlan_enable"  // enable one or more VLANs
	TypeVlanToggle  AutomationType = "vlan_toggle"  // toggle current enabled state
)

type RunMode string

const (
	ModeManual    RunMode = "manual"
	ModeScheduled RunMode = "scheduled"
)

// ScheduleConfig defines when an automation fires.
type ScheduleConfig struct {
	DaysOfWeek   []int  `json:"days_of_week"`       // 0=Sun … 6=Sat; empty = every day
	TimeHHMM     string `json:"time"`               // "22:30"
	Timezone     string `json:"timezone,omitempty"` // IANA
	EndsOnDate   string `json:"ends_on_date,omitempty"`
	SkipWeekends bool   `json:"skip_weekends,omitempty"`
}

// VlanTarget is a network/VLAN to act on.
type VlanTarget struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
}

// Automation is the root stored struct.
type Automation struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Type        AutomationType `json:"type"`
	Enabled     bool           `json:"enabled"`
	RunMode     RunMode        `json:"run_mode,omitempty"`
	Schedule    *ScheduleConfig `json:"schedule,omitempty"`
	VlanTargets []VlanTarget   `json:"vlan_targets,omitempty"`
	NextRunAt   *time.Time     `json:"next_run_at,omitempty"`
	LastRunAt   *time.Time     `json:"last_run_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ──────────────────────────────────────────────
// AutomationStore
// ──────────────────────────────────────────────

type AutomationStore struct {
	mu   sync.RWMutex
	path string
	list []Automation
}

func NewAutomationStore(path string) *AutomationStore {
	s := &AutomationStore{path: path}
	s.load()
	return s
}

// LoadedCount returns the number of automations loaded from disk at startup.
func (s *AutomationStore) LoadedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.list)
}

func (s *AutomationStore) load() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		// File not found is normal on first run; any other error is worth noting.
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unifideck] WARNING: could not read automations from %s: %v\n", s.path, err)
		}
		return
	}
	var items []Automation
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintf(os.Stderr, "[unifideck] WARNING: automations file %s is corrupt: %v — starting with empty list\n", s.path, err)
		return
	}
	s.list = items
}

func (s *AutomationStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *AutomationStore) List() []Automation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Automation, len(s.list))
	copy(out, s.list)
	return out
}

func (s *AutomationStore) Get(id string) (Automation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.list {
		if a.ID == id {
			return a, true
		}
	}
	return Automation{}, false
}

func (s *AutomationStore) Upsert(a Automation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.list {
		if existing.ID == a.ID {
			s.list[i] = a
			return s.save()
		}
	}
	s.list = append(s.list, a)
	return s.save()
}

func (s *AutomationStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.list {
		if a.ID == id {
			s.list = append(s.list[:i], s.list[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("automation %s not found", id)
}

func (s *AutomationStore) UpdateNextRun(id string, t *time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.list {
		if a.ID == id {
			s.list[i].NextRunAt = t
			if err := s.save(); err != nil {
				fmt.Fprintf(os.Stderr, "[unifideck] ERROR: failed to save automations after UpdateNextRun id=%s: %v\n", id, err)
			}
			return
		}
	}
}

func (s *AutomationStore) UpdateLastRun(id string, t *time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.list {
		if a.ID == id {
			s.list[i].LastRunAt = t
			if err := s.save(); err != nil {
				fmt.Fprintf(os.Stderr, "[unifideck] ERROR: failed to save automations after UpdateLastRun id=%s: %v\n", id, err)
			}
			return
		}
	}
}

// ──────────────────────────────────────────────
// AutomationLogger
// ──────────────────────────────────────────────

type AutomationLogger struct {
	mu   sync.Mutex
	path string
}

func NewAutomationLogger(path string) *AutomationLogger {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &AutomationLogger{path: path}
}

func (l *AutomationLogger) log(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func (l *AutomationLogger) Info(format string, args ...any)  { l.log("INFO", format, args...) }
func (l *AutomationLogger) Warn(format string, args ...any)  { l.log("WARN", format, args...) }
func (l *AutomationLogger) Error(format string, args ...any) { l.log("ERROR", format, args...) }

// Tail returns the last n lines of the log file.
func (l *AutomationLogger) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	// Return reversed (newest first)
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines
}

// ──────────────────────────────────────────────
// Scheduler
// ──────────────────────────────────────────────

type clientFactory func() *UnifiClient

type AutomationScheduler struct {
	store  *AutomationStore
	logger *AutomationLogger
	cf     clientFactory
	mu     sync.Mutex
	ticker *time.Ticker
	stop   chan struct{}
}

func NewAutomationScheduler(store *AutomationStore, logger *AutomationLogger, cf clientFactory) *AutomationScheduler {
	return &AutomationScheduler{store: store, logger: logger, cf: cf, stop: make(chan struct{})}
}

func (s *AutomationScheduler) Start() {
	s.RefreshNextRunTimes()
	s.ticker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.tick()
			case <-s.stop:
				return
			}
		}
	}()
}

func (s *AutomationScheduler) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.stop)
}

func (s *AutomationScheduler) tick() {
	now := time.Now()
	for _, a := range s.store.List() {
		if !a.Enabled || a.RunMode != ModeScheduled || a.Schedule == nil || a.NextRunAt == nil {
			continue
		}
		if now.After(*a.NextRunAt) || now.Equal(*a.NextRunAt) {
			s.logger.Info("scheduler trigger auto=%s name=%q", a.ID, a.Name)
			go func(id string) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := s.RunAutomation(ctx, id); err != nil {
					s.logger.Error("scheduler run failed auto=%s err=%v", id, err)
				}
			}(a.ID)
			s.advanceNextRun(a)
		}
	}
}

func (s *AutomationScheduler) advanceNextRun(a Automation) {
	next := NextRunTime(a, time.Now().Add(61*time.Second))
	s.store.UpdateNextRun(a.ID, next)
}

func (s *AutomationScheduler) RefreshNextRunTimes() {
	now := time.Now()
	for _, a := range s.store.List() {
		if a.RunMode != ModeScheduled || a.Schedule == nil {
			s.store.UpdateNextRun(a.ID, nil)
			continue
		}
		next := NextRunTime(a, now)
		s.store.UpdateNextRun(a.ID, next)
	}
}

// RunAutomation executes an automation immediately.
func (s *AutomationScheduler) RunAutomation(ctx context.Context, id string) error {
	a, ok := s.store.Get(id)
	if !ok {
		return fmt.Errorf("automation %s not found", id)
	}
	s.logger.Info("run start auto=%s name=%q type=%s", a.ID, a.Name, a.Type)
	c := s.cf()
	if !c.IsConfigured() {
		return fmt.Errorf("UniFi not configured")
	}

	var errs []string
	for _, target := range a.VlanTargets {
		enabled := true
		switch a.Type {
		case TypeVlanDisable:
			enabled = false
		case TypeVlanEnable:
			enabled = true
		case TypeVlanToggle:
			// fetch current state
			nets, err := c.ListNetworks(ctx)
			if err != nil {
				errs = append(errs, fmt.Sprintf("network=%s fetch: %v", target.NetworkID, err))
				continue
			}
			found := false
			for _, n := range nets {
				if n.ID == target.NetworkID {
					enabled = !n.Enabled
					found = true
					break
				}
			}
			if !found {
				errs = append(errs, fmt.Sprintf("network=%s not found", target.NetworkID))
				continue
			}
		}
		if err := c.SetNetworkEnabled(ctx, target.NetworkID, enabled); err != nil {
			errs = append(errs, fmt.Sprintf("network=%s enabled=%v: %v", target.NetworkID, enabled, err))
			s.logger.Warn("run step failed auto=%s network=%s enabled=%v err=%v", a.ID, target.NetworkID, enabled, err)
		} else {
			s.logger.Info("run step OK auto=%s network=%s (%s) enabled=%v", a.ID, target.NetworkID, target.NetworkName, enabled)
		}
	}

	now := time.Now()
	s.store.UpdateLastRun(a.ID, &now)

	if len(errs) > 0 {
		return fmt.Errorf("partial failures: %s", strings.Join(errs, "; "))
	}
	s.logger.Info("run done auto=%s name=%q", a.ID, a.Name)
	return nil
}

// ──────────────────────────────────────────────
// Scheduling math
// ──────────────────────────────────────────────

// NextRunTime computes the next wall-clock time (>=from) the automation should fire.
func NextRunTime(a Automation, from time.Time) *time.Time {
	if a.Schedule == nil {
		return nil
	}
	sc := a.Schedule
	loc := time.Local
	if sc.Timezone != "" {
		if l, err := time.LoadLocation(sc.Timezone); err == nil {
			loc = l
		}
	}
	parts := strings.SplitN(sc.TimeHHMM, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	var hh, mm int
	fmt.Sscanf(parts[0], "%d", &hh)
	fmt.Sscanf(parts[1], "%d", &mm)

	endsOn := time.Time{}
	if sc.EndsOnDate != "" {
		t, err := time.ParseInLocation("2006-01-02", sc.EndsOnDate, loc)
		if err == nil {
			endsOn = t.AddDate(0, 0, 1)
		}
	}

	candidate := from.In(loc)
	for i := 0; i < 400; i++ {
		day := time.Date(candidate.Year(), candidate.Month(), candidate.Day(), hh, mm, 0, 0, loc)
		if !endsOn.IsZero() && day.After(endsOn) {
			return nil
		}
		wd := int(day.Weekday())
		skipDay := false
		if sc.SkipWeekends && (wd == 0 || wd == 6) {
			skipDay = true
		}
		if !skipDay && len(sc.DaysOfWeek) > 0 {
			skipDay = true
			for _, d := range sc.DaysOfWeek {
				if d == wd {
					skipDay = false
					break
				}
			}
		}
		if !skipDay && !day.Before(from) {
			t := day.UTC()
			return &t
		}
		candidate = candidate.AddDate(0, 0, 1)
	}
	return nil
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validateAutomation(a Automation) error {
	if strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if a.Type != TypeVlanDisable && a.Type != TypeVlanEnable && a.Type != TypeVlanToggle {
		return fmt.Errorf("invalid automation type %q", a.Type)
	}
	if len(a.VlanTargets) == 0 {
		return fmt.Errorf("at least one VLAN target is required")
	}
	if a.RunMode == ModeScheduled {
		if a.Schedule == nil {
			return fmt.Errorf("scheduled automations require a schedule")
		}
		if a.Schedule.TimeHHMM == "" {
			return fmt.Errorf("schedule time is required")
		}
	}
	return nil
}

// InferRunMode returns the effective run mode for the automation.
func InferRunMode(a Automation) RunMode {
	if a.RunMode == ModeScheduled {
		return ModeScheduled
	}
	if a.Schedule != nil && a.Schedule.TimeHHMM != "" {
		return ModeScheduled
	}
	return ModeManual
}

// sortNetworks returns networks sorted by name.
func sortNetworks(nets []Network) []Network {
	sort.Slice(nets, func(i, j int) bool {
		return nets[i].Name < nets[j].Name
	})
	return nets
}
