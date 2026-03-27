package unifideck

import (
	"context"
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
// Schedule types
// ──────────────────────────────────────────────

// SnapshotRule defines one automatic-capture schedule.
// A single installation can have any number of rules, each targeting
// different cameras and/or different cadences.
type SnapshotRule struct {
	ID    string `json:"id"`
	// Enabled lets users pause a rule without deleting it.
	Enabled bool   `json:"enabled"`
	Label   string `json:"label,omitempty"`

	// CameraIDs lists which cameras this rule applies to.
	// An empty/nil slice means "all connected cameras".
	CameraIDs []string `json:"camera_ids"`

	// Mode is "times" (fire at specific HH:MM each day) or
	// "interval" (fire every IntervalMin minutes).
	Mode string `json:"mode"` // "times" | "interval"

	// Times mode: one or more "HH:MM" strings in 24-hour format.
	Times []string `json:"times,omitempty"`

	// Interval mode: minutes between captures.  Minimum 1.
	IntervalMin int `json:"interval_min,omitempty"`

	// Timezone is the IANA location name (e.g. "America/New_York").
	// Only used for Times mode.  Defaults to UTC.
	Timezone string `json:"timezone,omitempty"`
}

// SnapshotScheduleConfig is the top-level schedule document.
type SnapshotScheduleConfig struct {
	Rules      []SnapshotRule `json:"rules"`
	RetainDays int            `json:"retain_days"` // 0 = keep forever
	// DayTimezone is an IANA zone name (e.g. America/New_York) used to assign each
	// snapshot to a calendar day for the Timeline UI. Empty means UTC.
	DayTimezone string `json:"day_timezone,omitempty"`
}

// ──────────────────────────────────────────────
// Snapshot record types
// ──────────────────────────────────────────────

// SnapshotRecord is metadata for one saved snapshot.
type SnapshotRecord struct {
	ID         string    `json:"id"`
	CameraID   string    `json:"camera_id"`
	CameraName string    `json:"camera_name"`
	TakenAt    time.Time `json:"taken_at"`
	SizeBytes  int64     `json:"size_bytes"`
}

// SnapshotRecordAPI is the JSON shape for GET /api/snapshots — includes day_key for timeline filtering.
type SnapshotRecordAPI struct {
	ID         string    `json:"id"`
	CameraID   string    `json:"camera_id"`
	CameraName string    `json:"camera_name"`
	TakenAt    time.Time `json:"taken_at"`
	DayKey     string    `json:"day_key"` // YYYY-MM-DD in DayTimezone
	SizeBytes  int64     `json:"size_bytes"`
}

// CameraSnapshotGroup groups snapshots by camera for the API response.
type CameraSnapshotGroup struct {
	CameraID   string           `json:"camera_id"`
	CameraName string           `json:"camera_name"`
	Snapshots  []SnapshotRecord `json:"snapshots"`
}

// CameraSnapshotGroupAPI is used for GET /api/snapshots (snapshots include day_key).
type CameraSnapshotGroupAPI struct {
	CameraID   string              `json:"camera_id"`
	CameraName string              `json:"camera_name"`
	Snapshots  []SnapshotRecordAPI `json:"snapshots"`
}

// ──────────────────────────────────────────────
// SnapshotStore
// ──────────────────────────────────────────────

type SnapshotStore struct {
	mu          sync.RWMutex
	dir         string
	indexPath   string
	schedPath   string
	records     []SnapshotRecord
	schedConfig SnapshotScheduleConfig
}

var defaultScheduleConfig = SnapshotScheduleConfig{
	RetainDays: 30,
	Rules: []SnapshotRule{
		{
			ID:      "default",
			Enabled: true,
			Label:   "Daily (10:30 AM + 7:00 PM)",
			Mode:    "times",
			Times:   []string{"10:30", "19:00"},
		},
	},
}

func NewSnapshotStore(dataDir string) *SnapshotStore {
	dir := filepath.Join(dataDir, "snapshots")
	s := &SnapshotStore{
		dir:         dir,
		indexPath:   filepath.Join(dir, "index.json"),
		schedPath:   filepath.Join(dataDir, "snapshots-schedule.json"),
		schedConfig: defaultScheduleConfig,
	}
	_ = os.MkdirAll(dir, 0o755)
	s.loadSchedule()
	s.loadIndex()
	return s
}

// loadSchedule reads the on-disk schedule, migrating the old flat format if needed.
func (s *SnapshotStore) loadSchedule() {
	raw, err := os.ReadFile(s.schedPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unifideck] WARNING: could not read snapshot schedule: %v\n", err)
		}
		return
	}

	// New format has a top-level "rules" array.
	var cfg SnapshotScheduleConfig
	if err := json.Unmarshal(raw, &cfg); err == nil && cfg.Rules != nil {
		s.schedConfig = cfg
		return
	}

	// Migrate legacy format: { enabled, times, timezone, retain_days }.
	var old struct {
		Enabled    bool     `json:"enabled"`
		Times      []string `json:"times"`
		Timezone   string   `json:"timezone"`
		RetainDays int      `json:"retain_days"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		fmt.Fprintf(os.Stderr, "[unifideck] WARNING: snapshot schedule corrupt: %v\n", err)
		return
	}
	s.schedConfig = SnapshotScheduleConfig{
		RetainDays: old.RetainDays,
		Rules: []SnapshotRule{{
			ID:       "migrated",
			Enabled:  old.Enabled,
			Label:    "Imported schedule",
			Mode:     "times",
			Times:    old.Times,
			Timezone: old.Timezone,
		}},
	}
	fmt.Fprintf(os.Stderr, "[unifideck] INFO: migrated legacy snapshot schedule to new format\n")
}

func (s *SnapshotStore) SaveScheduleConfig(cfg SnapshotScheduleConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedConfig = cfg
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.schedPath, b, 0o644)
}

func (s *SnapshotStore) GetScheduleConfig() SnapshotScheduleConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.schedConfig
}

func (s *SnapshotStore) loadIndex() {
	raw, err := os.ReadFile(s.indexPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unifideck] WARNING: could not read snapshot index: %v\n", err)
		}
		return
	}
	var records []SnapshotRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		fmt.Fprintf(os.Stderr, "[unifideck] WARNING: snapshot index corrupt: %v\n", err)
		return
	}
	s.records = records
}

func (s *SnapshotStore) saveIndex() error {
	b, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath, b, 0o644)
}

// ImagePath returns the absolute path to a snapshot image file.
func (s *SnapshotStore) ImagePath(id string) string {
	return filepath.Join(s.dir, id+".jpg")
}

// Add saves a snapshot image and appends its record to the index.
func (s *SnapshotStore) Add(camID, camName string, data []byte, takenAt time.Time) (SnapshotRecord, error) {
	pfx := camID
	if len(pfx) > 8 {
		pfx = pfx[:8]
	}
	id := fmt.Sprintf("%s_%d", pfx, takenAt.UnixMilli())
	rec := SnapshotRecord{
		ID:         id,
		CameraID:   camID,
		CameraName: camName,
		TakenAt:    takenAt,
		SizeBytes:  int64(len(data)),
	}
	if err := os.WriteFile(s.ImagePath(id), data, 0o644); err != nil {
		return SnapshotRecord{}, fmt.Errorf("write snapshot image: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return rec, s.saveIndex()
}

// GroupedByCamera returns all records grouped by camera, oldest-first within each group.
func (s *SnapshotStore) GroupedByCamera() []CameraSnapshotGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]int)
	var groups []CameraSnapshotGroup
	for _, r := range s.records {
		if idx, ok := seen[r.CameraID]; ok {
			groups[idx].Snapshots = append(groups[idx].Snapshots, r)
		} else {
			seen[r.CameraID] = len(groups)
			groups = append(groups, CameraSnapshotGroup{
				CameraID:   r.CameraID,
				CameraName: r.CameraName,
				Snapshots:  []SnapshotRecord{r},
			})
		}
	}
	for i := range groups {
		sort.Slice(groups[i].Snapshots, func(a, b int) bool {
			return groups[i].Snapshots[a].TakenAt.Before(groups[i].Snapshots[b].TakenAt)
		})
	}
	return groups
}

// resolveDayLocation returns the timezone used to bucket snapshots into calendar days.
func resolveDayLocation(tz string) *time.Location {
	if strings.TrimSpace(tz) == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

// GroupedByCameraAPI returns the same grouping as GroupedByCamera but with each
// snapshot annotated with day_key (YYYY-MM-DD in the configured DayTimezone).
func (s *SnapshotStore) GroupedByCameraAPI() []CameraSnapshotGroupAPI {
	cfg := s.GetScheduleConfig()
	loc := resolveDayLocation(cfg.DayTimezone)
	groups := s.GroupedByCamera()
	out := make([]CameraSnapshotGroupAPI, len(groups))
	for i, g := range groups {
		out[i].CameraID = g.CameraID
		out[i].CameraName = g.CameraName
		out[i].Snapshots = make([]SnapshotRecordAPI, len(g.Snapshots))
		for j, r := range g.Snapshots {
			out[i].Snapshots[j] = SnapshotRecordAPI{
				ID:         r.ID,
				CameraID:   r.CameraID,
				CameraName: r.CameraName,
				TakenAt:    r.TakenAt,
				DayKey:     r.TakenAt.In(loc).Format("2006-01-02"),
				SizeBytes:  r.SizeBytes,
			}
		}
	}
	return out
}

// Get returns a snapshot record by ID.
func (s *SnapshotStore) Get(id string) (SnapshotRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.records {
		if r.ID == id {
			return r, true
		}
	}
	return SnapshotRecord{}, false
}

// Delete removes a snapshot record and its image file.
func (s *SnapshotStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.records {
		if r.ID == id {
			_ = os.Remove(s.ImagePath(r.ID))
			s.records = append(s.records[:i], s.records[i+1:]...)
			return s.saveIndex()
		}
	}
	return fmt.Errorf("snapshot %s not found", id)
}

// PruneOld deletes snapshots older than RetainDays (no-op if RetainDays <= 0).
func (s *SnapshotStore) PruneOld() {
	cfg := s.GetScheduleConfig()
	if cfg.RetainDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -cfg.RetainDays)
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []SnapshotRecord
	for _, r := range s.records {
		if r.TakenAt.Before(cutoff) {
			_ = os.Remove(s.ImagePath(r.ID))
		} else {
			kept = append(kept, r)
		}
	}
	if len(kept) != len(s.records) {
		s.records = kept
		_ = s.saveIndex()
	}
}

// Count returns the total number of stored snapshots.
func (s *SnapshotStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// ──────────────────────────────────────────────
// SnapshotScheduler
// ──────────────────────────────────────────────

// SnapshotScheduler fires rules on their configured cadence and captures
// JPEGs from the matching cameras.
type SnapshotScheduler struct {
	store      *SnapshotStore
	logger     *AutomationLogger
	clientFunc func() *UnifiClient
	stop       chan struct{}
	mu         sync.Mutex
	// lastFired tracks the last fire time per rule+slot key to prevent
	// duplicate triggers within the same minute (times mode) or before
	// the interval has elapsed (interval mode).
	lastFired map[string]time.Time
}

func NewSnapshotScheduler(store *SnapshotStore, logger *AutomationLogger, clientFunc func() *UnifiClient) *SnapshotScheduler {
	return &SnapshotScheduler{
		store:      store,
		logger:     logger,
		clientFunc: clientFunc,
		stop:       make(chan struct{}),
		lastFired:  make(map[string]time.Time),
	}
}

func (ss *SnapshotScheduler) Start() { go ss.run() }
func (ss *SnapshotScheduler) Stop()  { close(ss.stop) }

func (ss *SnapshotScheduler) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ss.stop:
			return
		case now := <-ticker.C:
			ss.checkAndFire(now)
		}
	}
}

func (ss *SnapshotScheduler) checkAndFire(now time.Time) {
	cfg := ss.store.GetScheduleConfig()
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		switch rule.Mode {
		case "interval":
			if rule.IntervalMin < 1 {
				continue
			}
			ss.mu.Lock()
			last := ss.lastFired[rule.ID]
			elapsed := now.Sub(last)
			shouldFire := last.IsZero() || elapsed >= time.Duration(rule.IntervalMin)*time.Minute
			if shouldFire {
				ss.lastFired[rule.ID] = now
			}
			ss.mu.Unlock()
			if shouldFire {
				go ss.captureForRule(rule, now)
			}

		default: // "times"
			loc := time.UTC
			if rule.Timezone != "" {
				if l, err := time.LoadLocation(rule.Timezone); err == nil {
					loc = l
				}
			}
			hhmm := now.In(loc).Format("15:04")
			for _, t := range rule.Times {
				if t != hhmm {
					continue
				}
				key := rule.ID + "_" + t
				ss.mu.Lock()
				shouldFire := now.Sub(ss.lastFired[key]) >= 2*time.Minute
				if shouldFire {
					ss.lastFired[key] = now
				}
				ss.mu.Unlock()
				if shouldFire {
					go ss.captureForRule(rule, now)
				}
				break
			}
		}
	}
}

// CaptureNow triggers an immediate snapshot.
// Pass a non-empty cameraIDs slice to limit capture to specific cameras;
// pass nil or empty to capture all connected cameras.
func (ss *SnapshotScheduler) CaptureNow(cameraIDs []string) {
	rule := SnapshotRule{
		ID:        "manual",
		Enabled:   true,
		Label:     "Manual",
		CameraIDs: cameraIDs,
		Mode:      "times",
	}
	go ss.captureForRule(rule, time.Now())
}

func (ss *SnapshotScheduler) captureForRule(rule SnapshotRule, scheduledAt time.Time) {
	c := ss.clientFunc()
	if !c.IsConfigured() {
		ss.logger.Warn("snapshot capture skipped: UniFi not configured")
		return
	}
	// Long timeout: many cameras × stagger + 429 retry backoffs can exceed 3 minutes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfgTZ := ss.store.GetScheduleConfig().DayTimezone
	dayLoc := resolveDayLocation(cfgTZ)

	label := rule.Label
	if label == "" {
		label = rule.ID
	}
	ss.logger.Info("snapshot run start rule=%q scheduled_at=%s day_tz=%q",
		label, scheduledAt.Format(time.RFC3339), cfgTZ)

	cameras, err := c.ListCameras(ctx)
	if err != nil {
		ss.logger.Error("snapshot capture: list cameras: %v", err)
		return
	}

	ss.store.PruneOld()

	// Build a fast lookup set for camera ID filtering.
	camSet := make(map[string]bool, len(rule.CameraIDs))
	for _, id := range rule.CameraIDs {
		camSet[id] = true
	}
	filterCams := len(rule.CameraIDs) > 0

	// Stagger + standard quality:
	// - highQuality=false uses a single HTTP GET per camera (HQ mode can issue two
	//   back-to-back requests when the first fails, which doubles load and blows
	//   Protect's ~10 req/s limit when combined with the live-view grid).
	// - 1.5 s between cameras keeps total snapshot traffic well under the limit
	//   even if the UI is also refreshing the live grid.
	const staggerDelay = 1500 * time.Millisecond
	const max429Retries = 4
	retryWaits := []time.Duration{3 * time.Second, 5 * time.Second, 8 * time.Second, 12 * time.Second}

	var succeeded, failed int
	var minCap, maxCap time.Time
	var haveCap bool
	first := true
	for _, cam := range cameras {
		if cam.State != "CONNECTED" && !cam.IsConnected {
			continue
		}
		if filterCams && !camSet[cam.ID] {
			continue
		}
		// Skip the delay before the very first capture.
		if !first {
			select {
			case <-ctx.Done():
				ss.logger.Warn("snapshot capture context cancelled during stagger")
				return
			case <-time.After(staggerDelay):
			}
		}
		first = false

		// Archived timeline snapshots: standard quality only (one request each).
		var data []byte
		var err error
	attemptLoop:
		for attempt := 0; attempt <= max429Retries; attempt++ {
			if attempt > 0 {
				w := retryWaits[attempt-1]
				if attempt-1 >= len(retryWaits) {
					w = retryWaits[len(retryWaits)-1]
				}
				ss.logger.Warn("snapshot 429 backoff cam=%q attempt=%d wait=%s", cam.Name, attempt, w)
				select {
				case <-ctx.Done():
					ss.logger.Warn("snapshot capture context cancelled during 429 backoff")
					return
				case <-time.After(w):
				}
			}
			data, _, err = c.CameraSnapshot(ctx, cam.ID, false)
			if err == nil {
				break attemptLoop
			}
			if !strings.Contains(err.Error(), "429") {
				break attemptLoop
			}
			if attempt == max429Retries {
				break
			}
		}
		if err != nil {
			ss.logger.Warn("snapshot capture failed cam=%q err=%v", cam.Name, err)
			failed++
			continue
		}
		// Stamp each file at actual capture time (after stagger) so the timeline
		// shows real clock spread — not one identical time for every camera in the run.
		capAt := time.Now()
		if _, err := ss.store.Add(cam.ID, cam.Name, data, capAt); err != nil {
			ss.logger.Error("snapshot store failed cam=%q err=%v", cam.Name, err)
			failed++
			continue
		}
		succeeded++
		if !haveCap {
			minCap, maxCap, haveCap = capAt, capAt, true
		} else {
			if capAt.Before(minCap) {
				minCap = capAt
			}
			if capAt.After(maxCap) {
				maxCap = capAt
			}
		}
	}

	if succeeded > 0 {
		ss.logger.Info("snapshot rule=%q ok=%d fail=%d span_utc=%s..%s span_day=%s..%s (day_tz=%q)",
			label, succeeded, failed,
			minCap.Format(time.RFC3339), maxCap.Format(time.RFC3339),
			minCap.In(dayLoc).Format("2006-01-02"), maxCap.In(dayLoc).Format("2006-01-02"), cfgTZ)
	} else {
		ss.logger.Info("snapshot rule=%q ok=%d fail=%d", label, succeeded, failed)
	}
}
