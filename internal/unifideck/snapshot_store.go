package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────

// SnapshotSchedule defines when automatic snapshots are taken.
type SnapshotSchedule struct {
	Enabled    bool     `json:"enabled"`
	Times      []string `json:"times"`              // ["10:30", "19:00"] – 24-hour HH:MM in Timezone
	Timezone   string   `json:"timezone,omitempty"` // IANA, e.g. "America/New_York"
	RetainDays int      `json:"retain_days"`        // 0 = keep forever
}

// SnapshotRecord is metadata for one saved snapshot.
type SnapshotRecord struct {
	ID         string    `json:"id"`
	CameraID   string    `json:"camera_id"`
	CameraName string    `json:"camera_name"`
	TakenAt    time.Time `json:"taken_at"`
	SizeBytes  int64     `json:"size_bytes"`
}

// CameraSnapshotGroup groups snapshots by camera for the API response.
type CameraSnapshotGroup struct {
	CameraID   string           `json:"camera_id"`
	CameraName string           `json:"camera_name"`
	Snapshots  []SnapshotRecord `json:"snapshots"`
}

// ──────────────────────────────────────────────
// SnapshotStore
// ──────────────────────────────────────────────

type SnapshotStore struct {
	mu        sync.RWMutex
	dir       string // base image directory, e.g. data/snapshots
	indexPath string
	schedPath string
	records   []SnapshotRecord
	schedule  SnapshotSchedule
}

var defaultSchedule = SnapshotSchedule{
	Enabled:    true,
	Times:      []string{"10:30", "19:00"},
	RetainDays: 30,
}

func NewSnapshotStore(dataDir string) *SnapshotStore {
	dir := filepath.Join(dataDir, "snapshots")
	s := &SnapshotStore{
		dir:       dir,
		indexPath: filepath.Join(dir, "index.json"),
		schedPath: filepath.Join(dataDir, "snapshots-schedule.json"),
		schedule:  defaultSchedule,
	}
	_ = os.MkdirAll(dir, 0o755)
	s.loadSchedule()
	s.loadIndex()
	return s
}

func (s *SnapshotStore) loadSchedule() {
	raw, err := os.ReadFile(s.schedPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unifideck] WARNING: could not read snapshot schedule: %v\n", err)
		}
		return
	}
	var sc SnapshotSchedule
	if err := json.Unmarshal(raw, &sc); err != nil {
		fmt.Fprintf(os.Stderr, "[unifideck] WARNING: snapshot schedule corrupt: %v\n", err)
		return
	}
	s.schedule = sc
}

func (s *SnapshotStore) SaveSchedule(sc SnapshotSchedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedule = sc
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.schedPath, b, 0o644)
}

func (s *SnapshotStore) GetSchedule() SnapshotSchedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.schedule
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
	// ID format: first 8 chars of camID + unix millis keeps it sortable and unique.
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

	// Collect camera order (preserve first-seen order).
	seen := make(map[string]int) // cameraID -> index in groups
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
	// Sort each group: oldest first.
	for i := range groups {
		sort.Slice(groups[i].Snapshots, func(a, b int) bool {
			return groups[i].Snapshots[a].TakenAt.Before(groups[i].Snapshots[b].TakenAt)
		})
	}
	return groups
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
	sc := s.GetSchedule()
	if sc.RetainDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -sc.RetainDays)
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

// SnapshotScheduler fires at the configured HH:MM times and captures
// a JPEG from every connected Protect camera.
type SnapshotScheduler struct {
	store      *SnapshotStore
	logger     *AutomationLogger
	clientFunc func() *UnifiClient
	stop       chan struct{}
	mu         sync.Mutex
	lastFired  map[string]time.Time // "HH:MM" -> last fire time to avoid duplicate triggers
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
	// Check every 30 seconds; fires at the first tick that matches a HH:MM slot.
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
	sc := ss.store.GetSchedule()
	if !sc.Enabled || len(sc.Times) == 0 {
		return
	}
	loc := time.UTC
	if sc.Timezone != "" {
		if l, err := time.LoadLocation(sc.Timezone); err == nil {
			loc = l
		}
	}
	hhmm := now.In(loc).Format("15:04")

	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, t := range sc.Times {
		if t == hhmm {
			// Guard: fire at most once per 2-minute window per slot.
			if now.Sub(ss.lastFired[t]) < 2*time.Minute {
				continue
			}
			ss.lastFired[t] = now
			go ss.captureAll(now)
		}
	}
}

// CaptureNow triggers an immediate capture outside the schedule.
func (ss *SnapshotScheduler) CaptureNow() {
	go ss.captureAll(time.Now())
}

func (ss *SnapshotScheduler) captureAll(takenAt time.Time) {
	c := ss.clientFunc()
	if !c.IsConfigured() {
		ss.logger.Warn("snapshot capture skipped: UniFi not configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cameras, err := c.ListCameras(ctx)
	if err != nil {
		ss.logger.Error("snapshot capture: list cameras: %v", err)
		return
	}

	ss.store.PruneOld()

	var succeeded, failed int
	for _, cam := range cameras {
		if cam.State != "CONNECTED" && !cam.IsConnected {
			continue
		}
		data, _, err := c.CameraSnapshot(ctx, cam.ID, true)
		if err != nil {
			ss.logger.Warn("snapshot capture failed cam=%q err=%v", cam.Name, err)
			failed++
			continue
		}
		if _, err := ss.store.Add(cam.ID, cam.Name, data, takenAt); err != nil {
			ss.logger.Error("snapshot store failed cam=%q err=%v", cam.Name, err)
			failed++
			continue
		}
		succeeded++
	}
	ss.logger.Info("snapshot capture complete ok=%d fail=%d time=%s",
		succeeded, failed, takenAt.In(func() *time.Location {
			sc := ss.store.GetSchedule()
			if sc.Timezone != "" {
				if l, err := time.LoadLocation(sc.Timezone); err == nil {
					return l
				}
			}
			return time.Local
		}()).Format("15:04 MST"))
}
