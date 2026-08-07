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

// ── Types ──────────────────────────────────────────────────────────────────────

// ConfigSnapshotSummary holds item counts for a config snapshot.
type ConfigSnapshotSummary struct {
	Networks int `json:"networks"`
	WLANs    int `json:"wlans"`
	Devices  int `json:"devices"`
	Policies int `json:"firewall_policies"`
	Forwards int `json:"port_forwards"`
}

// ConfigSnapshot is the metadata entry for one config snapshot (stored in index.json).
type ConfigSnapshot struct {
	ID        string                `json:"id"`
	Label     string                `json:"label"`
	TakenAt   time.Time             `json:"taken_at"`
	Trigger   string                `json:"trigger"` // "manual" | "scheduled"
	SizeBytes int64                 `json:"size_bytes"`
	Summary   ConfigSnapshotSummary `json:"summary"`
}

// ConfigSnapshotData is the full captured config (stored as data/{id}.json).
type ConfigSnapshotData struct {
	ID               string             `json:"id"`
	TakenAt          time.Time          `json:"taken_at"`
	Networks         []map[string]any   `json:"networks"`
	WLANs            []map[string]any   `json:"wlans"`
	Devices          []map[string]any   `json:"devices"`
	FirewallPolicies []map[string]any   `json:"firewall_policies"`
	PortForwards     []map[string]any   `json:"port_forwards"`
	IPSConfig        map[string]any     `json:"ips_config"`
	UDMBinaries      *UDMBinarySnapshot `json:"udm_binaries,omitempty"`
}

// ConfigSnapshotSchedule controls automatic snapshot capture.
type ConfigSnapshotSchedule struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"` // 0 = never
	RetainDays    int  `json:"retain_days"`    // 0 = keep all
}

// ── Diff types ─────────────────────────────────────────────────────────────────

// DiffChangeEntry is one field that changed between two snapshots.
type DiffChangeEntry struct {
	Key string `json:"key"`
	Old any    `json:"old"`
	New any    `json:"new"`
}

// DiffItem is an object that was added or removed.
type DiffItem struct {
	ID   string         `json:"id"`
	Name string         `json:"name,omitempty"`
	Data map[string]any `json:"data"`
}

// DiffChangedItem is an object that exists in both snapshots but differs.
type DiffChangedItem struct {
	ID      string            `json:"id"`
	Name    string            `json:"name,omitempty"`
	Changes []DiffChangeEntry `json:"changes"`
}

// DiffSection is the diff for one category (networks, WLANs, etc.).
type DiffSection struct {
	Name    string            `json:"name"`
	Added   []DiffItem        `json:"added"`
	Removed []DiffItem        `json:"removed"`
	Changed []DiffChangedItem `json:"changed"`
}

// ConfigSnapshotDiff holds the complete comparison between two snapshots.
type ConfigSnapshotDiff struct {
	SnapshotA    ConfigSnapshot `json:"snapshot_a"`
	SnapshotB    ConfigSnapshot `json:"snapshot_b"`
	Sections     []DiffSection  `json:"sections"`
	TotalAdded   int            `json:"total_added"`
	TotalRemoved int            `json:"total_removed"`
	TotalChanged int            `json:"total_changed"`
	Identical    bool           `json:"identical"`
}

// ── Store ──────────────────────────────────────────────────────────────────────

// ConfigSnapshotStore manages config snapshots on disk.
type ConfigSnapshotStore struct {
	mu       sync.Mutex
	dir      string
	index    []ConfigSnapshot
	schedule ConfigSnapshotSchedule
}

func NewConfigSnapshotStore(dataDir string) *ConfigSnapshotStore {
	s := &ConfigSnapshotStore{
		dir: filepath.Join(dataDir, "config-snapshots"),
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return s
	}
	s.loadIndex()
	s.loadSchedule()
	return s
}

func (s *ConfigSnapshotStore) indexPath() string    { return filepath.Join(s.dir, "index.json") }
func (s *ConfigSnapshotStore) schedulePath() string { return filepath.Join(s.dir, "schedule.json") }
func (s *ConfigSnapshotStore) dataPath(id string) string {
	return filepath.Join(s.dir, "data", id+".json")
}

func (s *ConfigSnapshotStore) loadIndex() {
	raw, err := os.ReadFile(s.indexPath())
	if err != nil {
		return
	}
	var idx []ConfigSnapshot
	if json.Unmarshal(raw, &idx) == nil {
		s.index = idx
	}
}

func (s *ConfigSnapshotStore) saveIndex() error {
	b, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath(), b, 0o644)
}

func (s *ConfigSnapshotStore) loadSchedule() {
	s.schedule = ConfigSnapshotSchedule{IntervalHours: 24, RetainDays: 30}
	raw, err := os.ReadFile(s.schedulePath())
	if err != nil {
		return
	}
	var sched ConfigSnapshotSchedule
	if json.Unmarshal(raw, &sched) == nil {
		s.schedule = sched
	}
}

func (s *ConfigSnapshotStore) GetSchedule() ConfigSnapshotSchedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.schedule
}

func (s *ConfigSnapshotStore) SaveSchedule(sched ConfigSnapshotSchedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(sched, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.schedulePath(), b, 0o644); err != nil {
		return err
	}
	s.schedule = sched
	return nil
}

func (s *ConfigSnapshotStore) List() []ConfigSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConfigSnapshot, len(s.index))
	copy(out, s.index)
	sort.Slice(out, func(i, j int) bool {
		return out[i].TakenAt.After(out[j].TakenAt)
	})
	return out
}

func (s *ConfigSnapshotStore) GetMeta(id string) *ConfigSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, snap := range s.index {
		if snap.ID == id {
			cp := snap
			return &cp
		}
	}
	return nil
}

func (s *ConfigSnapshotStore) Get(id string) (*ConfigSnapshotData, error) {
	raw, err := os.ReadFile(s.dataPath(id))
	if err != nil {
		return nil, fmt.Errorf("snapshot %s not found", id)
	}
	var data ConfigSnapshotData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("decode snapshot %s: %w", id, err)
	}
	return &data, nil
}

func (s *ConfigSnapshotStore) add(snap ConfigSnapshot, data *ConfigSnapshotData) error {
	if err := os.MkdirAll(filepath.Dir(s.dataPath(snap.ID)), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.dataPath(snap.ID), b, 0o644); err != nil {
		return err
	}
	snap.SizeBytes = int64(len(b))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.index = append(s.index, snap)
	return s.saveIndex()
}

func (s *ConfigSnapshotStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	var keep []ConfigSnapshot
	for _, snap := range s.index {
		if snap.ID == id {
			found = true
		} else {
			keep = append(keep, snap)
		}
	}
	if !found {
		return fmt.Errorf("snapshot %s not found", id)
	}
	s.index = keep
	if err := s.saveIndex(); err != nil {
		return err
	}
	_ = os.Remove(s.dataPath(id))
	return nil
}

func (s *ConfigSnapshotStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// Prune deletes snapshots older than retainDays. Returns number pruned.
func (s *ConfigSnapshotStore) Prune(retainDays int) int {
	if retainDays <= 0 {
		return 0
	}
	cutoff := time.Now().AddDate(0, 0, -retainDays)

	s.mu.Lock()
	defer s.mu.Unlock()

	var keep []ConfigSnapshot
	pruned := 0
	for _, snap := range s.index {
		if snap.TakenAt.Before(cutoff) {
			_ = os.Remove(s.dataPath(snap.ID))
			pruned++
		} else {
			keep = append(keep, snap)
		}
	}
	if pruned > 0 {
		s.index = keep
		_ = s.saveIndex()
	}
	return pruned
}

// ── Capture ────────────────────────────────────────────────────────────────────

// Capture fetches the current UniFi configuration and stores a snapshot.
// Errors fetching individual sections are silently swallowed so a partial
// snapshot is still useful (e.g. if Protect is not installed).
func (s *ConfigSnapshotStore) Capture(ctx context.Context, c *UnifiClient, label, trigger string, appCfg ...AppConfig) (*ConfigSnapshot, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("unifi not configured")
	}

	now := time.Now().UTC()
	data := &ConfigSnapshotData{TakenAt: now}

	if v, err := c.ListNetworksRaw(ctx); err == nil {
		data.Networks = v
	}
	if v, err := c.ListWLANsRaw(ctx); err == nil {
		data.WLANs = v
	}
	if v, err := c.ListDevicesRaw(ctx); err == nil {
		data.Devices = v
	}
	if v, err := c.ListFirewallPolicies(ctx); err == nil {
		data.FirewallPolicies = v
	}
	if v, err := c.ListPortForwards(ctx); err == nil {
		data.PortForwards = v
	}
	if v, err := c.GetIPSSettings(ctx); err == nil {
		data.IPSConfig = v
	}
	// If SSH credentials were provided, capture UDM binary hashes + top processes.
	if len(appCfg) > 0 && appCfg[0].SSHHost != "" {
		if snap, err := CaptureUDMBinarySnapshot(ctx, appCfg[0]); err == nil && snap != nil {
			data.UDMBinaries = snap
		}
	}

	id := fmt.Sprintf("cs_%s", now.Format("20060102_150405"))
	data.ID = id

	snap := ConfigSnapshot{
		ID:      id,
		Label:   label,
		TakenAt: now,
		Trigger: trigger,
		Summary: ConfigSnapshotSummary{
			Networks: len(data.Networks),
			WLANs:    len(data.WLANs),
			Devices:  len(data.Devices),
			Policies: len(data.FirewallPolicies),
			Forwards: len(data.PortForwards),
		},
	}

	if err := s.add(snap, data); err != nil {
		return nil, fmt.Errorf("save snapshot: %w", err)
	}
	return &snap, nil
}

// ── Diff ───────────────────────────────────────────────────────────────────────

// Diff compares two snapshots by ID and returns a structured diff.
func (s *ConfigSnapshotStore) Diff(idA, idB string) (*ConfigSnapshotDiff, error) {
	dataA, err := s.Get(idA)
	if err != nil {
		return nil, fmt.Errorf("snapshot A: %w", err)
	}
	dataB, err := s.Get(idB)
	if err != nil {
		return nil, fmt.Errorf("snapshot B: %w", err)
	}
	metaA := s.GetMeta(idA)
	metaB := s.GetMeta(idB)
	if metaA == nil {
		return nil, fmt.Errorf("metadata not found for %s", idA)
	}
	if metaB == nil {
		return nil, fmt.Errorf("metadata not found for %s", idB)
	}

	result := &ConfigSnapshotDiff{SnapshotA: *metaA, SnapshotB: *metaB}

	for _, sec := range []struct {
		name string
		a, b []map[string]any
	}{
		{"Networks", dataA.Networks, dataB.Networks},
		{"WLANs", dataA.WLANs, dataB.WLANs},
		{"Firewall Policies", dataA.FirewallPolicies, dataB.FirewallPolicies},
		{"Port Forwards", dataA.PortForwards, dataB.PortForwards},
		{"Devices", dataA.Devices, dataB.Devices},
	} {
		section := diffCollection(sec.name, sec.a, sec.b)
		result.TotalAdded += len(section.Added)
		result.TotalRemoved += len(section.Removed)
		result.TotalChanged += len(section.Changed)
		if len(section.Added)+len(section.Removed)+len(section.Changed) > 0 {
			result.Sections = append(result.Sections, section)
		}
	}
	result.Identical = result.TotalAdded == 0 && result.TotalRemoved == 0 && result.TotalChanged == 0
	return result, nil
}

// diffCollection diffs two collections of objects keyed by _id or id.
func diffCollection(name string, a, b []map[string]any) DiffSection {
	sec := DiffSection{Name: name}
	mapA := indexByID(a)
	mapB := indexByID(b)

	for id, item := range mapB {
		if _, ok := mapA[id]; !ok {
			sec.Added = append(sec.Added, DiffItem{ID: id, Name: objDisplayName(item), Data: item})
		}
	}
	for id, item := range mapA {
		if _, ok := mapB[id]; !ok {
			sec.Removed = append(sec.Removed, DiffItem{ID: id, Name: objDisplayName(item), Data: item})
		}
	}
	for id, itemA := range mapA {
		if itemB, ok := mapB[id]; ok {
			if changes := fieldDiff(itemA, itemB); len(changes) > 0 {
				sec.Changed = append(sec.Changed, DiffChangedItem{
					ID:      id,
					Name:    objDisplayName(itemA),
					Changes: changes,
				})
			}
		}
	}
	sort.Slice(sec.Added, func(i, j int) bool { return sec.Added[i].Name < sec.Added[j].Name })
	sort.Slice(sec.Removed, func(i, j int) bool { return sec.Removed[i].Name < sec.Removed[j].Name })
	sort.Slice(sec.Changed, func(i, j int) bool { return sec.Changed[i].Name < sec.Changed[j].Name })
	return sec
}

// indexByID maps objects by _id, id, or a name-based fallback key.
func indexByID(items []map[string]any) map[string]map[string]any {
	m := make(map[string]map[string]any, len(items))
	for _, item := range items {
		id := ""
		if v, ok := item["_id"].(string); ok && v != "" {
			id = v
		} else if v, ok := item["id"].(string); ok && v != "" {
			id = v
		} else if v, ok := item["name"].(string); ok && v != "" {
			id = "name:" + v
		} else {
			b, _ := json.Marshal(item)
			id = fmt.Sprintf("json:%x", b[:min(8, len(b))])
		}
		m[id] = item
	}
	return m
}

// objDisplayName returns a human-readable label for a config object.
func objDisplayName(item map[string]any) string {
	for _, k := range []string{"name", "description", "_id", "id"} {
		if v, ok := item[k].(string); ok && v != "" {
			return v
		}
	}
	return "(unnamed)"
}

// noiseFields are excluded from change detection (counters, timestamps, site metadata).
var noiseFields = map[string]bool{
	// General noise
	"site_id":              true,
	"uptime":               true,
	"last_seen":            true,
	"latest_assoc_time":    true,
	"assoc_time":           true,
	"bytes":                true,
	"rx_bytes":             true,
	"tx_bytes":             true,
	"satisfaction":         true,
	"satisfaction_reason":  true,
	"bytes_d":              true,
	"tx_bytes_d":           true,
	"rx_bytes_d":           true,
	"tx_packets_d":         true,
	"rx_packets_d":         true,
	"disconnect_timestamp": true,
	"last_ip":              true,
	// Device runtime stats — change every few seconds, not config-relevant
	"_uptime":              true,
	"next_interval":        true,
	"port_table":           true, // per-port byte/packet counters
	"stat":                 true, // aggregate traffic counters
	"sys_stats":            true, // loadavg, cpu, mem
	"bytes-d":              true,
	"bytes-r":              true,
	"uplink":               true, // runtime uplink connection info
	"temperatures":         true,
	"fan_level":            true,
	"general_temperature":  true,
	"cpu_temp":             true,
	"connect_request_ip":   true,
	"connect_request_port": true,
	"system-stats":         true, // cpu/mem/uptime — changes every poll cycle
}

// fieldDiff returns per-field changes between two objects, skipping noise fields.
func fieldDiff(a, b map[string]any) []DiffChangeEntry {
	allKeys := make(map[string]bool)
	for k := range a {
		allKeys[k] = true
	}
	for k := range b {
		allKeys[k] = true
	}

	sorted := make([]string, 0, len(allKeys))
	for k := range allKeys {
		if !noiseFields[k] {
			sorted = append(sorted, k)
		}
	}
	sort.Strings(sorted)

	var changes []DiffChangeEntry
	for _, k := range sorted {
		aj, _ := json.Marshal(a[k])
		bj, _ := json.Marshal(b[k])
		if string(aj) != string(bj) {
			changes = append(changes, DiffChangeEntry{Key: k, Old: a[k], New: b[k]})
		}
	}
	return changes
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

// ConfigSnapshotScheduler auto-captures config snapshots on an interval.
type ConfigSnapshotScheduler struct {
	store       *ConfigSnapshotStore
	logger      *AutomationLogger
	clientFn    func() *UnifiClient
	cfgFn       func() AppConfig
	stopCh      chan struct{}
	lastCapture time.Time
}

func NewConfigSnapshotScheduler(store *ConfigSnapshotStore, logger *AutomationLogger, clientFn func() *UnifiClient, cfgFn func() AppConfig) *ConfigSnapshotScheduler {
	return &ConfigSnapshotScheduler{
		store:    store,
		logger:   logger,
		clientFn: clientFn,
		cfgFn:    cfgFn,
		stopCh:   make(chan struct{}),
	}
}

func (s *ConfigSnapshotScheduler) Start() {
	go s.run()
}

func (s *ConfigSnapshotScheduler) Stop() {
	close(s.stopCh)
}

func (s *ConfigSnapshotScheduler) run() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			sched := s.store.GetSchedule()
			if !sched.Enabled || sched.IntervalHours <= 0 {
				continue
			}
			next := s.lastCapture.Add(time.Duration(sched.IntervalHours) * time.Hour)
			if time.Now().Before(next) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			c := s.clientFn()
			appCfg := s.cfgFn()
			snap, err := s.store.Capture(ctx, c, "", "scheduled", appCfg)
			cancel()
			if err != nil {
				s.logger.Warn("config snapshot auto-capture failed: %v", err)
				continue
			}
			s.lastCapture = time.Now()
			s.logger.Info("config snapshot captured id=%s nets=%d policies=%d",
				snap.ID, snap.Summary.Networks, snap.Summary.Policies)
			if sched.RetainDays > 0 {
				if n := s.store.Prune(sched.RetainDays); n > 0 {
					s.logger.Info("config snapshot pruned %d old", n)
				}
			}
		}
	}
}
