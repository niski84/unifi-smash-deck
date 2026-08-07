package unifideck

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ThreatKind distinguishes IDS/IPS events from local honeypot hits.
type ThreatKind string

const (
	ThreatKindIPS      ThreatKind = "ips"
	ThreatKindHoneypot ThreatKind = "honeypot"
)

// ThreatEvent is the unified representation for IDS/IPS alerts and honeypot hits.
type ThreatEvent struct {
	ID        string     `json:"id"`
	Kind      ThreatKind `json:"kind"`
	Timestamp int64      `json:"timestamp"` // Unix ms
	SrcIP     string     `json:"src_ip"`
	DstIP     string     `json:"dst_ip,omitempty"`
	SrcPort   int        `json:"src_port,omitempty"`
	DstPort   int        `json:"dst_port,omitempty"`
	Proto     string     `json:"proto,omitempty"`
	Severity  int        `json:"severity"` // 1=critical 2=major 3=minor
	Category  string     `json:"category,omitempty"`
	Signature string     `json:"signature,omitempty"`
	Action    string     `json:"action,omitempty"` // alert|drop|honeypot
	// Resolved from client tracker
	ClientMAC  string `json:"client_mac,omitempty"`
	ClientName string `json:"client_name,omitempty"`
	// Honeypot-specific
	HoneypotPort int    `json:"honeypot_port,omitempty"`
	VLAN         int    `json:"vlan,omitempty"`
	VLANName     string `json:"vlan_name,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	AgentName    string `json:"agent_name,omitempty"`
	BytesRecv    int    `json:"bytes_recv,omitempty"`
	BannerData   string `json:"banner_data,omitempty"` // first bytes the client sent
	Fingerprint  string `json:"fingerprint,omitempty"`
	Confidence   int    `json:"fingerprint_confidence,omitempty"`
	Evidence     string `json:"fingerprint_evidence,omitempty"`
	Persona      string `json:"persona,omitempty"`
	Assessment   string `json:"assessment,omitempty"`
}

const maxThreatEvents = 5000

type threatDisk struct {
	Events []*ThreatEvent `json:"events"`
}

// ThreatStore persists threat events to disk and deduplicates by ID.
// Events are kept newest-first, capped at maxThreatEvents.
type ThreatStore struct {
	mu     sync.Mutex
	path   string
	byID   map[string]*ThreatEvent
	events []*ThreatEvent // newest-first
}

// HoneypotSummary is the compact rolling-window view sent to alert consumers.
// It deliberately contains counts and fingerprints, never raw payloads.
type HoneypotSummary struct {
	WindowMinutes int            `json:"window_minutes"`
	Since         int64          `json:"since"`
	Until         int64          `json:"until"`
	EventCount    int            `json:"event_count"`
	ByFingerprint map[string]int `json:"by_fingerprint"`
	ByPort        map[int]int    `json:"by_port"`
	Latest        *ThreatEvent   `json:"latest,omitempty"`
}

func (ts *ThreatStore) HoneypotSummary(now time.Time, window time.Duration) HoneypotSummary {
	nowMS := now.UnixMilli()
	sinceMS := now.Add(-window).UnixMilli()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	sum := HoneypotSummary{
		WindowMinutes: int(window / time.Minute), Since: sinceMS, Until: nowMS,
		ByFingerprint: map[string]int{}, ByPort: map[int]int{},
	}
	for _, e := range ts.events {
		if e.Kind != ThreatKindHoneypot || e.Timestamp < sinceMS || e.Timestamp > nowMS {
			continue
		}
		sum.EventCount++
		fingerprint := e.Fingerprint
		if fingerprint == "" {
			fingerprint = e.Signature
		}
		sum.ByFingerprint[fingerprint]++
		sum.ByPort[e.DstPort]++
		if sum.Latest == nil {
			copy := *e
			sum.Latest = &copy
		}
	}
	return sum
}

func NewThreatStore(dataDir string) *ThreatStore {
	ts := &ThreatStore{
		path: filepath.Join(dataDir, "threat-events.json"),
		byID: make(map[string]*ThreatEvent),
	}
	ts.load()
	return ts
}

func (ts *ThreatStore) load() {
	raw, err := os.ReadFile(ts.path)
	if err != nil {
		return
	}
	var d threatDisk
	if err := json.Unmarshal(raw, &d); err != nil {
		log.Printf("[threats] load error: %v", err)
		return
	}
	for _, e := range d.Events {
		ts.byID[e.ID] = e
		ts.events = append(ts.events, e)
	}
	log.Printf("[threats] loaded %d event(s)", len(ts.events))
}

func (ts *ThreatStore) save() {
	d := threatDisk{Events: ts.events}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		log.Printf("[threats] marshal error: %v", err)
		return
	}
	if err := os.WriteFile(ts.path, b, 0644); err != nil {
		log.Printf("[threats] write error: %v", err)
	}
}

// Add inserts an event if not already known. Returns true if it was new.
func (ts *ThreatStore) Add(e ThreatEvent) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, exists := ts.byID[e.ID]; exists {
		return false
	}
	ptr := &e
	ts.byID[e.ID] = ptr
	// Prepend (newest-first)
	ts.events = append([]*ThreatEvent{ptr}, ts.events...)
	// Cap
	if len(ts.events) > maxThreatEvents {
		removed := ts.events[maxThreatEvents:]
		ts.events = ts.events[:maxThreatEvents]
		for _, r := range removed {
			delete(ts.byID, r.ID)
		}
	}
	ts.save()
	return true
}

// Recent returns up to n events, newest first.
func (ts *ThreatStore) Recent(n int) []ThreatEvent {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]ThreatEvent, 0, n)
	for i, e := range ts.events {
		if i >= n {
			break
		}
		out = append(out, *e)
	}
	return out
}

// LastTimestamp returns the Unix-ms timestamp of the most recent event, or 0.
func (ts *ThreatStore) LastTimestamp() int64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.events) == 0 {
		return 0
	}
	return ts.events[0].Timestamp
}

// Summary returns counts useful for the dashboard header.
func (ts *ThreatStore) Summary() (total, critical, honeypot int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	total = len(ts.events)
	for _, e := range ts.events {
		if e.Severity == 1 {
			critical++
		}
		if e.Kind == ThreatKindHoneypot {
			honeypot++
		}
	}
	return
}
