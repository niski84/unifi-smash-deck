package unifideck

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TrackedClient is a device entry persisted by ClientTracker.
type TrackedClient struct {
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname,omitempty"`
	Name      string `json:"name,omitempty"`
	IP        string `json:"ip,omitempty"`
	FirstSeen int64  `json:"first_seen"` // Unix ms
	LastSeen  int64  `json:"last_seen"`  // Unix ms
	IsWired   bool   `json:"is_wired"`
}

type clientTrackerDisk struct {
	Known map[string]*TrackedClient `json:"known"`
}

// ClientTracker keeps a persistent record of all seen client devices and
// detects new ones by diffing live polls against the stored history.
type ClientTracker struct {
	mu           sync.Mutex
	path         string
	known        map[string]*TrackedClient // keyed by MAC
	lastSnapshot time.Time
	stopCh       chan struct{}
}

// NewClientTracker creates a tracker backed by a JSON file in dataDir.
func NewClientTracker(dataDir string) *ClientTracker {
	ct := &ClientTracker{
		path:   filepath.Join(dataDir, "client-history.json"),
		known:  make(map[string]*TrackedClient),
		stopCh: make(chan struct{}),
	}
	ct.load()
	return ct
}

func (ct *ClientTracker) load() {
	data, err := os.ReadFile(ct.path)
	if err != nil {
		return // file not yet written — start with empty history
	}
	var d clientTrackerDisk
	if err := json.Unmarshal(data, &d); err != nil {
		log.Printf("[unifideck] client-tracker: parse error: %v", err)
		return
	}
	if d.Known != nil {
		ct.known = d.Known
	}
	log.Printf("[unifideck] client-tracker: loaded %d known devices", len(ct.known))
}

func (ct *ClientTracker) save() {
	d := clientTrackerDisk{Known: ct.known}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		log.Printf("[unifideck] client-tracker: marshal error: %v", err)
		return
	}
	if err := os.WriteFile(ct.path, data, 0644); err != nil {
		log.Printf("[unifideck] client-tracker: write error: %v", err)
	}
}

// Snapshot diffs the current live client list against stored history.
// New entries are added with FirstSeen = now; existing entries have
// LastSeen and mutable fields (hostname, IP) updated.
// Returns any devices that appear for the first time.
func (ct *ClientTracker) Snapshot(clients []Client) []TrackedClient {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	now := time.Now().UnixMilli()
	var newOnes []TrackedClient
	for _, c := range clients {
		if c.MAC == "" {
			continue
		}
		if existing, ok := ct.known[c.MAC]; ok {
			existing.LastSeen = now
			if c.Hostname != "" {
				existing.Hostname = c.Hostname
			}
			if c.Name != "" {
				existing.Name = c.Name
			}
			if c.IP != "" {
				existing.IP = c.IP
			}
		} else {
			tc := &TrackedClient{
				MAC:       c.MAC,
				Hostname:  c.Hostname,
				Name:      c.Name,
				IP:        c.IP,
				FirstSeen: now,
				LastSeen:  now,
				IsWired:   c.Wired,
			}
			ct.known[c.MAC] = tc
			newOnes = append(newOnes, *tc)
			log.Printf("[unifideck] client-tracker: new device mac=%s host=%q", c.MAC, c.Hostname)
		}
	}
	ct.lastSnapshot = time.Now()
	ct.save()
	return newOnes
}

// NewDevices returns all tracked devices whose FirstSeen is within the last
// `days` days, sorted newest first.
func (ct *ClientTracker) NewDevices(days int) []TrackedClient {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	cutoff := time.Now().AddDate(0, 0, -days).UnixMilli()
	var out []TrackedClient
	for _, tc := range ct.known {
		if tc.FirstSeen >= cutoff {
			out = append(out, *tc)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FirstSeen > out[j].FirstSeen
	})
	return out
}

// LastSnapshot returns when the last successful poll completed (zero if never).
func (ct *ClientTracker) LastSnapshot() time.Time {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.lastSnapshot
}

// Start begins the background 20-minute polling loop.
// fetchClients should call ListClients on the current UnifiClient.
// Returning (nil, nil) is treated as "not configured yet" and skipped silently.
func (ct *ClientTracker) Start(fetchClients func(ctx context.Context) ([]Client, error)) {
	go func() {
		ct.poll(fetchClients)
		ticker := time.NewTicker(20 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ct.poll(fetchClients)
			case <-ct.stopCh:
				return
			}
		}
	}()
}

func (ct *ClientTracker) poll(fetchClients func(ctx context.Context) ([]Client, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clients, err := fetchClients(ctx)
	if err != nil {
		log.Printf("[unifideck] client-tracker: poll error: %v", err)
		return
	}
	if clients == nil {
		return // controller not configured yet — skip
	}
	newOnes := ct.Snapshot(clients)
	if len(newOnes) > 0 {
		log.Printf("[unifideck] client-tracker: %d new device(s) found in this poll", len(newOnes))
	} else {
		log.Printf("[unifideck] client-tracker: poll OK — %d clients, no new devices", len(clients))
	}
}

// Stop signals the background poller to exit.
func (ct *ClientTracker) Stop() {
	select {
	case <-ct.stopCh:
	default:
		close(ct.stopCh)
	}
}
