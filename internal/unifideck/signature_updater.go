package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ThreatFeedMode controls how aggressively signature/intel feeds are refreshed.
type ThreatFeedMode string

const (
	ThreatFeedPassive    ThreatFeedMode = "passive"    // every 24h
	ThreatFeedBalanced   ThreatFeedMode = "balanced"   // every 6h (default)
	ThreatFeedAggressive ThreatFeedMode = "aggressive" // every 1h
)

func (m ThreatFeedMode) Interval() time.Duration {
	switch m {
	case ThreatFeedAggressive:
		return time.Hour
	case ThreatFeedPassive:
		return 24 * time.Hour
	default:
		return 6 * time.Hour
	}
}

func ValidThreatFeedMode(s string) ThreatFeedMode {
	switch ThreatFeedMode(s) {
	case ThreatFeedPassive, ThreatFeedBalanced, ThreatFeedAggressive:
		return ThreatFeedMode(s)
	default:
		return ThreatFeedBalanced
	}
}

// FeedEntry is one IP record from the Feodo Tracker botnet C2 blocklist.
type FeedEntry struct {
	IP      string `json:"ip_address"`
	Port    int    `json:"port"`
	Malware string `json:"malware"`
	Country string `json:"country"`
}

// FeedStatus is returned by /api/security/signatures.
type FeedStatus struct {
	LastUpdatedMs int64  `json:"last_updated_ms"` // 0 if never fetched
	EntryCount    int    `json:"entry_count"`
	Mode          string `json:"mode"`
	NextUpdateIn  string `json:"next_update_in,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	Source        string `json:"source"`
}

// SignatureUpdater periodically fetches the Feodo Tracker botnet C2 IP blocklist
// and caches it locally so the app can flag known-bad source IPs.
type SignatureUpdater struct {
	dataDir string
	httpCli *http.Client
	feedURL string // overridable for tests

	mu          sync.RWMutex
	mode        ThreatFeedMode
	entries     []FeedEntry
	lastUpdated time.Time
	lastErr     error

	stopCh  chan struct{}
	resetCh chan ThreatFeedMode
}

const feodoTrackerURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

func NewSignatureUpdater(dataDir string) *SignatureUpdater {
	su := &SignatureUpdater{
		dataDir: dataDir,
		httpCli: &http.Client{Timeout: 30 * time.Second},
		feedURL: feodoTrackerURL,
		mode:    ThreatFeedBalanced,
		stopCh:  make(chan struct{}),
		resetCh: make(chan ThreatFeedMode, 1),
	}
	su.loadCache()
	return su
}

func (su *SignatureUpdater) cacheFile() string {
	return filepath.Join(su.dataDir, "threat-signatures.json")
}

type sigCache struct {
	LastUpdatedMs int64       `json:"last_updated_ms"`
	Entries       []FeedEntry `json:"entries"`
}

func (su *SignatureUpdater) loadCache() {
	raw, err := os.ReadFile(su.cacheFile())
	if err != nil {
		return
	}
	var c sigCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return
	}
	su.entries = c.Entries
	if c.LastUpdatedMs > 0 {
		su.lastUpdated = time.UnixMilli(c.LastUpdatedMs)
	}
	log.Printf("[sigs] loaded %d cached entries from disk", len(su.entries))
}

func (su *SignatureUpdater) saveCache() {
	c := sigCache{
		LastUpdatedMs: su.lastUpdated.UnixMilli(),
		Entries:       su.entries,
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(su.cacheFile(), b, 0o644)
}

// SetMode updates the polling frequency; safe to call concurrently.
func (su *SignatureUpdater) SetMode(m ThreatFeedMode) {
	su.mu.Lock()
	su.mode = m
	su.mu.Unlock()
	select {
	case su.resetCh <- m:
	default:
	}
}

// Start runs the fetch loop in a background goroutine.
func (su *SignatureUpdater) Start() {
	go su.run()
}

// Stop halts the fetch loop.
func (su *SignatureUpdater) Stop() {
	select {
	case <-su.stopCh:
	default:
		close(su.stopCh)
	}
}

func (su *SignatureUpdater) run() {
	su.mu.RLock()
	mode := su.mode
	lastUpdated := su.lastUpdated
	su.mu.RUnlock()

	// If we have a recent enough cache, wait for the remainder of the interval.
	initialDelay := time.Duration(0)
	if !lastUpdated.IsZero() {
		elapsed := time.Since(lastUpdated)
		if elapsed < mode.Interval() {
			initialDelay = mode.Interval() - elapsed
		}
	}

	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-su.stopCh:
			return
		case newMode := <-su.resetCh:
			mode = newMode
			timer.Reset(newMode.Interval())
		case <-timer.C:
			su.fetch()
			su.mu.RLock()
			mode = su.mode
			su.mu.RUnlock()
			timer.Reset(mode.Interval())
		}
	}
}

func (su *SignatureUpdater) fetch() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, su.feedURL, nil)
	if err != nil {
		su.setErr(fmt.Errorf("build request: %w", err))
		return
	}
	req.Header.Set("User-Agent", "unifi-smash-deck/1.0 (threat-intel updater; +https://github.com/niski84/unifi-smash-deck)")

	resp, err := su.httpCli.Do(req)
	if err != nil {
		su.setErr(fmt.Errorf("fetch: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		su.setErr(fmt.Errorf("fetch: HTTP %d", resp.StatusCode))
		return
	}

	var entries []FeedEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		su.setErr(fmt.Errorf("decode: %w", err))
		return
	}

	su.mu.Lock()
	su.entries = entries
	su.lastUpdated = time.Now()
	su.lastErr = nil
	su.mu.Unlock()

	su.saveCache()
	log.Printf("[sigs] updated — %d entries from %s", len(entries), su.feedURL)
}

func (su *SignatureUpdater) setErr(err error) {
	su.mu.Lock()
	su.lastErr = err
	su.mu.Unlock()
	log.Printf("[sigs] error: %v", err)
}

// Status returns the current feed status for the /api/security/signatures endpoint.
func (su *SignatureUpdater) Status() FeedStatus {
	su.mu.RLock()
	defer su.mu.RUnlock()
	s := FeedStatus{
		Mode:       string(su.mode),
		EntryCount: len(su.entries),
		Source:     su.feedURL,
	}
	if !su.lastUpdated.IsZero() {
		s.LastUpdatedMs = su.lastUpdated.UnixMilli()
		next := su.lastUpdated.Add(su.mode.Interval())
		if d := time.Until(next); d > 0 {
			s.NextUpdateIn = d.Round(time.Minute).String()
		}
	}
	if su.lastErr != nil {
		s.LastError = su.lastErr.Error()
	}
	return s
}

// IsKnownBadIP returns (true, malware family) if the IP is in the current feed.
func (su *SignatureUpdater) IsKnownBadIP(ip string) (bool, string) {
	su.mu.RLock()
	defer su.mu.RUnlock()
	for _, e := range su.entries {
		if e.IP == ip {
			return true, e.Malware
		}
	}
	return false, ""
}
