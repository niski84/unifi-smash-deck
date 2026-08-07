package unifideck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleFeed() []FeedEntry {
	return []FeedEntry{
		{IP: "1.2.3.4", Port: 443, Malware: "Dridex", Country: "RU"},
		{IP: "5.6.7.8", Port: 8080, Malware: "Emotet", Country: "CN"},
	}
}

func newTestUpdater(t *testing.T, url string) *SignatureUpdater {
	t.Helper()
	su := NewSignatureUpdater(t.TempDir())
	su.feedURL = url
	return su
}

// TestSignatureUpdater_FetchAndCache verifies that fetch() downloads entries,
// persists them to disk, and IsKnownBadIP reports correctly.
func TestSignatureUpdater_FetchAndCache(t *testing.T) {
	feed := sampleFeed()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(feed)
	}))
	defer srv.Close()

	su := newTestUpdater(t, srv.URL)
	su.fetch()

	// Entries are loaded.
	if got := len(su.entries); got != len(feed) {
		t.Fatalf("want %d entries, got %d", len(feed), got)
	}

	// IsKnownBadIP finds a present IP.
	if ok, malware := su.IsKnownBadIP("1.2.3.4"); !ok || malware != "Dridex" {
		t.Errorf("expected 1.2.3.4 to be known bad Dridex, got ok=%v malware=%q", ok, malware)
	}

	// IsKnownBadIP returns false for an unknown IP.
	if ok, _ := su.IsKnownBadIP("9.9.9.9"); ok {
		t.Error("9.9.9.9 should not be a known bad IP")
	}

	// Cache file was written.
	cacheFile := filepath.Join(su.dataDir, "threat-signatures.json")
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("cache file not found: %v", err)
	}

	// Re-loading from cache yields the same entries.
	su2 := NewSignatureUpdater(su.dataDir)
	if got := len(su2.entries); got != len(feed) {
		t.Fatalf("after reload: want %d entries, got %d", len(feed), got)
	}
}

// TestSignatureUpdater_HTTPError verifies fetch() sets lastErr on a non-200 response.
func TestSignatureUpdater_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	su := newTestUpdater(t, srv.URL)
	su.fetch()

	su.mu.RLock()
	err := su.lastErr
	su.mu.RUnlock()

	if err == nil {
		t.Fatal("expected an error after HTTP 500, got nil")
	}
}

// TestSignatureUpdater_Status verifies Status() returns populated fields after a fetch.
func TestSignatureUpdater_Status(t *testing.T) {
	feed := sampleFeed()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(feed)
	}))
	defer srv.Close()

	su := newTestUpdater(t, srv.URL)
	su.fetch()

	status := su.Status()
	if status.EntryCount != len(feed) {
		t.Errorf("want EntryCount=%d, got %d", len(feed), status.EntryCount)
	}
	if status.LastUpdatedMs == 0 {
		t.Error("LastUpdatedMs should be non-zero after a fetch")
	}
	if status.Mode != string(ThreatFeedBalanced) {
		t.Errorf("want mode=%q, got %q", ThreatFeedBalanced, status.Mode)
	}
}

// TestSignatureUpdater_SetMode verifies the mode change is applied.
func TestSignatureUpdater_SetMode(t *testing.T) {
	su := newTestUpdater(t, "")
	su.SetMode(ThreatFeedAggressive)

	su.mu.RLock()
	m := su.mode
	su.mu.RUnlock()

	if m != ThreatFeedAggressive {
		t.Errorf("want aggressive, got %q", m)
	}
}

// TestThreatFeedMode_Intervals verifies the interval mapping.
func TestThreatFeedMode_Intervals(t *testing.T) {
	cases := []struct {
		mode ThreatFeedMode
		want time.Duration
	}{
		{ThreatFeedPassive, 24 * time.Hour},
		{ThreatFeedBalanced, 6 * time.Hour},
		{ThreatFeedAggressive, time.Hour},
		{"unknown", 6 * time.Hour}, // falls back to balanced
	}
	for _, c := range cases {
		if got := c.mode.Interval(); got != c.want {
			t.Errorf("mode %q: want %v, got %v", c.mode, c.want, got)
		}
	}
}

// TestHandleSecuritySignatures_GET tests the /api/security/signatures GET endpoint.
func TestHandleSecuritySignatures_GET(t *testing.T) {
	feed := sampleFeed()
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(feed)
	}))
	defer feedSrv.Close()

	dir := t.TempDir()
	su := &SignatureUpdater{
		dataDir: dir,
		httpCli: feedSrv.Client(),
		feedURL: feedSrv.URL,
		mode:    ThreatFeedBalanced,
		stopCh:  make(chan struct{}),
		resetCh: make(chan ThreatFeedMode, 1),
	}
	su.fetch() // pre-load entries

	s := minimalHTTPServer(t)
	s.sigUpdater = su

	req := httptest.NewRequest(http.MethodGet, "/api/security/signatures", nil)
	w := httptest.NewRecorder()
	s.handleSecuritySignatures(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp apiResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("response not successful: %+v", resp)
	}

	// Verify populated fields.
	data, _ := json.Marshal(resp.Data)
	var status FeedStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("unmarshal FeedStatus: %v", err)
	}
	if status.EntryCount != len(feed) {
		t.Errorf("want entry_count=%d, got %d", len(feed), status.EntryCount)
	}
	if status.LastUpdatedMs == 0 {
		t.Error("last_updated_ms should be non-zero")
	}
}

// TestHandleSecuritySignatures_POST tests the manual refresh endpoint.
func TestHandleSecuritySignatures_POST(t *testing.T) {
	s := minimalHTTPServer(t)
	s.sigUpdater = NewSignatureUpdater(t.TempDir())

	req := httptest.NewRequest(http.MethodPost, "/api/security/signatures", nil)
	w := httptest.NewRecorder()
	s.handleSecuritySignatures(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}

	var resp apiResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success=true")
	}
}

// TestHandleSettings_ThreatFeedMode verifies that GET /api/settings returns
// threat_feed_mode and that POST /api/settings persists it.
func TestHandleSettings_ThreatFeedMode(t *testing.T) {
	dir := t.TempDir()
	cfg := AppConfig{Port: "8099", ThreatFeedMode: "aggressive"}

	s := &HTTPServer{
		cfg:          cfg,
		settingsPath: filepath.Join(dir, "settings.json"),
		sigUpdater:   NewSignatureUpdater(dir),
		honeypotSrv:  NewHoneypotServer(NewThreatStore(dir), NewClientTracker(dir), nil),
	}

	// GET returns the saved mode.
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	s.handleSettings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET settings: want 200, got %d", w.Code)
	}
	var resp apiResp
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	data, _ := json.Marshal(resp.Data)
	var m map[string]any
	json.Unmarshal(data, &m) //nolint:errcheck
	if m["threat_feed_mode"] != "aggressive" {
		t.Errorf("want threat_feed_mode=aggressive, got %v", m["threat_feed_mode"])
	}

	// POST updates the mode.
	body := `{"threat_feed_mode":"passive"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/settings", httpBodyString(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	s.handleSettings(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("POST settings: want 200, got %d: %s", w2.Code, w2.Body.String())
	}

	s.mu.RLock()
	got := s.cfg.ThreatFeedMode
	s.mu.RUnlock()
	if got != "passive" {
		t.Errorf("want ThreatFeedMode=passive after POST, got %q", got)
	}
}

// minimalHTTPServer builds the smallest HTTPServer usable for handler tests.
func minimalHTTPServer(t *testing.T) *HTTPServer {
	t.Helper()
	dir := t.TempDir()
	ts := NewThreatStore(dir)
	ct := NewClientTracker(dir)
	return &HTTPServer{
		cfg:          AppConfig{Port: "8099"},
		settingsPath: filepath.Join(dir, "settings.json"),
		threatStore:  ts,
		honeypotSrv:  NewHoneypotServer(ts, ct, nil),
		sigUpdater:   NewSignatureUpdater(dir),
	}
}

func httpBodyString(s string) *strings.Reader { return strings.NewReader(s) }
