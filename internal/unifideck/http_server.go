package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HTTPServer wires HTTP routes to UniFi + automations + snapshots.
type HTTPServer struct {
	mu sync.RWMutex
	cfg AppConfig

	settingsPath   string
	automationPath string
	logPath        string

	store            *AutomationStore
	logger           *AutomationLogger
	scheduler        *AutomationScheduler
	snapStore        *SnapshotStore
	snapScheduler    *SnapshotScheduler
}

func NewHTTPServer(cfg AppConfig) *HTTPServer {
	settingsPath := DefaultSettingsPath()
	autoPath := filepath.Join(DataDir(), "unifideck-automations.json")
	logPath := filepath.Join(DataDir(), "unifideck.log")
	store := NewAutomationStore(autoPath)
	snapStore := NewSnapshotStore(DataDir())
	logger := NewAutomationLogger(logPath)
	s := &HTTPServer{
		cfg:            cfg,
		settingsPath:   settingsPath,
		automationPath: autoPath,
		logPath:        logPath,
		store:          store,
		logger:         logger,
		snapStore:      snapStore,
	}
	s.scheduler = NewAutomationScheduler(s.store, s.logger, s.unifiClient)
	s.snapScheduler = NewSnapshotScheduler(snapStore, logger, s.unifiClient)
	log.Printf("[unifideck] automations file: %s (%d loaded)", autoPath, store.LoadedCount())
	log.Printf("[unifideck] snapshots dir   : %s (%d stored)", filepath.Join(DataDir(), "snapshots"), snapStore.Count())
	log.Printf("[unifideck] activity log    : %s", logPath)
	return s
}

func (s *HTTPServer) unifiClient() *UnifiClient {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	return NewUnifiClient(cfg.UnifiHost, cfg.UnifiAPIKey, cfg.UnifiSite)
}

func (s *HTTPServer) snapshotCfg() AppConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *HTTPServer) replaceCfg(c AppConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
}

type apiResp struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Routes returns the HTTP mux for the API + static UI.
// webFS should be rooted at the directory containing index.html.
func (s *HTTPServer) Routes(webFS fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/networks", s.handleNetworks)
	mux.HandleFunc("/api/networks/", s.handleNetworkSubroutes)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/cameras", s.handleCameras)
	mux.HandleFunc("/api/cameras/", s.handleCameraSubroutes)
	mux.HandleFunc("/api/snapshots", s.handleSnapshots)
	mux.HandleFunc("/api/snapshots/", s.handleSnapshotSubroutes)
	mux.HandleFunc("/api/automations", s.handleAutomations)
	mux.HandleFunc("/api/automations/", s.handleAutomationSubroutes)
	mux.HandleFunc("/api/logs", s.handleLogs)

	mux.Handle("/", http.FileServer(http.FS(webFS)))
	return mux
}

func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"service":    "unifi-smash-deck",
		"data_dir":   DataDir(),
		"automations": s.store.LoadedCount(),
	}})
}

func (s *HTTPServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.snapshotCfg()
		safe := map[string]string{
			"port":          cfg.Port,
			"unifi_host":    cfg.UnifiHost,
			"unifi_site":    cfg.UnifiSite,
			"unifi_api_key": maskKey(cfg.UnifiAPIKey),
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: safe})
	case http.MethodPost:
		var body struct {
			Port        string `json:"port"`
			UnifiHost   string `json:"unifi_host"`
			UnifiSite   string `json:"unifi_site"`
			UnifiAPIKey string `json:"unifi_api_key"`
			// Accept unifi_pass as alias for unifi_api_key for backward compat.
			UnifiPass string `json:"unifi_pass"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		cur := s.snapshotCfg()
		if body.Port != "" {
			cur.Port = body.Port
		}
		if body.UnifiHost != "" {
			cur.UnifiHost = strings.TrimRight(body.UnifiHost, "/")
		}
		if body.UnifiSite != "" {
			cur.UnifiSite = body.UnifiSite
		}
		// Accept API key from either field name; unifi_api_key takes precedence.
		keyVal := body.UnifiAPIKey
		if keyVal == "" {
			keyVal = body.UnifiPass
		}
		if keyVal != "" && !isMasked(keyVal) {
			cur.UnifiAPIKey = keyVal
			// Clear the old pass field so saved JSON stays clean.
			cur.UnifiPass = ""
		}
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]bool{"saved": true}})
	case http.MethodPut:
		// Test connection
		cfg := s.snapshotCfg()
		c := NewUnifiClient(cfg.UnifiHost, cfg.UnifiAPIKey, cfg.UnifiSite)
		if !c.IsConfigured() {
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": "not configured"}})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		msg, err := c.TestConnection(ctx)
		if err != nil {
			writeJSON(w, http.StatusOK, apiResp{Success: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": msg}})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

func (s *HTTPServer) handleNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"networks": []any{}, "configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	nets, err := c.ListNetworks(ctx)
	if err != nil {
		s.logger.Warn("list networks err=%v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	nets = sortNetworks(nets)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"networks": nets, "configured": true}})
}

// handleNetworkSubroutes: POST /api/networks/{id}/enable, POST /api/networks/{id}/disable
func (s *HTTPServer) handleNetworkSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/networks/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
		return
	}
	networkID := parts[0]
	seg := parts[1]

	switch seg {
	case "enable", "disable":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
			return
		}
		// Optional body: { "name": "Guest Network" } for richer log messages.
		var reqBody struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		enabled := seg == "enable"
		c := s.unifiClient()
		if !c.IsConfigured() {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
			return
		}
		label := networkID
		if reqBody.Name != "" {
			label = fmt.Sprintf("%q (id=%s)", reqBody.Name, networkID)
		}
		s.logger.Info("network toggle %s → enabled=%v (fetching full object…)", label, enabled)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := c.SetNetworkEnabled(ctx, networkID, enabled); err != nil {
			s.logger.Warn("network toggle FAILED %s enabled=%v err=%v", label, enabled, err)
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("network toggle OK %s enabled=%v", label, enabled)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"enabled": enabled, "network_id": networkID}})
	default:
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
	}
}

func (s *HTTPServer) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"clients": []any{}, "configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	clients, err := c.ListClients(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"clients": clients}})
}

func (s *HTTPServer) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"devices": []any{}, "configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	devices, err := c.ListDevices(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"devices": devices}})
}

func (s *HTTPServer) handleCameras(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"cameras": []any{}, "configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cameras, err := c.ListCameras(ctx)
	if err != nil {
		s.logger.Warn("list cameras err=%v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"cameras": cameras, "configured": true}})
}

// handleCameraSubroutes proxies snapshot images: GET /api/cameras/{id}/snapshot
func (s *HTTPServer) handleCameraSubroutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/cameras/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[1] != "snapshot" {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
		return
	}
	cameraID := parts[0]
	if cameraID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "camera id required"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		http.Error(w, "UniFi not configured", http.StatusServiceUnavailable)
		return
	}
	highQuality := r.URL.Query().Get("highQuality") == "true"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data, contentType, err := c.CameraSnapshot(ctx, cameraID, highQuality)
	if err != nil {
		// Log to stderr only — don't pollute the user-visible activity log for routine snapshot failures.
		log.Printf("[unifideck] camera snapshot failed id=%s err=%v", cameraID, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if contentType == "" {
		contentType = "image/jpeg"
	}
	w.Header().Set("Content-Type", contentType)
	// Prevent browser caching so every poll gets a fresh image.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ── Snapshot handlers ──────────────────────────────────────────────────────────

// GET /api/snapshots — returns schedule + all snapshots grouped by camera.
func (s *HTTPServer) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	groups := s.snapStore.GroupedByCamera()
	if groups == nil {
		groups = []CameraSnapshotGroup{}
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"schedule": s.snapStore.GetSchedule(),
		"cameras":  groups,
		"total":    s.snapStore.Count(),
	}})
}

// handleSnapshotSubroutes routes:
//
//	GET    /api/snapshots/schedule          → return schedule
//	POST   /api/snapshots/schedule          → save schedule
//	POST   /api/snapshots/capture           → trigger immediate capture
//	GET    /api/snapshots/{id}/image        → serve JPEG
//	DELETE /api/snapshots/{id}              → delete snapshot
func (s *HTTPServer) handleSnapshotSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/snapshots/")
	path = strings.Trim(path, "/")
	parts := strings.SplitN(path, "/", 2)
	seg := parts[0]

	switch seg {
	case "schedule":
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.snapStore.GetSchedule()})
		case http.MethodPost:
			var sc SnapshotSchedule
			if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
				writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
				return
			}
			if err := s.snapStore.SaveSchedule(sc); err != nil {
				writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
				return
			}
			s.logger.Info("snapshot schedule updated times=%v tz=%s retain=%dd", sc.Times, sc.Timezone, sc.RetainDays)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: sc})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		}

	case "capture":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
			return
		}
		s.snapScheduler.CaptureNow()
		s.logger.Info("snapshot capture triggered manually")
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": "capturing"}})

	default:
		// Remaining routes: /{id}/image  or  DELETE /{id}
		id := seg
		if id == "" {
			writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
			return
		}
		if len(parts) == 2 && parts[1] == "image" {
			// GET /api/snapshots/{id}/image — serve the JPEG
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
				return
			}
			rec, ok := s.snapStore.Get(id)
			if !ok {
				http.Error(w, "snapshot not found", http.StatusNotFound)
				return
			}
			imgPath := s.snapStore.ImagePath(rec.ID)
			data, err := os.ReadFile(imgPath)
			if err != nil {
				http.Error(w, "image not found on disk", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=86400") // archived snapshots don't change
			_, _ = w.Write(data)
			return
		}
		// DELETE /api/snapshots/{id}
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
			return
		}
		if err := s.snapStore.Delete(id); err != nil {
			writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("snapshot deleted id=%s", id)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]bool{"deleted": true}})
	}
}

func (s *HTTPServer) handleAutomations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list := s.store.List()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"automations": list}})
	case http.MethodPost:
		var a Automation
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		if err := validateAutomation(a); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: err.Error()})
			return
		}
		if a.ID == "" {
			a.ID = newID()
		}
		a.CreatedAt = time.Now()
		a.UpdatedAt = a.CreatedAt
		if err := s.store.Upsert(a); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.scheduler.RefreshNextRunTimes()
		s.logger.Info("automation created id=%s name=%q", a.ID, a.Name)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: a})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

func (s *HTTPServer) handleAutomationSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/automations/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
		return
	}
	id := parts[0]

	if len(parts) >= 2 && parts[1] == "run" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := s.scheduler.RunAutomation(ctx, id); err != nil {
				s.logger.Error("manual run failed auto=%s err=%v", id, err)
			}
		}()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": "started"}})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var a Automation
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		if a.ID != id {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "id mismatch"})
			return
		}
		if err := validateAutomation(a); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: err.Error()})
			return
		}
		a.UpdatedAt = time.Now()
		if err := s.store.Upsert(a); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.scheduler.RefreshNextRunTimes()
		s.logger.Info("automation updated id=%s name=%q", a.ID, a.Name)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: a})
	case http.MethodDelete:
		if err := s.store.Delete(id); err != nil {
			writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("automation deleted id=%s", id)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]bool{"deleted": true}})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

func (s *HTTPServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	n := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	if n <= 0 || n > 5000 {
		n = 200
	}
	lines := s.logger.Tail(n)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"lines": lines}})
}

// StartScheduler starts both the automation and snapshot background schedulers.
func (s *HTTPServer) StartScheduler() {
	s.scheduler.Start()
	s.snapScheduler.Start()
}

// StopScheduler stops both schedulers.
func (s *HTTPServer) StopScheduler() {
	s.scheduler.Stop()
	s.snapScheduler.Stop()
}

func maskKey(k string) string {
	if len(k) < 8 {
		if k == "" {
			return ""
		}
		return "****"
	}
	return k[:2] + strings.Repeat("•", len(k)-4) + k[len(k)-2:]
}

func isMasked(s string) bool {
	return strings.Contains(s, "•") || strings.HasPrefix(s, "****")
}
