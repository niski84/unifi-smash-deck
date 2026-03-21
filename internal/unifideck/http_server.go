package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HTTPServer wires HTTP routes to UniFi + automations.
type HTTPServer struct {
	mu sync.RWMutex
	cfg AppConfig

	settingsPath   string
	automationPath string
	logPath        string

	store     *AutomationStore
	logger    *AutomationLogger
	scheduler *AutomationScheduler
}

func NewHTTPServer(cfg AppConfig) *HTTPServer {
	settingsPath := DefaultSettingsPath()
	autoPath := filepath.Clean("data/unifideck-automations.json")
	logPath := filepath.Clean("data/unifideck.log")
	s := &HTTPServer{
		cfg:            cfg,
		settingsPath:   settingsPath,
		automationPath: autoPath,
		logPath:        logPath,
		store:          NewAutomationStore(autoPath),
		logger:         NewAutomationLogger(logPath),
	}
	s.scheduler = NewAutomationScheduler(s.store, s.logger, s.unifiClient)
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
func (s *HTTPServer) Routes(webDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/networks", s.handleNetworks)
	mux.HandleFunc("/api/networks/", s.handleNetworkSubroutes)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/automations", s.handleAutomations)
	mux.HandleFunc("/api/automations/", s.handleAutomationSubroutes)
	mux.HandleFunc("/api/logs", s.handleLogs)

	fs := http.FileServer(http.Dir(filepath.Clean(webDir)))
	mux.Handle("/", fs)
	return mux
}

func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"service": "unifi-smash-deck"}})
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
		enabled := seg == "enable"
		c := s.unifiClient()
		if !c.IsConfigured() {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := c.SetNetworkEnabled(ctx, networkID, enabled); err != nil {
			s.logger.Warn("set network enabled=%v id=%s err=%v", enabled, networkID, err)
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("network %s network_id=%s enabled=%v", seg, networkID, enabled)
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

// StartScheduler starts the background ticker.
func (s *HTTPServer) StartScheduler() { s.scheduler.Start() }

// StopScheduler stops the scheduler.
func (s *HTTPServer) StopScheduler() { s.scheduler.Stop() }

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
