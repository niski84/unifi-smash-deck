package unifideck

import (
	"bytes"
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
	cfgSnapStore     *ConfigSnapshotStore
	cfgSnapScheduler *ConfigSnapshotScheduler
	clientTracker    *ClientTracker
	threatStore      *ThreatStore
	threatPoller     *IPSThreatPoller
	honeypotSrv      *HoneypotServer
	sigUpdater       *SignatureUpdater
	watchdog         *UDMWatchdog
}

func NewHTTPServer(cfg AppConfig) *HTTPServer {
	settingsPath := DefaultSettingsPath()
	autoPath := filepath.Join(DataDir(), "unifideck-automations.json")
	logPath := filepath.Join(DataDir(), "unifideck.log")
	store := NewAutomationStore(autoPath)
	snapStore := NewSnapshotStore(DataDir())
	cfgSnapStore := NewConfigSnapshotStore(DataDir())
	logger := NewAutomationLogger(logPath)
	clientTracker := NewClientTracker(DataDir())
	threatStore := NewThreatStore(DataDir())
	threatPoller := NewIPSThreatPoller(threatStore, clientTracker)
	honeypotSrv := NewHoneypotServer(threatStore, clientTracker, nil) // webhook wired after cfg known
	sigUpdater := NewSignatureUpdater(DataDir())

	watchdogCfgPath := filepath.Join(DataDir(), "udm-watchdog.json")

	s := &HTTPServer{
		cfg:            cfg,
		settingsPath:   settingsPath,
		automationPath: autoPath,
		logPath:        logPath,
		store:          store,
		logger:         logger,
		snapStore:      snapStore,
		cfgSnapStore:   cfgSnapStore,
		clientTracker:  clientTracker,
		threatStore:    threatStore,
		threatPoller:   threatPoller,
		honeypotSrv:    honeypotSrv,
		sigUpdater:     sigUpdater,
	}
	s.watchdog = NewUDMWatchdog(watchdogCfgPath, s.snapshotCfg)
	s.scheduler = NewAutomationScheduler(s.store, s.logger, s.unifiClient)
	s.snapScheduler = NewSnapshotScheduler(snapStore, logger, s.unifiClient)
	s.cfgSnapScheduler = NewConfigSnapshotScheduler(cfgSnapStore, logger, s.unifiClient, s.snapshotCfg)
	log.Printf("[unifideck] automations file: %s (%d loaded)", autoPath, store.LoadedCount())
	log.Printf("[unifideck] snapshots dir   : %s (%d stored)", filepath.Join(DataDir(), "snapshots"), snapStore.Count())
	log.Printf("[unifideck] config snapshots: %s (%d stored)", filepath.Join(DataDir(), "config-snapshots"), cfgSnapStore.Count())
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
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/networks", s.handleNetworks)
	mux.HandleFunc("/api/networks/", s.handleNetworkSubroutes)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/new", s.handleClientsNew)
	mux.HandleFunc("/api/clients/dismiss", s.handleClientsDismiss)
	mux.HandleFunc("/api/clients/block", s.handleClientBlock)
	mux.HandleFunc("/api/security/events", s.handleSecurityEvents)
	mux.HandleFunc("/api/security/summary", s.handleSecuritySummary)
	mux.HandleFunc("/api/security/test", s.handleSecurityTest)
	mux.HandleFunc("/api/security/signatures", s.handleSecuritySignatures)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/cameras", s.handleCameras)
	mux.HandleFunc("/api/cameras/", s.handleCameraSubroutes)
	mux.HandleFunc("/api/snapshots", s.handleSnapshots)
	mux.HandleFunc("/api/snapshots/", s.handleSnapshotSubroutes)
	mux.HandleFunc("/api/automations", s.handleAutomations)
	mux.HandleFunc("/api/automations/", s.handleAutomationSubroutes)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/iot/diagnose", s.handleIoTDiagnose)
	mux.HandleFunc("/api/iot/wlans/", s.handleIoTWLANFix)
	mux.HandleFunc("/api/network-health", s.handleNetworkHealth)
	mux.HandleFunc("/api/network-health/", s.handleHealthFix)
	mux.HandleFunc("/api/config-snapshots", s.handleConfigSnapshots)
	mux.HandleFunc("/api/config-snapshots/", s.handleConfigSnapshotSubroutes)
	mux.HandleFunc("/api/audit", s.handleAuditLog)
	mux.HandleFunc("/api/firewall-audit", s.handleFirewallAudit)
	mux.HandleFunc("/api/network-insights", s.handleNetworkInsights)
	s.registerUDMRoutes(mux)

	// Auto-start watchdog if it was previously enabled.
	if s.watchdog.Status().Config.Enabled {
		_ = s.watchdog.Start()
	}

	mux.Handle("/", http.FileServer(http.FS(webFS)))
	return mux
}

// registerUDMRoutes adds all UDM Pro-specific API routes.
func (s *HTTPServer) registerUDMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/udm-process-scan", s.handleUDMProcessScan)
	mux.HandleFunc("/api/udm-watchdog", s.handleUDMWatchdog)
	mux.HandleFunc("/api/udm-sysconfig", s.handleUDMSysConfig)
	mux.HandleFunc("/api/udm-deploy", s.handleUDMDeploy)
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
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"port":                 cfg.Port,
			"unifi_host":           cfg.UnifiHost,
			"unifi_site":           cfg.UnifiSite,
			"unifi_api_key":        maskKey(cfg.UnifiAPIKey),
			"honeypot_ports":       cfg.HoneypotPorts,
			"security_webhook_url": cfg.SecurityWebhookURL,
			"threat_feed_mode":     cfg.ThreatFeedMode,
		}})
	case http.MethodPost:
		var body struct {
			Port               string `json:"port"`
			UnifiHost          string `json:"unifi_host"`
			UnifiSite          string `json:"unifi_site"`
			UnifiAPIKey        string `json:"unifi_api_key"`
			UnifiPass          string `json:"unifi_pass"` // backward compat alias
			HoneypotPorts      []int  `json:"honeypot_ports"`
			SecurityWebhookURL string `json:"security_webhook_url"`
			ThreatFeedMode     string `json:"threat_feed_mode"`
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
		keyVal := body.UnifiAPIKey
		if keyVal == "" {
			keyVal = body.UnifiPass
		}
		if keyVal != "" && !isMasked(keyVal) {
			cur.UnifiAPIKey = keyVal
			cur.UnifiPass = ""
		}
		// Security settings (nil body fields mean "leave unchanged" for ports)
		if body.HoneypotPorts != nil {
			cur.HoneypotPorts = body.HoneypotPorts
		}
		cur.SecurityWebhookURL = body.SecurityWebhookURL
		if body.ThreatFeedMode != "" {
			cur.ThreatFeedMode = string(ValidThreatFeedMode(body.ThreatFeedMode))
		}
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		// Reconcile honeypot listeners with new port list.
		s.honeypotSrv.UpdatePorts(cur.HoneypotPorts)
		// Apply new feed mode immediately.
		if cur.ThreatFeedMode != "" {
			s.sigUpdater.SetMode(ValidThreatFeedMode(cur.ThreatFeedMode))
		}
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

// handleClientsNew returns devices first seen within the last 30 days.
// The clientTracker background poller builds this list automatically.
func (s *HTTPServer) handleClientsNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	newDevices := s.clientTracker.NewDevices(30)
	if newDevices == nil {
		newDevices = []TrackedClient{}
	}
	var lastSnap int64
	if t := s.clientTracker.LastSnapshot(); !t.IsZero() {
		lastSnap = t.UnixMilli()
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"new_devices":   newDevices,
		"last_snapshot": lastSnap,
	}})
}

// handleClientsDismiss marks the given MACs as dismissed so they no longer
// appear in the new-devices list. Persisted server-side in client-history.json.
func (s *HTTPServer) handleClientsDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	var body struct {
		MACs []string `json:"macs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.MACs) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "macs array required"})
		return
	}
	s.clientTracker.Dismiss(body.MACs)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"dismissed": len(body.MACs)}})
}

// handleClientBlock blocks or unblocks a client by MAC via UniFi cmd/stamgr.
func (s *HTTPServer) handleClientBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	var body struct {
		MAC    string `json:"mac"`
		Action string `json:"action"` // "block" or "unblock"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.MAC == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "mac and action required"})
		return
	}
	if body.Action != "block" && body.Action != "unblock" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "action must be block or unblock"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var err error
	if body.Action == "block" {
		err = c.BlockClient(ctx, body.MAC)
	} else {
		err = c.UnblockClient(ctx, body.MAC)
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"mac": body.MAC, "action": body.Action}})
}

// handleSecurityTest runs built-in test scenarios or a single custom probe.
// POST body:
//
//	{}                                          → run all built-in scenarios
//	{"type":"honeypot","port":4444,"payload":"USER root\r\n"}
//	{"type":"ips","src_ip":"10.0.0.1","severity":1,"signature":"ET TEST","category":"Test"}
func (s *HTTPServer) handleSecurityTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	var body struct {
		Type      string `json:"type"`      // "honeypot" | "ips" | "" = all
		Port      int    `json:"port"`      // honeypot port to probe (0 = use temp port)
		Payload   string `json:"payload"`   // bytes to send
		SrcIP     string `json:"src_ip"`
		Severity  int    `json:"severity"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
	}
	// Empty body is valid (runs all scenarios).
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

	var triggered []ThreatEvent

	switch body.Type {
	case "", "all":
		triggered = s.RunTestScenarios()

	case "honeypot":
		port := body.Port
		if port == 0 {
			port = tempHoneypotPort
			existing := s.honeypotSrv.ActivePorts()
			s.honeypotSrv.UpdatePorts(append(existing, port))
			time.Sleep(80 * time.Millisecond)
			defer s.honeypotSrv.UpdatePorts(existing)
		}
		e, err := s.probeHoneypot(port, body.Payload)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: err.Error()})
			return
		}
		if e != nil {
			triggered = append(triggered, *e)
		}

	case "ips":
		src := body.SrcIP
		if src == "" {
			src = "10.0.254.1"
		}
		sev := body.Severity
		if sev == 0 {
			sev = 1
		}
		sig := body.Signature
		if sig == "" {
			sig = "ET TEST Manual injection"
		}
		cat := body.Category
		if cat == "" {
			cat = categoryForSeverity(sev)
		}
		e := s.injectIPSEvent(src, sev, sig, cat)
		triggered = append(triggered, e)

	default:
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "type must be honeypot, ips, or all"})
		return
	}

	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"triggered": triggered,
		"count":     len(triggered),
	}})
}

// handleSecurityEvents returns recent threat events (IPS + honeypot).
func (s *HTTPServer) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	events := s.threatStore.Recent(500)
	if events == nil {
		events = []ThreatEvent{}
	}
	ports := s.honeypotSrv.ActivePorts()
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"events":          events,
		"honeypot_active": ports,
	}})
}

// handleSecuritySignatures returns the threat intel feed status (GET) or triggers
// an immediate refresh (POST).
func (s *HTTPServer) handleSecuritySignatures(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.sigUpdater.Status()})
	case http.MethodPost:
		go s.sigUpdater.fetch()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": "refresh triggered"}})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// handleSecuritySummary returns counts for the dashboard badge.
func (s *HTTPServer) handleSecuritySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	total, critical, honeypot := s.threatStore.Summary()
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"total":    total,
		"critical": critical,
		"honeypot": honeypot,
	}})
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

// handleCameraSubroutes routes /api/cameras/{id}/snapshot and /api/cameras/{id}/live.
func (s *HTTPServer) handleCameraSubroutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/cameras/")
	parts := strings.SplitN(strings.Trim(path, "/"), "/", 2)
	if len(parts) < 2 {
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
	switch parts[1] {
	case "snapshot":
		highQuality := r.URL.Query().Get("highQuality") == "true"
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		data, contentType, err := c.CameraSnapshot(ctx, cameraID, highQuality)
		if err != nil {
			log.Printf("[unifideck] camera snapshot failed id=%s err=%v", cameraID, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if contentType == "" {
			contentType = "image/jpeg"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case "live":
		s.handleCameraLive(w, r, c, cameraID)
	default:
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
	}
}

// handleCameraLive streams a multipart/x-mixed-replace MJPEG feed for one camera.
// It continuously fetches high-quality snapshots (~5 fps) and pushes them as
// JPEG frames until the client closes the connection.
func (s *HTTPServer) handleCameraLive(w http.ResponseWriter, r *http.Request, c *UnifiClient, cameraID string) {
	const (
		boundary      = "unifidecklive"
		frameInterval = 200 * time.Millisecond // 5 fps
		frameTimeout  = 4 * time.Second
	)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary="+boundary)
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

	ctx := r.Context()
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()

	log.Printf("[unifideck] live stream start cam=%s", cameraID)
	frames := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("[unifideck] live stream end cam=%s frames=%d", cameraID, frames)
			return
		case <-ticker.C:
			snapCtx, cancel := context.WithTimeout(ctx, frameTimeout)
			data, _, err := c.CameraSnapshot(snapCtx, cameraID, true) // always high quality
			cancel()
			if err != nil {
				continue // skip frames on transient errors; stop only on client disconnect
			}
			hdr := fmt.Sprintf("--%s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n",
				boundary, len(data))
			if _, err := fmt.Fprint(w, hdr); err != nil {
				return
			}
			if _, err := w.Write(data); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, "\r\n"); err != nil {
				return
			}
			flusher.Flush()
			frames++
		}
	}
}

// ── Snapshot handlers ──────────────────────────────────────────────────────────

// GET /api/snapshots — returns schedule config + all snapshots grouped by camera.
func (s *HTTPServer) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	groups := s.snapStore.GroupedByCameraAPI()
	if groups == nil {
		groups = []CameraSnapshotGroupAPI{}
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"schedule": s.snapStore.GetScheduleConfig(),
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
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.snapStore.GetScheduleConfig()})
		case http.MethodPost:
			var cfg SnapshotScheduleConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
				return
			}
			if err := s.snapStore.SaveScheduleConfig(cfg); err != nil {
				writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
				return
			}
			s.logger.Info("snapshot schedule updated: %d rule(s), retain=%dd", len(cfg.Rules), cfg.RetainDays)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: cfg})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		}

	case "capture":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
			return
		}
		// Optional body: {"camera_ids": ["id1","id2"]} — omit or empty to capture all.
		var body struct {
			CameraIDs []string `json:"camera_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body) // ignore decode error; body is optional
		s.snapScheduler.CaptureNow(body.CameraIDs)
		if len(body.CameraIDs) > 0 {
			s.logger.Info("snapshot capture triggered manually for %d camera(s)", len(body.CameraIDs))
		} else {
			s.logger.Info("snapshot capture triggered manually (all cameras)")
		}
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

// ── Config Snapshot handlers ───────────────────────────────────────────────────

// GET  /api/config-snapshots         → list all snapshots + schedule
// POST /api/config-snapshots         → capture a new snapshot now
func (s *HTTPServer) handleConfigSnapshots(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snaps := s.cfgSnapStore.List()
		sched := s.cfgSnapStore.GetSchedule()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"snapshots": snaps,
			"schedule":  sched,
			"count":     len(snaps),
		}})

	case http.MethodPost:
		var body struct {
			Label string `json:"label"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		c := s.unifiClient()
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()

		snap, err := s.cfgSnapStore.Capture(ctx, c, body.Label, "manual", s.snapshotCfg())
		if err != nil {
			s.logger.Warn("config snapshot capture failed: %v", err)
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("config snapshot captured id=%s label=%q nets=%d policies=%d",
			snap.ID, snap.Label, snap.Summary.Networks, snap.Summary.Policies)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: snap})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// handleConfigSnapshotSubroutes routes /api/config-snapshots/{id|verb}
func (s *HTTPServer) handleConfigSnapshotSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/config-snapshots/")
	path = strings.Trim(path, "/")

	switch path {
	case "schedule":
		s.handleCfgSnapSchedule(w, r)
	case "diff":
		s.handleCfgSnapDiff(w, r)
	case "backup":
		s.handleCfgBackup(w, r)
	default:
		// /api/config-snapshots/{id}
		if path == "" {
			writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "not found"})
			return
		}
		id := path
		switch r.Method {
		case http.MethodGet:
			data, err := s.cfgSnapStore.Get(id)
			if err != nil {
				writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: data})
		case http.MethodDelete:
			if err := s.cfgSnapStore.Delete(id); err != nil {
				writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: err.Error()})
				return
			}
			s.logger.Info("config snapshot deleted id=%s", id)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]bool{"deleted": true}})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		}
	}
}

// GET/POST /api/config-snapshots/schedule
func (s *HTTPServer) handleCfgSnapSchedule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: s.cfgSnapStore.GetSchedule()})
	case http.MethodPost:
		var sched ConfigSnapshotSchedule
		if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		if err := s.cfgSnapStore.SaveSchedule(sched); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: sched})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// GET /api/config-snapshots/diff?a={id}&b={id}
func (s *HTTPServer) handleCfgSnapDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	idA := r.URL.Query().Get("a")
	idB := r.URL.Query().Get("b")
	if idA == "" || idB == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "a and b snapshot IDs required"})
		return
	}
	diff, err := s.cfgSnapStore.Diff(idA, idB)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: diff})
}

// POST /api/config-snapshots/backup — download a UniFi config backup file
func (s *HTTPServer) handleCfgBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	data, _, err := c.TriggerBackup(ctx)
	if err != nil {
		s.logger.Warn("unifi backup failed: %v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	filename := fmt.Sprintf("unifi-backup-%s.unf", time.Now().Format("20060102-150405"))
	s.logger.Info("unifi backup downloaded size=%d", len(data))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// GET /api/audit — recent UniFi system events
func (s *HTTPServer) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"events":    []any{},
			"configured": false,
		}})
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	events, err := c.ListAuditEvents(ctx, limit)
	if err != nil {
		s.logger.Warn("audit log err=%v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"events":     events,
		"configured": true,
	}})
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

// StartScheduler starts all background schedulers and the client device tracker.
func (s *HTTPServer) StartScheduler() {
	s.scheduler.Start()
	s.snapScheduler.Start()
	s.cfgSnapScheduler.Start()
	s.clientTracker.Start(func(ctx context.Context) ([]Client, error) {
		c := s.unifiClient()
		if !c.IsConfigured() {
			return nil, nil // not configured yet — skip silently
		}
		return c.ListClients(ctx)
	})
	// Security: IPS poller + honeypot listeners.
	s.threatPoller.Start(func(ctx context.Context, since time.Time) ([]IPSEvent, error) {
		c := s.unifiClient()
		if !c.IsConfigured() {
			return nil, nil
		}
		return c.ListIPSEvents(ctx, since)
	})
	cfg := s.snapshotCfg()
	s.honeypotSrv.UpdatePorts(cfg.HoneypotPorts)
	// Wire webhook after we have cfg.
	s.honeypotSrv.webhookFn = s.fireSecurityWebhook
	// Signature feed updater — apply saved mode then start.
	if cfg.ThreatFeedMode != "" {
		s.sigUpdater.SetMode(ValidThreatFeedMode(cfg.ThreatFeedMode))
	}
	s.sigUpdater.Start()
}

// StopScheduler stops all schedulers, the client tracker, and security components.
func (s *HTTPServer) StopScheduler() {
	s.scheduler.Stop()
	s.snapScheduler.Stop()
	s.cfgSnapScheduler.Stop()
	s.clientTracker.Stop()
	s.threatPoller.Stop()
	s.honeypotSrv.StopAll()
	s.sigUpdater.Stop()
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

// fireSecurityWebhook POSTs a ThreatEvent to the configured security webhook URL.
// Called by the honeypot server (and can be called for IPS events in future).
func (s *HTTPServer) fireSecurityWebhook(e ThreatEvent) {
	cfg := s.snapshotCfg()
	url := strings.TrimSpace(cfg.SecurityWebhookURL)
	if url == "" {
		return
	}
	go func() {
		b, err := json.Marshal(e)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			log.Printf("[threats] webhook request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("[threats] webhook delivery error: %v", err)
			return
		}
		resp.Body.Close()
		log.Printf("[threats] webhook fired → %s (HTTP %d)", url, resp.StatusCode)
	}()
}
