package unifideck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPServer wires HTTP routes to UniFi + automations + snapshots.
type HTTPServer struct {
	mu  sync.RWMutex
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
	clientBrake      *ClientBrake
	fleetDB          *FleetDB

	// conntrack-derived per-device rates (real throughput for EVERY device incl. WiFi,
	// where UniFi's per-client counters are stale). Background poller diffs snapshots.
	connMu    sync.Mutex
	connRates map[string][2]float64 // ip -> {upBps, downBps}
	connPrev  map[string][2]float64 // ip -> cumulative {up, down} bytes
	connPrevT time.Time
	connOnce  sync.Once
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
		fleetDB:        nil,
	}
	s.watchdog = NewUDMWatchdog(watchdogCfgPath, s.snapshotCfg)
	brakeCfgPath := filepath.Join(DataDir(), "client-brake.json")
	s.clientBrake = NewClientBrake(brakeCfgPath, s.snapshotCfg)
	s.scheduler = NewAutomationScheduler(s.store, s.logger, s.unifiClient)
	s.snapScheduler = NewSnapshotScheduler(snapStore, logger, s.unifiClient)
	s.cfgSnapScheduler = NewConfigSnapshotScheduler(cfgSnapStore, logger, s.unifiClient, s.snapshotCfg)
	log.Printf("[unifideck] automations file: %s (%d loaded)", autoPath, store.LoadedCount())
	log.Printf("[unifideck] snapshots dir   : %s (%d stored)", filepath.Join(DataDir(), "snapshots"), snapStore.Count())
	log.Printf("[unifideck] config snapshots: %s (%d stored)", filepath.Join(DataDir(), "config-snapshots"), cfgSnapStore.Count())
	log.Printf("[unifideck] activity log    : %s", logPath)
	// Warm the conntrack rate poller at BOOT so per-device (incl. WiFi) rates are ready
	// before the first page load — no more "wait minutes for the animation to appear".
	s.connOnce.Do(func() { go s.startConnPoller() })
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

// SnapshotCfg is a public accessor for the current config, used by FleetPoller.
func (s *HTTPServer) SnapshotCfg() AppConfig {
	return s.snapshotCfg()
}

// SetFleetDB sets the fleet database for time-series storage.
func (s *HTTPServer) SetFleetDB(db *FleetDB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fleetDB = db
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
	mux.HandleFunc("/api/fleet/summary", s.handleFleetSummary)
	mux.HandleFunc("/api/networks", s.handleNetworks)
	mux.HandleFunc("/api/networks/", s.handleNetworkSubroutes)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/new", s.handleClientsNew)
	mux.HandleFunc("/api/clients/dismiss", s.handleClientsDismiss)
	mux.HandleFunc("/api/clients/block", s.handleClientBlock)
	mux.HandleFunc("/api/security/events", s.handleSecurityEvents)
	mux.HandleFunc("/api/security/status", s.handleSecurityStatus)
	mux.HandleFunc("/api/security/webhook/test", s.handleSecurityWebhookTest)
	mux.HandleFunc("/api/security/vlans", s.handleHoneypotVLANs)
	mux.HandleFunc("/api/security/agents/events", s.handleHoneypotAgentEvent)
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
	mux.HandleFunc("/api/drift/site", s.handleDriftSite)
	mux.HandleFunc("/api/drift/gold", s.handleDriftGold)
	mux.HandleFunc("/api/capacity/site", s.handleCapacitySite)
	mux.HandleFunc("/api/capacity/eol", s.handleCapacityEOL)
	mux.HandleFunc("/api/capacity/summary", s.handleCapacitySummary)
	mux.HandleFunc("/api/rf/site", s.handleRFSite)
	mux.HandleFunc("/api/isp/summary", s.handleISPSummary)
	mux.HandleFunc("/api/isp/status", s.handleISPStatus)
	mux.HandleFunc("/api/isp/history", s.handleISPHistory)
	mux.HandleFunc("/api/isp/traffic", s.handleISPTraffic)
	mux.HandleFunc("/api/isp/traffic/flow-audit", s.handleISPFlowAudit)
	mux.HandleFunc("/api/isp/traffic/attribution", s.handleISPTrafficAttribution)
	s.registerUDMRoutes(mux)

	// Auto-start watchdog if it was previously enabled.
	if s.watchdog.Status().Config.Enabled {
		_ = s.watchdog.Start()
	}
	// Auto-start upload brake if it was previously enabled.
	if s.clientBrake.Status().Config.Enabled {
		_ = s.clientBrake.Start()
	}

	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/topology/stream", s.handleTopologyStream)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.Handle("/", http.FileServer(http.FS(webFS)))
	return corsMiddleware(mux)
}

// corsMiddleware adds permissive CORS headers so the topology viz can be opened from any origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleTopology returns live devices + clients in one call, purpose-built for the 3D topology viz.
func (s *HTTPServer) handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"devices": []any{}, "clients": []any{}, "configured": false,
		}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	data, err := s.buildTopologyData(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: data})
}

// handleFlows SSHes to the UDM, runs conntrack, and returns every active flow whose
// DESTINATION is a public/external IP — i.e. a LAN device talking to the internet.
// This is the foundation for "suspicious IoT": the viz maps src → node and flags
// devices (especially on the IoT VLAN) reaching unexpected external hosts.
func (s *HTTPServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	out, err := s.fetchConntrack(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	flows := parseExternalFlows(out)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"flows": flows, "count": len(flows)}})
}

// fetchConntrack SSHes to the UDM and returns `conntrack -L` output (every active flow
// with per-connection byte counts). Shared by the external-flow endpoint and the
// per-device rate poller.
func (s *HTTPServer) fetchConntrack(ctx context.Context) (string, error) {
	cfg := s.snapshotCfg()
	// SSH and the Network API do not necessarily use the same address. In this
	// setup the API host may be a controller alias while SSH is pinned to the
	// UDM's management address. Using UnifiHost here made /api/flows fail after
	// reboots or network readdressing even though the configured SSH connection
	// worked.
	host := cfg.SSHHost
	if host == "" {
		host = strings.Split(strings.TrimPrefix(strings.TrimPrefix(cfg.UnifiHost, "https://"), "http://"), ":")[0]
	}
	if host == "" {
		return "", fmt.Errorf("UDM SSH host not configured")
	}
	key := cfg.SSHKeyPath
	if key == "" {
		key = filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519")
	}
	port := cfg.SSHPort
	if port == "" {
		port = "22"
	}
	out, err := exec.CommandContext(ctx, "ssh", "-i", key, "-p", port,
		"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=7", "-o", "BatchMode=yes",
		"root@"+host, "conntrack -L 2>/dev/null").Output()
	if err != nil {
		return "", fmt.Errorf("ssh/conntrack: %w", err)
	}
	return string(out), nil
}

// parseConntrackCumulative sums per-device cumulative up/down bytes from conntrack.
// Each entry has an original direction (src→dst, first bytes=) and a reply (second bytes=).
// For the original src: up=orig, down=reply. For the original dst: up=reply, down=orig.
func parseConntrackCumulative(out string) map[string][2]float64 {
	cum := map[string][2]float64{}
	add := func(ip string, up, down float64) {
		if ip == "" || !isPrivateIP(ip) {
			return
		}
		v := cum[ip]
		v[0] += up
		v[1] += down
		cum[ip] = v
	}
	for _, line := range strings.Split(out, "\n") {
		var os, od string
		var ob, rb float64
		srcN, dstN, byteN := 0, 0, 0
		for _, tok := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(tok, "src="):
				if srcN == 0 {
					os = tok[4:]
				}
				srcN++
			case strings.HasPrefix(tok, "dst="):
				if dstN == 0 {
					od = tok[4:]
				}
				dstN++
			case strings.HasPrefix(tok, "bytes="):
				v, _ := strconv.ParseFloat(tok[6:], 64)
				if byteN == 0 {
					ob = v
				} else if byteN == 1 {
					rb = v
				}
				byteN++
			}
		}
		add(os, ob, rb)
		add(od, rb, ob)
	}
	return cum
}

// startConnPoller refreshes per-device conntrack rates every 6s in the background.
func (s *HTTPServer) startConnPoller() {
	tick := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		out, err := s.fetchConntrack(ctx)
		if err != nil {
			return
		}
		cum := parseConntrackCumulative(out)
		now := time.Now()
		s.connMu.Lock()
		rates := map[string][2]float64{}
		if !s.connPrevT.IsZero() {
			if dt := now.Sub(s.connPrevT).Seconds(); dt > 0.5 {
				for ip, c := range cum {
					p := s.connPrev[ip]
					up, down := (c[0]-p[0])/dt, (c[1]-p[1])/dt
					if up < 0 {
						up = 0
					}
					if down < 0 {
						down = 0
					}
					rates[ip] = [2]float64{up, down}
				}
			}
		}
		s.connPrev, s.connPrevT, s.connRates = cum, now, rates
		s.connMu.Unlock()
	}
	// Fast warmup: first snapshot, then a 2nd ~2.5s later so real rates are available
	// within ~3s of boot (instead of waiting a full 6s tick). Then settle to 4s.
	tick()
	time.Sleep(2500 * time.Millisecond)
	tick()
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	for range t.C {
		tick()
	}
}

func (s *HTTPServer) conntrackRates() map[string][2]float64 {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.connRates
}

// parseExternalFlows extracts flows with a public destination from `conntrack -L` output.
func parseExternalFlows(out string) []map[string]any {
	var flows []map[string]any
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := f[0]
		var src, dst, dport string
		var totBytes int64
		for _, tok := range f {
			switch {
			case strings.HasPrefix(tok, "src=") && src == "":
				src = tok[4:]
			case strings.HasPrefix(tok, "dst=") && dst == "":
				dst = tok[4:]
			case strings.HasPrefix(tok, "dport=") && dport == "":
				dport = tok[6:]
			case strings.HasPrefix(tok, "bytes="):
				if v, e := strconv.ParseInt(tok[6:], 10, 64); e == nil {
					totBytes += v
				}
			}
		}
		if src == "" || dst == "" || !isExternalIP(dst) || !isPrivateIP(src) {
			continue // want LAN-device → public-internet flows only
		}
		flows = append(flows, map[string]any{"src": src, "dst": dst, "dport": dport, "proto": proto, "bytes": totBytes})
	}
	return flows
}

func isExternalIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// exclude CGNAT 100.64.0.0/10 (carrier / Tailscale-ish space)
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}

// buildTopologyData assembles the full topology payload (devices + clients + cameras,
// with trunk uplink rates annotated). Shared by the one-shot handler and the SSE stream.
func (s *HTTPServer) buildTopologyData(ctx context.Context, c *UnifiClient) (map[string]any, error) {
	devices, err := c.ListDevicesRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	clients, err := c.ListActiveClientsRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("clients: %w", err)
	}
	// Trunk uplink rates so traffic is conserved up to the router (controller-measured).
	annotateUplinkRates(devices)
	// Per-device rates from conntrack (covers WiFi devices, which UniFi's API reports
	// stale/zero for). Background poller; first reading appears after ~6s.
	s.connOnce.Do(func() { go s.startConnPoller() })
	rates := s.conntrackRates()
	if rates != nil {
		for _, cl := range clients {
			if ip, _ := cl["ip"].(string); ip != "" {
				if r, ok := rates[ip]; ok {
					cl["up_bps"] = r[0]
					cl["down_bps"] = r[1]
				}
			}
		}
	}
	// Cameras as real nodes with their switch-port bitrate (wireless cams via conntrack).
	cameras := buildCameraNodes(ctx, c, devices, rates)
	return map[string]any{"devices": devices, "clients": clients, "cameras": cameras}, nil
}

// handleTopologyStream pushes the topology over SSE every few seconds — one persistent
// connection instead of repeated polls (the lightest live-delivery approach). The
// underlying UniFi data only refreshes every few seconds, so 4s cadence is plenty.
func (s *HTTPServer) handleTopologyStream(w http.ResponseWriter, r *http.Request) {
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: false, Error: "unifi not configured"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	push := func() bool {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		data, err := s.buildTopologyData(ctx, c)
		if err != nil {
			return true // skip this tick, keep the stream open
		}
		b, err := json.Marshal(data)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: topology\ndata: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	push() // immediate first frame
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

// annotateUplinkRates adds up_bps/down_bps to each device from its uplink port's
// live rate (tx_bytes-r = up toward parent, rx_bytes-r = down). This makes the trunk
// links carry the real aggregate (e.g. a switch's cameras visibly flow up to the
// router) instead of vanishing. Falls back to the device.uplink object if no port is
// flagged is_uplink. Leaves up_bps absent if neither source has it (viz then uses deltas).
func annotateUplinkRates(devices []map[string]any) {
	toF := func(v any) float64 {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		}
		return 0
	}
	max := func(a, b float64) float64 {
		if a > b {
			return a
		}
		return b
	}
	for _, d := range devices {
		// Two independent measures of trunk traffic, because the uplink-port rate field
		// is FLAKY on some switches (intermittently reports 0 between polls):
		//   1) the uplink port's own tx/rx-r
		//   2) the SUM of downstream ports (rx = traffic going up, tx = coming down) — conserved
		// Take the max per direction so a momentary 0 on one source can't blank the trunk.
		var ulTx, ulRx, dnRx, dnTx float64
		if pt, ok := d["port_table"].([]any); ok {
			for _, pi := range pt {
				pm, _ := pi.(map[string]any)
				if isUp, _ := pm["is_uplink"].(bool); isUp {
					ulTx += toF(pm["tx_bytes-r"])
					ulRx += toF(pm["rx_bytes-r"])
				} else {
					dnRx += toF(pm["rx_bytes-r"]) // received from a downstream device → flows UP
					dnTx += toF(pm["tx_bytes-r"]) // sent to a downstream device → came DOWN
				}
			}
		}
		up, down := max(ulTx, dnRx), max(ulRx, dnTx)
		if up == 0 && down == 0 { // APs with no usable port_table → fall back to the uplink object
			if ul, ok := d["uplink"].(map[string]any); ok {
				up, down = toF(ul["tx_bytes-r"]), toF(ul["rx_bytes-r"])
			}
		}
		if up > 0 || down > 0 {
			d["up_bps"] = up
			d["down_bps"] = down
		}
	}
}

// buildCameraNodes correlates Protect cameras → station (uplink/port) → switch
// port_table (byte counters), emitting camera entries the 3D viz renders as nodes
// wired to their switch with real upload flow.
func buildCameraNodes(ctx context.Context, c *UnifiClient, devices []map[string]any, connRates map[string][2]float64) []map[string]any {
	cams, err := c.ListCameras(ctx)
	if err != nil || len(cams) == 0 {
		return []map[string]any{}
	}
	stas, err := c.ListStationsRaw(ctx)
	if err != nil {
		return []map[string]any{}
	}
	normMac := func(v any) string {
		s := strings.ToLower(fmt.Sprint(v))
		return strings.NewReplacer(":", "", "-", "").Replace(s)
	}
	str := func(v any) string { s, _ := v.(string); return s }
	toF := func(v any) float64 {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		}
		return 0
	}
	toI := func(v any) int { return int(toF(v)) }

	staByMac := map[string]map[string]any{}
	for _, s := range stas {
		staByMac[normMac(s["mac"])] = s
	}
	// per-switch-port stats: cumulative bytes + controller-measured instantaneous
	// rate (bytes-r). The cumulative counters refresh slowly (~30-60s), so the viz
	// uses the -r rate fields for cameras instead of computing deltas.
	portStats := func(swMac string, port int) (txR, rxR float64, ok bool) {
		for _, d := range devices {
			if normMac(d["mac"]) != normMac(swMac) {
				continue
			}
			pt, _ := d["port_table"].([]any)
			for _, pi := range pt {
				pm, _ := pi.(map[string]any)
				if toI(pm["port_idx"]) == port {
					return toF(pm["tx_bytes-r"]), toF(pm["rx_bytes-r"]), true
				}
			}
		}
		return 0, 0, false
	}

	out := []map[string]any{}
	for _, cam := range cams {
		sta := staByMac[normMac(cam.MAC)]
		if sta == nil {
			continue // camera not seen on the network right now
		}
		wired, _ := sta["is_wired"].(bool)
		var uplink string
		var upBps, downBps float64
		if wired {
			uplink = str(sta["sw_mac"])
			if txR, rxR, ok := portStats(uplink, toI(sta["sw_port"])); ok {
				upBps, downBps = rxR, txR // switch rx-rate = camera upload (video to NVR)
			}
		} else {
			uplink = str(sta["ap_mac"])
			upBps, downBps = toF(sta["rx_bytes-r"]), toF(sta["tx_bytes-r"])
		}
		// Wireless cams report stale 0 via UniFi — use conntrack rate by IP instead.
		if (upBps == 0 && downBps == 0) && connRates != nil {
			if r, ok := connRates[str(sta["ip"])]; ok {
				upBps, downBps = r[0], r[1]
			}
		}
		out = append(out, map[string]any{
			"mac": cam.MAC, "name": cam.Name, "id": cam.ID,
			"uplink_mac": uplink, "up_bps": upBps, "down_bps": downBps,
			"is_camera": true, "is_wired": wired,
		})
	}
	return out
}

// registerUDMRoutes adds all UDM Pro-specific API routes.
func (s *HTTPServer) registerUDMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/client-brake", s.handleClientBrake)
	mux.HandleFunc("/api/udm-process-scan", s.handleUDMProcessScan)
	mux.HandleFunc("/api/udm-watchdog", s.handleUDMWatchdog)
	mux.HandleFunc("/api/udm-sysconfig", s.handleUDMSysConfig)
	mux.HandleFunc("/api/udm-deploy", s.handleUDMDeploy)
}

// handleHealth reports service liveness, data dir, and loaded automation count.
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"service":     "unifi-smash-deck",
		"data_dir":    DataDir(),
		"automations": s.store.LoadedCount(),
	}})
}

// handleFleetSummary returns a rolled-up online status across all polled sites.
func (s *HTTPServer) handleFleetSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	summary, err := s.fleetDB.QueryFleetSummary()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: summary})
}

// handleSettings reads (GET), saves (POST), or tests (PUT) the app configuration.
func (s *HTTPServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.snapshotCfg()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"port":                       cfg.Port,
			"unifi_host":                 cfg.UnifiHost,
			"unifi_site":                 cfg.UnifiSite,
			"unifi_api_key":              maskKey(cfg.UnifiAPIKey),
			"honeypot_ports":             cfg.HoneypotPorts,
			"controller_honeypot_ips":    cfg.ControllerHoneypotIPs,
			"honeypot_vlans":             cfg.HoneypotVLANs,
			"adaptix_profile":            cfg.AdaptixProfile,
			"windows_profile":            cfg.WindowsProfile,
			"security_webhook_url":       cfg.SecurityWebhookURL,
			"honeypot_ingest_configured": cfg.HoneypotIngestToken != "",
			"threat_feed_mode":           cfg.ThreatFeedMode,
		}})
	case http.MethodPost:
		var body struct {
			Port                  string         `json:"port"`
			UnifiHost             string         `json:"unifi_host"`
			UnifiSite             string         `json:"unifi_site"`
			UnifiAPIKey           string         `json:"unifi_api_key"`
			UnifiPass             string         `json:"unifi_pass"` // backward compat alias
			HoneypotPorts         []int          `json:"honeypot_ports"`
			ControllerHoneypotIPs []string       `json:"controller_honeypot_ips"`
			HoneypotVLANs         []HoneypotVLAN `json:"honeypot_vlans"`
			HoneypotIngestToken   string         `json:"honeypot_ingest_token"`
			AdaptixProfile        AdaptixProfile `json:"adaptix_profile"`
			WindowsProfile        WindowsProfile `json:"windows_profile"`
			SecurityWebhookURL    string         `json:"security_webhook_url"`
			ThreatFeedMode        string         `json:"threat_feed_mode"`
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
		if body.ControllerHoneypotIPs != nil {
			cur.ControllerHoneypotIPs = body.ControllerHoneypotIPs
		}
		if body.HoneypotVLANs != nil {
			cur.HoneypotVLANs = body.HoneypotVLANs
		}
		if body.HoneypotIngestToken != "" {
			cur.HoneypotIngestToken = body.HoneypotIngestToken
		}
		if body.AdaptixProfile.HTTPHeader != "" || body.AdaptixProfile.HTTPPaths != nil || body.AdaptixProfile.HTTPUserAgents != nil || body.AdaptixProfile.DNSSuffixes != nil {
			cur.AdaptixProfile = body.AdaptixProfile
		}
		if body.WindowsProfile.Persona != "" || body.WindowsProfile.OS != "" || body.WindowsProfile.Enabled {
			cur.WindowsProfile = normalizeWindowsProfile(body.WindowsProfile)
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
		if s.threatPoller != nil {
			s.threatPoller.SetHoneypotIPs(cur.ControllerHoneypotIPs)
		}
		s.honeypotSrv.SetAdaptixProfile(cur.AdaptixProfile)
		s.honeypotSrv.SetWindowsProfile(cur.WindowsProfile)
		s.honeypotSrv.SetHoneypotVLANs(cur.HoneypotVLANs)
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

// handleHoneypotAgentEvent accepts an event from a companion sensor. The
// shared token is intentionally only accepted in a header and is never
// returned by the settings API.
func (s *HTTPServer) handleHoneypotAgentEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	cfg := s.snapshotCfg()
	if cfg.HoneypotIngestToken == "" || r.Header.Get("X-Honeypot-Agent-Token") != cfg.HoneypotIngestToken {
		writeJSON(w, http.StatusUnauthorized, apiResp{Success: false, Error: "invalid agent token"})
		return
	}
	var input struct {
		AgentID   string       `json:"agent_id"`
		AgentName string       `json:"agent_name"`
		VLAN      HoneypotVLAN `json:"vlan"`
		Event     ThreatEvent  `json:"event"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid event payload"})
		return
	}
	if input.Event.ID == "" || input.Event.Kind != ThreatKindHoneypot {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "honeypot event required"})
		return
	}
	input.Event.AgentID, input.Event.AgentName = input.AgentID, input.AgentName
	if input.Event.VLAN == 0 {
		input.Event.VLAN = input.VLAN.VLAN
	}
	if input.Event.VLANName == "" {
		input.Event.VLANName = input.VLAN.NetworkName
	}
	if s.threatStore.Add(input.Event) {
		s.fireSecurityWebhook(input.Event)
	}
	writeJSON(w, http.StatusAccepted, apiResp{Success: true, Data: map[string]any{"accepted": true}})
}

// handleNetworks lists the UniFi networks/VLANs for the configured site.
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

// handleNetworkSubroutes enables or disables a UniFi network by ID.
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

// handleClients lists all currently connected clients for the configured site.
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
		Type      string `json:"type"`    // "honeypot" | "ips" | "" = all
		Port      int    `json:"port"`    // honeypot port to probe (0 = use temp port)
		Payload   string `json:"payload"` // bytes to send
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
		"events":              events,
		"honeypot_active":     ports,
		"honeypot_configured": s.snapshotCfg().HoneypotPorts,
	}})
}

// handleSecurityStatus exposes whether local listeners are actually active and
// whether the controller feed is producing data. This avoids reporting a
// configured-but-unbound honeypot as healthy.
func (s *HTTPServer) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	cfg := s.snapshotCfg()
	s.honeypotSrv.SetAdaptixProfile(cfg.AdaptixProfile)
	s.honeypotSrv.SetWindowsProfile(cfg.WindowsProfile)
	s.honeypotSrv.SetHoneypotVLANs(cfg.HoneypotVLANs)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"local_honeypot": map[string]any{
			"configured_ports": cfg.HoneypotPorts,
			"active_ports":     s.honeypotSrv.ActivePorts(),
			"enabled":          len(s.honeypotSrv.ActivePorts()) > 0,
			"windows_profile":  cfg.WindowsProfile,
		},
		"controller_honeypot_ips": cfg.ControllerHoneypotIPs,
		"controller_ips":          s.threatPoller.Status(),
	}})
}

// handleSecurityWebhookTest sends a non-persisted test payload to the configured
// webhook. It does not create a threat event or trigger a honeypot listener.
func (s *HTTPServer) handleSecurityWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	url := strings.TrimSpace(s.snapshotCfg().SecurityWebhookURL)
	if url == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "security webhook is not configured"})
		return
	}
	e := ThreatEvent{
		ID: "webhook-test", Kind: ThreatKindHoneypot, Timestamp: time.Now().UnixMilli(),
		SrcIP: "127.0.0.1", Severity: 1, Category: "Webhook Test", Action: "test",
		Signature: "AdaptixC2 webhook delivery test", Fingerprint: "AdaptixC2 webhook delivery test",
		Confidence: 100, Evidence: "manual test from UniFi Smash Deck",
	}
	sum := s.threatStore.HoneypotSummary(time.Now(), 15*time.Minute)
	payload := SecurityWebhookPayload{ThreatEvent: e, Summary: sum, Announcement: "Security alert. This is a honeypot webhook delivery test."}
	status, err := deliverSecurityWebhook(url, payload)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"status": "delivered", "http_status": status}})
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

// handleDevices lists the UniFi infrastructure devices for the configured site.
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

// handleCameras lists the UniFi Protect cameras for the configured site.
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

// handleSnapshots returns the snapshot schedule config and all snapshots grouped by camera.
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

// handleAutomations lists (GET) or creates (POST) automation rules.
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

// handleAutomationSubroutes runs (POST /{id}/run), updates (PUT), or deletes (DELETE) an automation.
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

// handleConfigSnapshots lists config snapshots with schedule (GET) or captures a new one now (POST).
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

// handleAuditLog returns recent UniFi system audit events.
func (s *HTTPServer) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"events":     []any{},
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

// handleLogs returns the most recent server log lines (default 200, max 5000).
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
	if s.threatPoller != nil {
		s.threatPoller.SetHoneypotIPs(cfg.ControllerHoneypotIPs)
	}
	s.honeypotSrv.SetAdaptixProfile(cfg.AdaptixProfile)
	s.honeypotSrv.SetWindowsProfile(cfg.WindowsProfile)
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

type SecurityWebhookPayload struct {
	ThreatEvent
	Summary      HoneypotSummary `json:"honeypot_summary"`
	Announcement string          `json:"announcement"`
}

func buildHoneypotAnnouncement(sum HoneypotSummary) string {
	if sum.EventCount == 0 {
		return "Security alert. A honeypot event was detected."
	}
	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(sum.ByFingerprint))
	for name, count := range sum.ByFingerprint {
		items = append(items, item{name, count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	parts := make([]string, 0, 3)
	for i, item := range items {
		if i == 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%d %s", item.count, item.name))
	}
	latest := ""
	if sum.Latest != nil {
		latest = fmt.Sprintf(" Latest was %s on port %d.", sum.Latest.Fingerprint, sum.Latest.DstPort)
	}
	return fmt.Sprintf("Security alert. In the last %d minutes, %d honeypot events were detected. Activity included %s.%s", sum.WindowMinutes, sum.EventCount, strings.Join(parts, ", "), latest)
}

// fireSecurityWebhook POSTs a ThreatEvent plus a rolling 15-minute summary to
// the configured security webhook URL. Consumers can use Announcement as
// ready-to-speak text without reconstructing the event history.
// Called by the honeypot server (and can be called for IPS events in future).
func (s *HTTPServer) fireSecurityWebhook(e ThreatEvent) {
	cfg := s.snapshotCfg()
	url := strings.TrimSpace(cfg.SecurityWebhookURL)
	if url == "" {
		return
	}
	sum := s.threatStore.HoneypotSummary(time.Now(), 15*time.Minute)
	payload := SecurityWebhookPayload{ThreatEvent: e, Summary: sum, Announcement: buildHoneypotAnnouncement(sum)}
	go func() {
		status, err := deliverSecurityWebhook(url, payload)
		if err != nil {
			log.Printf("[threats] webhook delivery error: %v", err)
			return
		}
		log.Printf("[threats] webhook fired → %s (HTTP %d)", url, status)
	}()
}

func deliverSecurityWebhook(url string, payload any) (int, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// ── Config Drift Detection handlers ────────────────────────────────────────

// handleDriftSite analyzes drift for a single site.
// GET /api/drift/site?site_id=xxx
func (s *HTTPServer) handleDriftSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}

	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required"})
		return
	}

	cfg := s.snapshotCfg()
	var site *SiteConnection
	for i := range cfg.Sites {
		if cfg.Sites[i].ID == siteID {
			site = &cfg.Sites[i]
			break
		}
	}
	if site == nil {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "site not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	report, err := AnalyzeDrift(ctx, *site, cfg.GoldStandard)
	if err != nil {
		s.logger.Warn("drift analysis failed site=%s err=%v", siteID, err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: report})
}

// handleDriftGold retrieves (GET) or updates (POST) the gold standard config.
func (s *HTTPServer) handleDriftGold(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.snapshotCfg()
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: cfg.GoldStandard})

	case http.MethodPost:
		var gold GoldStandard
		if err := json.NewDecoder(r.Body).Decode(&gold); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}

		cfg := s.snapshotCfg()
		cfg.GoldStandard = gold
		if err := SaveAppConfig(s.settingsPath, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}

		s.replaceCfg(cfg)
		s.logger.Info("gold standard config updated")
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: gold})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// ── Capacity & Hardware Lifecycle handlers ─────────────────────────────────

// handleCapacitySite analyzes PoE and RAM capacity for a single site.
// GET /api/capacity/site?site_id=xxx
func (s *HTTPServer) handleCapacitySite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}

	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required"})
		return
	}

	cfg := s.snapshotCfg()
	var site *SiteConnection
	for i := range cfg.Sites {
		if cfg.Sites[i].ID == siteID {
			site = &cfg.Sites[i]
			break
		}
	}
	// Fall back to legacy single-site config if no explicit site list.
	if site == nil && cfg.UnifiHost != "" && cfg.UnifiAPIKey != "" {
		legacy := SiteConnection{
			ID:       "legacy",
			Name:     "default",
			Type:     "unifi",
			Host:     cfg.UnifiHost,
			Token:    cfg.UnifiAPIKey,
			SiteName: cfg.UnifiSite,
		}
		if siteID == "legacy" {
			site = &legacy
		}
	}
	if site == nil {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "site not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	poeReport, memReport, err := AnalyzeCapacity(ctx, *site)
	if err != nil {
		log.Printf("[capacity] site=%s err=%v", siteID, err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"poe":    poeReport,
		"memory": memReport,
	}})
}

// handleCapacityEOL returns all known EOL model dates.
// GET /api/capacity/eol
func (s *HTTPServer) handleCapacityEOL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: EOLList()})
}

// handleCapacitySummary returns fleet-wide capacity metrics from the fleet DB.
// GET /api/capacity/summary
func (s *HTTPServer) handleCapacitySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	summary, err := s.fleetDB.QueryCapacitySummary()
	if err != nil {
		log.Printf("[capacity] summary query err=%v", err)
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: summary})
}

// ── ISP / WAN Health handlers ─────────────────────────────────────────────────

// handleISPSummary returns per-ISP WAN health summary.
// GET /api/isp/summary?days=7
func (s *HTTPServer) handleISPSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		fmt.Sscanf(v, "%d", &days)
	}
	if days <= 0 || days > 90 {
		days = 7
	}
	summaries, err := s.fleetDB.QueryWANByISP(days)
	if err != nil {
		log.Printf("[isp] summary err=%v", err)
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"summaries": summaries, "days": days}})
}

// handleISPStatus returns the latest WAN status per site.
// GET /api/isp/status
func (s *HTTPServer) handleISPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	statuses, err := s.fleetDB.QueryLatestWANStatus()
	if err != nil {
		log.Printf("[isp] status err=%v", err)
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"sites": statuses}})
}

// handleISPHistory returns time-series WAN data for one site.
// GET /api/isp/history?site_id=xxx&hours=24
func (s *HTTPServer) handleISPHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required"})
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		fmt.Sscanf(v, "%d", &hours)
	}
	if hours <= 0 || hours > 720 {
		hours = 24
	}
	points, err := s.fleetDB.QueryWANHistory(siteID, hours)
	if err != nil {
		log.Printf("[isp] history site=%s err=%v", siteID, err)
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"points": points, "site_id": siteID, "hours": hours}})
}

// handleISPTraffic returns WAN (internet) download/upload bytes since local
// midnight for a site. GET /api/isp/traffic?site_id=xxx
//
// The numbers come from the gateway's WAN uplink port (eth8) cumulative byte
// counters, differenced against the first sample after midnight. This is
// real internet traffic only — eth8 is a pure WAN interface with no VLANs.
func (s *HTTPServer) handleISPTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		// Default to the first configured site if not specified.
		if sites := s.cfg.Sites; len(sites) > 0 {
			siteID = sites[0].ID
		}
	}
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required (no default site configured)"})
		return
	}

	// Fetch all samples from the last 36h (covers midnight even if poller
	// started early today) and compute "today" via midnight baseline.
	// Query a small window before local midnight so a poll straddling the
	// boundary is available to ComputeTodayTraffic. The computation itself
	// still uses the first sample at/after local midnight.
	sinceMidnight := localMidnightUnix(time.Now()) - 12*60*60
	samples, err := s.fleetDB.QueryWANTrafficSince(siteID, sinceMidnight)
	if err != nil {
		log.Printf("[isp] traffic site=%s err=%v", siteID, err)
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	// Recovery for databases written before persisted site IDs were loaded:
	// samples may be split across random IDs from prior restarts. Combine those
	// same-UDM counter readings long enough to restore the dashboard; new
	// samples use the stable site ID going forward.
	legacyRecovery := false
	if len(samples) < 2 {
		if recovered, rerr := s.fleetDB.QueryWANTrafficAcrossSitesSince(sinceMidnight); rerr == nil && len(recovered) >= 2 {
			samples = recovered
			legacyRecovery = true
		}
	}

	rxToday, txToday := ComputeTodayTraffic(samples)
	totalToday := rxToday + txToday

	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"site_id":         siteID,
		"interface":       expectedWANInterface,
		"counter_source":  "UDM gateway WAN uplink",
		"download_bytes":  rxToday,
		"upload_bytes":    txToday,
		"total_bytes":     totalToday,
		"download_gb":     fmt.Sprintf("%.2f", float64(rxToday)/1e9),
		"upload_gb":       fmt.Sprintf("%.2f", float64(txToday)/1e9),
		"total_gb":        fmt.Sprintf("%.2f", float64(totalToday)/1e9),
		"download_str":    formatBytes(rxToday),
		"upload_str":      formatBytes(txToday),
		"total_str":       formatBytes(totalToday),
		"sample_count":    len(samples),
		"legacy_recovery": legacyRecovery,
		"note":            "Real WAN (internet) traffic from gateway eth8 uplink. Cross-validated against SSH /proc/net/dev.",
	}})
}

// handleISPFlowAudit reads the UDM's historical traffic_flow records directly
// and reports the source/destination breakdown alongside the WAN counter. This
// is the forensic path for cases where client counters are stale or incomplete.
// GET /api/isp/traffic/flow-audit?hours=24
func (s *HTTPServer) handleISPFlowAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		fmt.Sscanf(v, "%d", &hours)
	}
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	end := time.Now()
	start := end.Add(-time.Duration(hours) * time.Hour)
	cfg := s.snapshotCfg()
	rows, err := QueryUDMWANFlows(cfg, start, end)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	var linkLookupError string
	if links, linkErr := CurrentUDMClientLinks(cfg); linkErr == nil {
		for i := range rows {
			if link, ok := links[strings.ToLower(rows[i].SourceMAC)]; ok {
				rows[i].CurrentName = link.Name
				rows[i].CurrentHostname = link.Hostname
				rows[i].CurrentSwitchMAC = link.SwitchMAC
				rows[i].CurrentSwitchPort = link.SwitchPort
				rows[i].CurrentLinkUp = link.LinkUp
			}
		}
	} else {
		linkLookupError = linkErr.Error()
		log.Printf("[isp] flow audit current-link lookup failed: %v", linkErr)
	}

	var flowUpload, flowDownload int64
	for _, row := range rows {
		flowUpload += row.UploadBytes
		flowDownload += row.DownloadBytes
	}

	data := map[string]any{
		"start":                 start,
		"end":                   end,
		"hours":                 hours,
		"interface":             expectedWANInterface,
		"counter_source":        "UDM gateway WAN uplink",
		"flow_source":           "UDM ace_audit.traffic_flow out.interface_name=eth8",
		"wan_upload_bytes":      nil,
		"wan_download_bytes":    nil,
		"flow_upload_bytes":     flowUpload,
		"flow_download_bytes":   flowDownload,
		"unattributed_upload":   nil,
		"unattributed_download": nil,
		"rows":                  rows,
		"note":                  "WAN totals come from eth8 counters; flow totals come from UDM ace_audit.traffic_flow. A positive remainder means the UDM flow collection did not expose every WAN byte in this window.",
	}
	if linkLookupError != "" {
		data["current_link_lookup_error"] = linkLookupError
	}

	// Compare against the same interval when local WAN snapshots are available.
	if s.fleetDB != nil {
		siteID := r.URL.Query().Get("site_id")
		if siteID == "" && len(cfg.Sites) > 0 {
			siteID = cfg.Sites[0].ID
		}
		if siteID != "" {
			samples, qerr := s.fleetDB.QueryWANTrafficSince(siteID, start.Unix()-300)
			if qerr == nil && len(samples) >= 2 {
				first, last := samples[0], samples[len(samples)-1]
				wanUpload := last.TXBytes - first.TXBytes
				wanDownload := last.RXBytes - first.RXBytes
				if wanUpload < 0 {
					wanUpload = 0
				}
				if wanDownload < 0 {
					wanDownload = 0
				}
				unattributedUpload := wanUpload - flowUpload
				if unattributedUpload < 0 {
					unattributedUpload = 0
				}
				unattributedDownload := wanDownload - flowDownload
				if unattributedDownload < 0 {
					unattributedDownload = 0
				}
				data["site_id"] = siteID
				data["wan_upload_bytes"] = wanUpload
				data["wan_download_bytes"] = wanDownload
				data["unattributed_upload"] = unattributedUpload
				data["unattributed_download"] = unattributedDownload
				data["flow_upload_coverage"] = float64(flowUpload) / float64(maxInt64(wanUpload, 1))
				data["flow_download_coverage"] = float64(flowDownload) / float64(maxInt64(wanDownload, 1))
			}
		}
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: data})
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// handleISPTrafficAttribution answers "who downloaded all that data?" — it
// diffs per-client byte counters between a baseline (default: midnight today)
// and the latest sample, then returns per-device download/upload deltas sorted
// by total bytes. GET /api/isp/traffic/attribution?site_id=xxx&hours=24
func (s *HTTPServer) handleISPTrafficAttribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	if s.fleetDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "fleet polling not available"})
		return
	}
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		if sites := s.cfg.Sites; len(sites) > 0 {
			siteID = sites[0].ID
		}
	}
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "site_id required"})
		return
	}

	// Default: since local midnight. Allow ?hours=N override.
	sinceTS := localMidnightUnix(time.Now())
	if v := r.URL.Query().Get("hours"); v != "" {
		var hours int
		fmt.Sscanf(v, "%d", &hours)
		if hours > 0 && hours <= 168 {
			sinceTS = time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
		}
	}

	baseline, err := s.fleetDB.QueryClientTrafficAt(siteID, sinceTS)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}
	latest, err := s.fleetDB.QueryClientTrafficLatest(siteID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
		return
	}

	attributions := AttributeClientTraffic(baseline, latest)

	// Sum totals for the header.
	var totalRX, totalTX int64
	for _, a := range attributions {
		totalRX += a.RXDelta
		totalTX += a.TXDelta
	}

	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
		"site_id":        siteID,
		"since_ts":       sinceTS,
		"total_download": totalRX,
		"total_upload":   totalTX,
		"total_dl_str":   formatBytes(totalRX),
		"total_ul_str":   formatBytes(totalTX),
		"client_count":   len(attributions),
		"clients":        attributions,
	}})
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/TB)
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.0f MB", float64(b)/MB)
	default:
		return fmt.Sprintf("%.0f KB", float64(b)/KB)
	}
}
