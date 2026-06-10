package unifideck

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// InsightDevice is one UniFi device's health row.
type InsightDevice struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Model      string  `json:"model"`
	IP         string  `json:"ip"`
	Firmware   string  `json:"firmware"`
	UptimeDays float64 `json:"uptime_days"`
	CPU        float64 `json:"cpu"`  // percent
	Mem        float64 `json:"mem"`  // percent
	Clients    int     `json:"clients"`
	LoadAvg1   float64 `json:"load_avg_1"`
}

// InsightClient is a connected station with traffic data.
type InsightClient struct {
	MAC      string  `json:"mac"`
	Hostname string  `json:"hostname"`
	IP       string  `json:"ip"`
	VLAN     int     `json:"vlan"`
	TxBytes  int64   `json:"tx_bytes"`
	RxBytes  int64   `json:"rx_bytes"`
	TxGB     float64 `json:"tx_gb"`
	RxGB     float64 `json:"rx_gb"`
	Uptime   int64   `json:"uptime"`
	Wired    bool    `json:"wired"`
	OUI      string  `json:"oui"`
}

// VlanSummary is per-VLAN aggregated stats.
type VlanSummary struct {
	VLAN    int     `json:"vlan"`
	Name    string  `json:"name"`
	Clients int     `json:"clients"`
	TxGB    float64 `json:"tx_gb"`
	RxGB    float64 `json:"rx_gb"`
}

// InsightFinding is one finding from the insights engine.
// Reuses FindingSeverity from network_health.go.
type InsightFinding struct {
	ID             string          `json:"id"`
	Severity       FindingSeverity `json:"severity"`
	Category       string          `json:"category"` // "device"|"clients"|"security"|"performance"
	Title          string          `json:"title"`
	Detail         string          `json:"detail"`
	Recommendation string          `json:"recommendation"`
}

// NetworkInsightsReport is the full payload for GET /api/network-insights.
type NetworkInsightsReport struct {
	RunAt        time.Time        `json:"run_at"`
	Configured   bool             `json:"configured"`
	Devices      []InsightDevice  `json:"devices"`
	TopTalkers   []InsightClient  `json:"top_talkers"`
	VlanSummary  []VlanSummary    `json:"vlan_summary"`
	TotalClients int              `json:"total_clients"`
	Findings     []InsightFinding `json:"findings"`
	Critical     int              `json:"critical"`
	Warning      int              `json:"warning"`
	Info         int              `json:"info"`
}

// ── Extended raw types ────────────────────────────────────────────────────────

// insightRawDevice extends rawDevice with the system-stats percentage fields.
type insightRawDevice struct {
	ID          string `json:"_id"`
	Name        string `json:"name"`
	Model       string `json:"model"`
	IP          string `json:"ip"`
	Version     string `json:"version"`
	Uptime      int64  `json:"uptime"`
	NumSta      int    `json:"num_sta"`
	SysStats    struct {
		MemUsed  float64 `json:"mem_used"`
		MemTotal float64 `json:"mem_total"`
		LoadAvg1 string  `json:"loadavg_1"`
	} `json:"sys_stats"`
	SystemStats struct {
		CPU string `json:"cpu"`
		Mem string `json:"mem"`
	} `json:"system-stats"`
}

// insightRawSta extends rawSta with traffic + VLAN fields.
type insightRawSta struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
	VLAN     int    `json:"vlan"`
	TxBytes  int64  `json:"tx_bytes"`
	RxBytes  int64  `json:"rx_bytes"`
	Uptime   int64  `json:"uptime"`
	Wired    bool   `json:"is_wired"`
	OUI      string `json:"oui"`
}

// ── Main entry point ──────────────────────────────────────────────────────────

func RunNetworkInsights(ctx context.Context, c *UnifiClient) (*NetworkInsightsReport, error) {
	report := &NetworkInsightsReport{
		RunAt:      time.Now().UTC(),
		Configured: c.IsConfigured(),
	}
	if !c.IsConfigured() {
		return report, nil
	}

	// Fetch devices and clients concurrently.
	type fetched struct {
		devices []insightRawDevice
		clients []insightRawSta
		devErr  error
		cliErr  error
	}
	ch := make(chan fetched, 1)
	go func() {
		var f fetched
		f.devices, f.devErr = insightFetchDevices(ctx, c)
		f.clients, f.cliErr = insightFetchClients(ctx, c)
		ch <- f
	}()
	f := <-ch

	if f.devErr != nil {
		return nil, fmt.Errorf("fetch devices: %w", f.devErr)
	}
	if f.cliErr != nil {
		return nil, fmt.Errorf("fetch clients: %w", f.cliErr)
	}

	// ── Build device list ──────────────────────────────────────────────────────

	for _, d := range f.devices {
		id := InsightDevice{
			ID:         d.ID,
			Name:       d.Name,
			Model:      d.Model,
			IP:         d.IP,
			Firmware:   d.Version,
			UptimeDays: math.Round(float64(d.Uptime)/86400*10) / 10,
			Clients:    d.NumSta,
		}
		// Use system-stats percentages (strings like "88.6" or " 80.0").
		id.CPU = insightParseFloat(strings.TrimSpace(d.SystemStats.CPU))
		id.Mem = insightParseFloat(strings.TrimSpace(d.SystemStats.Mem))
		// Fall back to raw bytes if system-stats missing.
		if id.Mem == 0 && d.SysStats.MemTotal > 0 {
			id.Mem = math.Round(d.SysStats.MemUsed/d.SysStats.MemTotal*1000) / 10
		}
		id.LoadAvg1 = insightParseFloat(d.SysStats.LoadAvg1)
		report.Devices = append(report.Devices, id)
	}
	sort.Slice(report.Devices, func(i, j int) bool {
		return report.Devices[i].Mem > report.Devices[j].Mem
	})

	// ── Build client list + VLAN summary ──────────────────────────────────────

	vlanClients := map[int][]insightRawSta{}
	for _, sta := range f.clients {
		vlanClients[sta.VLAN] = append(vlanClients[sta.VLAN], sta)
	}
	report.TotalClients = len(f.clients)

	// Top talkers: sort by tx+rx bytes descending, take top 15.
	talkers := make([]insightRawSta, len(f.clients))
	copy(talkers, f.clients)
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].TxBytes+talkers[i].RxBytes > talkers[j].TxBytes+talkers[j].RxBytes
	})
	if len(talkers) > 15 {
		talkers = talkers[:15]
	}
	for _, sta := range talkers {
		report.TopTalkers = append(report.TopTalkers, insightRawStaToClient(sta))
	}

	// VLAN summaries (sorted by VLAN number, -1 = untagged).
	var vlans []int
	for v := range vlanClients {
		vlans = append(vlans, v)
	}
	sort.Ints(vlans)
	for _, v := range vlans {
		stas := vlanClients[v]
		sum := VlanSummary{VLAN: v, Name: insightVLANName(v), Clients: len(stas)}
		for _, s := range stas {
			sum.TxGB += math.Round(float64(s.TxBytes)/1e9*100) / 100
			sum.RxGB += math.Round(float64(s.RxBytes)/1e9*100) / 100
		}
		sum.TxGB = math.Round(sum.TxGB*100) / 100
		sum.RxGB = math.Round(sum.RxGB*100) / 100
		report.VlanSummary = append(report.VlanSummary, sum)
	}

	// ── Run findings ──────────────────────────────────────────────────────────

	report.Findings = append(report.Findings, insightCheckDeviceHealth(report.Devices)...)
	report.Findings = append(report.Findings, insightCheckOverloadedAPs(f.devices)...)
	report.Findings = append(report.Findings, insightCheckTopTalkers(report.TopTalkers)...)
	report.Findings = append(report.Findings, insightCheckUnknownDevices(f.clients)...)
	report.Findings = append(report.Findings, insightCheckMisplacedCameras(f.clients)...)

	for _, fn := range report.Findings {
		switch fn.Severity {
		case SevCritical:
			report.Critical++
		case SevWarning:
			report.Warning++
		case SevInfo:
			report.Info++
		}
	}

	return report, nil
}

// handleNetworkInsights returns a graded report of network findings and recommendations.
func (s *HTTPServer) handleNetworkInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := RunNetworkInsights(ctx, s.unifiClient())
	if err != nil {
		s.logger.Warn("network insights err=%v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: report})
}

// ── Findings ──────────────────────────────────────────────────────────────────

func insightCheckDeviceHealth(devices []InsightDevice) []InsightFinding {
	var out []InsightFinding
	for _, d := range devices {
		if d.Mem >= 90 {
			out = append(out, InsightFinding{
				ID: "mem-critical-" + d.ID, Severity: SevCritical, Category: "device",
				Title:  fmt.Sprintf("%s memory critical: %.0f%%", d.Name, d.Mem),
				Detail: fmt.Sprintf("At %.0f%% RAM, this device risks OOM kills and service crashes.", d.Mem),
				Recommendation: "Reduce Network Controller data retention (Settings → System) or restart the device.",
			})
		} else if d.Mem >= 80 {
			out = append(out, InsightFinding{
				ID: "mem-high-" + d.ID, Severity: SevWarning, Category: "device",
				Title:  fmt.Sprintf("%s memory high: %.0f%%", d.Name, d.Mem),
				Detail: fmt.Sprintf("%.0f%% RAM is above the 80%% watch threshold. For the UDM Pro this is typically MongoDB + Protect NVR growth.", d.Mem),
				Recommendation: "SSH in and run `podman stats --no-stream` to attribute memory by container. Reduce data retention days if MongoDB is the cause.",
			})
		}
		if d.CPU >= 50 {
			sev := SevWarning
			if d.CPU >= 80 {
				sev = SevCritical
			}
			out = append(out, InsightFinding{
				ID: "cpu-high-" + d.ID, Severity: sev, Category: "device",
				Title:  fmt.Sprintf("%s CPU high: %.0f%%", d.Name, d.CPU),
				Detail: fmt.Sprintf("%.0f%% CPU on a network switch or AP suggests a loop, storm, or PoE renegotiation cycle.", d.CPU),
				Recommendation: "Check port error counters for flapping links. For switches: verify STP topology is stable and no port is cycling.",
			})
		}
	}
	return out
}

func insightCheckOverloadedAPs(devices []insightRawDevice) []InsightFinding {
	var out []InsightFinding
	for _, d := range devices {
		if d.NumSta < 25 {
			continue
		}
		// UDM Pro acts as both router and AP — its client count includes all
		// wired + wireless clients network-wide; don't flag it as overloaded.
		if strings.HasPrefix(strings.ToUpper(d.Model), "UDM") {
			continue
		}
		sev := SevInfo
		if d.NumSta >= 35 {
			sev = SevWarning
		}
		out = append(out, InsightFinding{
			ID: "ap-overloaded-" + d.ID, Severity: sev, Category: "performance",
			Title:  fmt.Sprintf("%s carrying %d clients", d.Name, d.NumSta),
			Detail: fmt.Sprintf("%d clients on a single AP degrades per-client throughput significantly. Recommended max is 20–25.", d.NumSta),
			Recommendation: "Add a nearby AP and reduce TX power to shrink coverage cells, redistributing clients.",
		})
	}
	return out
}

func insightCheckTopTalkers(talkers []InsightClient) []InsightFinding {
	var out []InsightFinding
	for _, t := range talkers {
		total := t.TxGB + t.RxGB
		if total < 5 {
			break // sorted descending; no point checking further
		}
		name := t.Hostname
		if name == "" {
			name = t.IP
		}
		out = append(out, InsightFinding{
			ID: "top-talker-" + t.MAC, Severity: SevInfo, Category: "clients",
			Title:  fmt.Sprintf("%s transferred %.1f GB this session", name, total),
			Detail: fmt.Sprintf("TX: %.2f GB  RX: %.2f GB  VLAN: %s  Uptime: %s", t.TxGB, t.RxGB, insightVLANName(t.VLAN), insightFormatUptime(t.Uptime)),
			Recommendation: "If unexpected, check whether this device is a media server, cloud backup, or has been compromised.",
		})
	}
	return out
}

func insightCheckUnknownDevices(clients []insightRawSta) []InsightFinding {
	var out []InsightFinding
	// Sensitive VLANs: IoT (2), Cameras (30), Work (10)
	sensitive := map[int]string{2: "IoT", 30: "Cameras", 10: "Work"}
	for _, s := range clients {
		vlanName, ok := sensitive[s.VLAN]
		if !ok {
			continue
		}
		if s.Hostname != "" || s.Name != "" {
			continue
		}
		out = append(out, InsightFinding{
			ID: "unknown-" + strings.ReplaceAll(s.MAC, ":", ""), Severity: SevWarning, Category: "security",
			Title:  fmt.Sprintf("Unidentified device on %s VLAN (%s)", vlanName, s.IP),
			Detail: fmt.Sprintf("MAC %s (OUI: %s) has been connected for %s with no hostname. On sensitive VLANs, every device should be identifiable.", s.MAC, insightOUI(s.OUI), insightFormatUptime(s.Uptime)),
			Recommendation: "Assign a static DHCP reservation and name in UniFi to identify this device, or investigate if it shouldn't be on this VLAN.",
		})
	}
	return out
}

func insightCheckMisplacedCameras(clients []insightRawSta) []InsightFinding {
	// Protect cameras that appear outside the Cameras VLAN (30)
	cameraKeywords := []string{"g4-", "g5-", "g3-", "camera", "cam", "protect", "doorbell", "door", "backdoor", "yard", "driveway", "garage", "side-", "front-", "rear-"}
	var out []InsightFinding
	for _, s := range clients {
		if s.VLAN == 30 {
			continue // already on Cameras VLAN
		}
		name := strings.ToLower(s.Hostname + " " + s.Name)
		for _, kw := range cameraKeywords {
			if strings.Contains(name, kw) {
				out = append(out, InsightFinding{
					ID: "misplaced-cam-" + strings.ReplaceAll(s.MAC, ":", ""), Severity: SevWarning, Category: "security",
					Title:  fmt.Sprintf("Camera %q is on VLAN %s instead of Cameras VLAN 30", s.Hostname, insightVLANName(s.VLAN)),
					Detail: "This device appears to be a Protect camera but is not on the isolated Cameras VLAN. The 'Block Cameras to Internal' rule does not apply to it.",
					Recommendation: "Migrate this camera to the Cameras VLAN (30) via UniFi Protect → Camera Settings → Network.",
				})
				break
			}
		}
	}
	return out
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

func insightFetchDevices(ctx context.Context, c *UnifiClient) ([]insightRawDevice, error) {
	var resp struct {
		Data []insightRawDevice `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/device"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func insightFetchClients(ctx context.Context, c *UnifiClient) ([]insightRawSta, error) {
	var resp struct {
		Data []insightRawSta `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/sta"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// ── Small helpers ─────────────────────────────────────────────────────────────

func insightParseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return math.Round(v*10) / 10
}

func insightRawStaToClient(s insightRawSta) InsightClient {
	name := s.Hostname
	if name == "" {
		name = s.Name
	}
	return InsightClient{
		MAC:      s.MAC,
		Hostname: name,
		IP:       s.IP,
		VLAN:     s.VLAN,
		TxBytes:  s.TxBytes,
		RxBytes:  s.RxBytes,
		TxGB:     math.Round(float64(s.TxBytes)/1e9*100) / 100,
		RxGB:     math.Round(float64(s.RxBytes)/1e9*100) / 100,
		Uptime:   s.Uptime,
		Wired:    s.Wired,
		OUI:      s.OUI,
	}
}

func insightVLANName(vlan int) string {
	switch vlan {
	case 0:
		return "Zone00 (untagged)"
	case 2:
		return "IoT"
	case 10:
		return "Work"
	case 20:
		return "Trusted"
	case 30:
		return "Cameras"
	case 40:
		return "Media"
	default:
		if vlan == 0 {
			return "untagged"
		}
		return fmt.Sprintf("VLAN %d", vlan)
	}
}

func insightFormatUptime(seconds int64) string {
	if seconds == 0 {
		return "unknown"
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	if d > 0 {
		return fmt.Sprintf("%dd %dh", d, h)
	}
	return fmt.Sprintf("%dh", h)
}

func insightOUI(oui string) string {
	if oui == "" {
		return "unknown"
	}
	return oui
}
