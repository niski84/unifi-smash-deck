package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// DiagnosticStatus is one of "ok", "warn", "fail".
type DiagnosticStatus string

const (
	StatusOK   DiagnosticStatus = "ok"
	StatusWarn DiagnosticStatus = "warn"
	StatusFail DiagnosticStatus = "fail"
)

// DiagnosticCheck is one evaluated best-practice rule.
type DiagnosticCheck struct {
	ID          string           `json:"id"`
	Status      DiagnosticStatus `json:"status"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	// Fixable: if true the UI shows a Fix button.
	Fixable    bool   `json:"fixable"`
	FixLabel   string `json:"fix_label,omitempty"`
	FixWLANID  string `json:"fix_wlan_id,omitempty"`
	FixAction  string `json:"fix_action,omitempty"` // e.g. "disable-isolation"
}

// IoTDevice is an extended client record including ESSID and OUI,
// fetched from stat/sta and filtered to known IoT vendors.
type IoTDevice struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	ESSID    string `json:"essid"`
	OUI      string `json:"oui"`
	Signal   int    `json:"signal"`
	Uptime   int64  `json:"uptime"`
	LastSeen int64  `json:"last_seen"`
}

// IoTDiagnosticsResult is the response from /api/iot/diagnose.
type IoTDiagnosticsResult struct {
	RunAt      time.Time         `json:"run_at"`
	Checks     []DiagnosticCheck `json:"checks"`
	IoTDevices []IoTDevice       `json:"iot_devices"`
}

// ── IoT vendor OUI prefixes ──────────────────────────────────────────────────

var iotOUIs = []string{
	"wyze labs",
	"amazon technologies",
	"google llc",
	"amazon",
	"apple",
	"ring",
	"ecobee",
	"lutron",
	"sonos",
	"belkin",
	"philips lighting",
	"signify",
	"tp-link",
	"shenzhen",
}

func isIoTOUI(oui string) bool {
	lower := strings.ToLower(oui)
	for _, prefix := range iotOUIs {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

// ── Raw client fetch (extended fields not in the shared Client struct) ────────

type rawSta struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Name     string `json:"name,omitempty"`
	ESSID    string `json:"essid,omitempty"`
	OUI      string `json:"oui,omitempty"`
	Signal   int    `json:"signal,omitempty"`
	Uptime   int64  `json:"uptime,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
	Wired    bool   `json:"is_wired"`
}

func listRawStations(ctx context.Context, c *UnifiClient) ([]rawSta, error) {
	var resp struct {
		Data []rawSta `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/sta"), nil, &resp); err != nil {
		return nil, fmt.Errorf("list stations: %w", err)
	}
	return resp.Data, nil
}

// ── Diagnostics runner ────────────────────────────────────────────────────────

// RunIoTDiagnostics queries the UDM Pro and evaluates a set of IoT best-practice
// rules. It returns both the check results and a filtered list of IoT clients.
func RunIoTDiagnostics(ctx context.Context, c *UnifiClient) (*IoTDiagnosticsResult, error) {
	wlans, err := c.ListWLANs(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch WLANs: %w", err)
	}
	mdns, err := c.GetMDNSSetting(ctx)
	if err != nil {
		// Non-fatal — mDNS endpoint may vary by firmware.
		mdns = MDNSSetting{}
	}
	stations, err := listRawStations(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("fetch clients: %w", err)
	}

	var checks []DiagnosticCheck

	// ── Check 1: AP Isolation (l2_isolation) ─────────────────────────────────
	for _, w := range wlans {
		if !w.Enabled {
			continue
		}
		if w.L2Isolation {
			checks = append(checks, DiagnosticCheck{
				ID:     "ap_isolation_" + w.ID,
				Status: StatusFail,
				Title:  fmt.Sprintf("AP Isolation ON — %s", w.Name),
				Description: fmt.Sprintf(
					"%q has AP isolation (l2_isolation) enabled. "+
						"Devices on this SSID cannot discover or communicate with each other locally. "+
						"This breaks Wyze pairing, local control, and multicast discovery.",
					w.Name),
				Fixable:   true,
				FixLabel:  "Disable AP Isolation",
				FixWLANID: w.ID,
				FixAction: "disable-isolation",
			})
		} else {
			checks = append(checks, DiagnosticCheck{
				ID:          "ap_isolation_" + w.ID,
				Status:      StatusOK,
				Title:       fmt.Sprintf("AP Isolation OFF — %s", w.Name),
				Description: fmt.Sprintf("%q allows local device-to-device communication.", w.Name),
			})
		}
	}

	// ── Check 2: Multicast Enhancement ───────────────────────────────────────
	for _, w := range wlans {
		if !w.Enabled {
			continue
		}
		if !w.McastEnhance {
			checks = append(checks, DiagnosticCheck{
				ID:     "mcast_" + w.ID,
				Status: StatusWarn,
				Title:  fmt.Sprintf("Multicast Enhancement OFF — %s", w.Name),
				Description: fmt.Sprintf(
					"%q has multicast enhancement disabled. "+
						"Enabling it improves reliability of device discovery (mDNS, SSDP) for IoT devices.",
					w.Name),
				Fixable:   true,
				FixLabel:  "Enable Multicast Enhancement",
				FixWLANID: w.ID,
				FixAction: "enable-mcast",
			})
		} else {
			checks = append(checks, DiagnosticCheck{
				ID:          "mcast_" + w.ID,
				Status:      StatusOK,
				Title:       fmt.Sprintf("Multicast Enhancement ON — %s", w.Name),
				Description: fmt.Sprintf("%q has multicast enhancement enabled.", w.Name),
			})
		}
	}

	// ── Check 3: WPA3 on IoT SSIDs ────────────────────────────────────────────
	for _, w := range wlans {
		if !w.Enabled {
			continue
		}
		if w.WPA3Support {
			sev := StatusWarn
			if w.EnhancedIoT {
				sev = StatusFail
			}
			checks = append(checks, DiagnosticCheck{
				ID:     "wpa3_" + w.ID,
				Status: sev,
				Title:  fmt.Sprintf("WPA3 Enabled — %s", w.Name),
				Description: fmt.Sprintf(
					"%q has WPA3 support enabled. Many IoT devices (including Wyze) only support WPA2. "+
						"WPA3 can prevent these devices from connecting or cause intermittent drops.",
					w.Name),
			})
		} else {
			checks = append(checks, DiagnosticCheck{
				ID:          "wpa3_" + w.ID,
				Status:      StatusOK,
				Title:       fmt.Sprintf("WPA2 Only — %s", w.Name),
				Description: fmt.Sprintf("%q uses WPA2, compatible with all IoT devices.", w.Name),
			})
		}
	}

	// ── Check 4: 2.4 GHz enforcement on IoT SSIDs ────────────────────────────
	for _, w := range wlans {
		if !w.Enabled || !w.EnhancedIoT {
			continue
		}
		if w.WlanBand != "2g" {
			checks = append(checks, DiagnosticCheck{
				ID:     "band_2g_" + w.ID,
				Status: StatusWarn,
				Title:  fmt.Sprintf("Not 2.4 GHz Only — %s", w.Name),
				Description: fmt.Sprintf(
					"%q (IoT network) is set to band=%q. "+
						"Wyze and most IoT devices are 2.4 GHz only — setting band to 2g prevents them from attempting 5 GHz.",
					w.Name, w.WlanBand),
			})
		} else {
			checks = append(checks, DiagnosticCheck{
				ID:          "band_2g_" + w.ID,
				Status:      StatusOK,
				Title:       fmt.Sprintf("2.4 GHz Only — %s", w.Name),
				Description: fmt.Sprintf("%q is locked to 2.4 GHz only, correct for IoT devices.", w.Name),
			})
		}
	}

	// ── Check 5: no2ghz_oui on IoT SSIDs ─────────────────────────────────────
	for _, w := range wlans {
		if !w.Enabled || !w.EnhancedIoT {
			continue
		}
		if w.No2GHzOUI {
			checks = append(checks, DiagnosticCheck{
				ID:     "no2ghz_oui_" + w.ID,
				Status: StatusFail,
				Title:  fmt.Sprintf("2.4 GHz OUI Block ON — %s", w.Name),
				Description: fmt.Sprintf(
					"%q has 'no2ghz_oui' enabled — this blocks devices with known 2.4 GHz-only OUIs (like Wyze) from joining the network.",
					w.Name),
			})
		}
	}

	// ── Check 6: mDNS relay ───────────────────────────────────────────────────
	if mdns.Mode == "all" {
		checks = append(checks, DiagnosticCheck{
			ID:          "mdns_relay",
			Status:      StatusOK,
			Title:       "mDNS Relay: All Networks",
			Description: "mDNS is relayed across all VLANs. Chromecast, AirPlay, and SSDP discovery work cross-network.",
		})
	} else if mdns.Mode == "" {
		checks = append(checks, DiagnosticCheck{
			ID:          "mdns_relay",
			Status:      StatusWarn,
			Title:       "mDNS Relay: Not Configured",
			Description: "mDNS relay mode is unset. Cross-VLAN casting (Chromecast, AirPlay) may not work if your devices are on different VLANs.",
		})
	} else {
		checks = append(checks, DiagnosticCheck{
			ID:    "mdns_relay",
			Status: StatusWarn,
			Title:  fmt.Sprintf("mDNS Relay: mode=%s", mdns.Mode),
			Description: fmt.Sprintf(
				"mDNS mode is %q with %d predefined and %d custom services. "+
					"Set mode to 'all' to relay mDNS across all VLANs for full casting support.",
				mdns.Mode, len(mdns.PredefinedSvcs), len(mdns.CustomSvcs)),
		})
	}

	// ── IoT devices list ─────────────────────────────────────────────────────
	var iotDevices []IoTDevice
	for _, s := range stations {
		if s.Wired || !isIoTOUI(s.OUI) {
			continue
		}
		label := s.Name
		if label == "" {
			label = s.Hostname
		}
		iotDevices = append(iotDevices, IoTDevice{
			MAC:      s.MAC,
			Name:     label,
			IP:       s.IP,
			ESSID:    s.ESSID,
			OUI:      s.OUI,
			Signal:   s.Signal,
			Uptime:   s.Uptime,
			LastSeen: s.LastSeen,
		})
	}

	return &IoTDiagnosticsResult{
		RunAt:      time.Now(),
		Checks:     checks,
		IoTDevices: iotDevices,
	}, nil
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

// handleIoTDiagnose runs and returns the full IoT diagnostics report.
// GET /api/iot/diagnose
func (s *HTTPServer) handleIoTDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := RunIoTDiagnostics(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: result})
}

// handleIoTWLANFix applies a fix to a WLAN setting.
// POST /api/iot/wlans/{id}/disable-isolation
// POST /api/iot/wlans/{id}/enable-mcast
func (s *HTTPServer) handleIoTWLANFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	// Parse /api/iot/wlans/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/iot/wlans/")
	parts := strings.SplitN(strings.Trim(path, "/"), "/", 2)
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "expected /api/iot/wlans/{id}/{action}"})
		return
	}
	wlanID, action := parts[0], parts[1]

	var fields map[string]any
	switch action {
	case "disable-isolation":
		fields = map[string]any{"l2_isolation": false}
	case "enable-isolation":
		fields = map[string]any{"l2_isolation": true}
	case "enable-mcast":
		fields = map[string]any{"mcastenhance_enabled": true}
	case "disable-mcast":
		fields = map[string]any{"mcastenhance_enabled": false}
	case "disable-wpa3":
		fields = map[string]any{"wpa3_support": false, "wpa3_transition": false}
	case "set-band-2g":
		fields = map[string]any{"wlan_band": "2g", "wlan_bands": []string{"2g"}}
	default:
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: fmt.Sprintf("unknown action %q", action)})
		return
	}

	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := c.UpdateWLANFields(ctx, wlanID, fields); err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	s.logger.Info("iot fix: wlan=%s action=%s", wlanID, action)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"wlan_id": wlanID, "action": action}})
}

// parseJSON is a small helper used in tests.
func parseJSON(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
