package unifideck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GoldStandard is the desired configuration that every site should match.
// Stored as part of AppConfig.
type GoldStandard struct {
	// WiFi settings
	DisableAutoOptimize bool `json:"disable_auto_optimize"` // true = enforce OFF
	DisableFastRoaming  bool `json:"disable_fast_roaming"`
	RequireWPA3         bool `json:"require_wpa3"`         // warn if WPA2-only
	MaxChannelWidth2G   int  `json:"max_channel_width_2g"` // 0=any, 20=enforce 20MHz
	// Security
	DisableSSHPassword bool `json:"disable_ssh_password"` // require key-only
	// Network
	RequiredDNS []string `json:"required_dns"` // empty=skip check
	RequireIGMP bool     `json:"require_igmp"`
}

// DriftCheck represents one finding from the drift analysis.
type DriftCheck struct {
	CheckName   string `json:"check_name"`
	Severity    string `json:"severity"`    // "ok" | "warn" | "critical"
	Description string `json:"description"` // what was found
	Suggestion  string `json:"suggestion"`  // what to do
	Passed      bool   `json:"passed"`
}

// SiteDriftReport is the full drift result for one site.
type SiteDriftReport struct {
	SiteID     string       `json:"site_id"`
	SiteName   string       `json:"site_name"`
	Score      int          `json:"score"` // 0-100, higher=better
	Checks     []DriftCheck `json:"checks"`
	AnalyzedAt time.Time    `json:"analyzed_at"`
	FailCount  int          `json:"fail_count"`
	WarnCount  int          `json:"warn_count"`
	CritCount  int          `json:"crit_count"`
}

// AnalyzeDrift fetches live config for one site and runs all drift checks.
func AnalyzeDrift(ctx context.Context, site SiteConnection, gold GoldStandard) (*SiteDriftReport, error) {
	// Fetch WLANs
	wlans, err := fetchWLANs(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("fetch wlans: %w", err)
	}

	// Fetch system settings
	settings, err := fetchSettings(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("fetch settings: %w", err)
	}

	// Run all drift checks
	checks := []DriftCheck{
		checkAutoOptimize(wlans, settings, gold),
		checkFastRoaming(wlans, settings, gold),
		checkWPASecurity(wlans, settings, gold),
		checkSSH(wlans, settings, gold),
		checkIGMP(wlans, settings, gold),
		checkChannelWidth2G(wlans, settings, gold),
	}

	// Count failures and compute score
	failCount := 0
	warnCount := 0
	critCount := 0
	for _, c := range checks {
		if !c.Passed {
			switch c.Severity {
			case "critical":
				critCount++
			case "warn":
				warnCount++
			}
			failCount++
		}
	}

	// Compute score: 100 - (critCount*20 + warnCount*5), clamped to 0-100
	score := 100 - (critCount*20 + warnCount*5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	report := &SiteDriftReport{
		SiteID:     site.ID,
		SiteName:   site.Name,
		Score:      score,
		Checks:     checks,
		AnalyzedAt: time.Now(),
		FailCount:  failCount,
		WarnCount:  warnCount,
		CritCount:  critCount,
	}

	return report, nil
}

// fetchWLANs retrieves the list of WLANs from the site.
func fetchWLANs(ctx context.Context, site SiteConnection) ([]map[string]any, error) {
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/rest/wlanconf",
		strings.TrimRight(site.Host, "/"),
		defaultIfEmpty(site.SiteName, "default"))

	data, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode wlans: %w", err)
	}

	return resp.Data, nil
}

// fetchSettings retrieves the site settings (super_mgmt, mgmt, etc).
func fetchSettings(ctx context.Context, site SiteConnection) ([]map[string]any, error) {
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/get/setting",
		strings.TrimRight(site.Host, "/"),
		defaultIfEmpty(site.SiteName, "default"))

	data, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode settings: %w", err)
	}

	return resp.Data, nil
}

// doHTTPRequest performs an HTTP GET with X-API-KEY header and returns the body.
func doHTTPRequest(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-KEY", token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}

	return body, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Drift check functions
// ─────────────────────────────────────────────────────────────────────────────

// checkAutoOptimize looks for auto-optimize enabled in settings.
func checkAutoOptimize(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if !gold.DisableAutoOptimize {
		return DriftCheck{
			CheckName:   "auto_optimize",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	// Look for super_mgmt setting with auto_optimize or auto_channel enabled
	for _, s := range settings {
		key, _ := s["key"].(string)
		if key == "super_mgmt" {
			// Check auto_channel
			if autoChannel, ok := s["auto_channel"].(bool); ok && autoChannel {
				return DriftCheck{
					CheckName:   "auto_optimize",
					Severity:    "warn",
					Description: "Auto-Optimize Network is enabled — known to cause IoT client drops on 2.4GHz",
					Suggestion:  "Disable Auto-Optimize in Network Settings > WiFi > Advanced. Lock 2.4GHz channel width to 20MHz.",
					Passed:      false,
				}
			}
			// Check auto_optimize
			if autoOpt, ok := s["auto_optimize"].(bool); ok && autoOpt {
				return DriftCheck{
					CheckName:   "auto_optimize",
					Severity:    "warn",
					Description: "Auto-Optimize Network is enabled — known to cause IoT client drops on 2.4GHz",
					Suggestion:  "Disable Auto-Optimize in Network Settings > WiFi > Advanced. Lock 2.4GHz channel width to 20MHz.",
					Passed:      false,
				}
			}
		}
	}

	return DriftCheck{
		CheckName:   "auto_optimize",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// checkFastRoaming looks for fast_roaming_enabled in WLANs.
func checkFastRoaming(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if !gold.DisableFastRoaming {
		return DriftCheck{
			CheckName:   "fast_roaming",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	for _, w := range wlans {
		if fastRoaming, ok := w["fast_roaming_enabled"].(bool); ok && fastRoaming {
			name, _ := w["name"].(string)
			if name == "" {
				name = "unknown"
			}
			return DriftCheck{
				CheckName:   "fast_roaming",
				Severity:    "warn",
				Description: fmt.Sprintf("Fast Roaming (802.11r) is enabled on SSID '%s' — can break older clients", name),
				Suggestion:  "Disable Fast Roaming unless all clients are known-compatible. Test with a small SSID first.",
				Passed:      false,
			}
		}
	}

	return DriftCheck{
		CheckName:   "fast_roaming",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// checkWPASecurity looks for WPA2-only (no WPA3) in WLANs.
func checkWPASecurity(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if !gold.RequireWPA3 {
		return DriftCheck{
			CheckName:   "wpa_security",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	for _, w := range wlans {
		security, _ := w["security"].(string)
		// "wpapsk" typically means WPA2-only without WPA3
		if security == "wpapsk" {
			name, _ := w["name"].(string)
			if name == "" {
				name = "unknown"
			}
			return DriftCheck{
				CheckName:   "wpa_security",
				Severity:    "warn",
				Description: fmt.Sprintf("SSID '%s' uses WPA2-only — WPA3 transition mode is available", name),
				Suggestion:  "Update to WPA2/WPA3 transition mode in WLAN settings for improved security.",
				Passed:      false,
			}
		}
	}

	return DriftCheck{
		CheckName:   "wpa_security",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// checkSSH looks for SSH enabled with password (no SSH keys).
func checkSSH(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if !gold.DisableSSHPassword {
		return DriftCheck{
			CheckName:   "ssh",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	for _, s := range settings {
		key, _ := s["key"].(string)
		if key == "mgmt" {
			// Check if SSH is enabled
			sshEnabled, _ := s["x_ssh_enabled"].(bool)
			if !sshEnabled {
				return DriftCheck{
					CheckName:   "ssh",
					Severity:    "ok",
					Description: "✓ OK",
					Passed:      true,
				}
			}

			// SSH is enabled; check for SSH keys
			sshKeysVal := s["x_ssh_keys"]
			if sshKeysVal == nil {
				return DriftCheck{
					CheckName:   "ssh",
					Severity:    "critical",
					Description: "SSH is enabled with password authentication (no SSH keys configured)",
					Suggestion:  "Add an SSH public key in Settings > System > SSH Keys, then disable password auth.",
					Passed:      false,
				}
			}

			// Check if it's an empty string or empty slice
			if sshStr, ok := sshKeysVal.(string); ok && sshStr == "" {
				return DriftCheck{
					CheckName:   "ssh",
					Severity:    "critical",
					Description: "SSH is enabled with password authentication (no SSH keys configured)",
					Suggestion:  "Add an SSH public key in Settings > System > SSH Keys, then disable password auth.",
					Passed:      false,
				}
			}

			if sshSlice, ok := sshKeysVal.([]any); ok && len(sshSlice) == 0 {
				return DriftCheck{
					CheckName:   "ssh",
					Severity:    "critical",
					Description: "SSH is enabled with password authentication (no SSH keys configured)",
					Suggestion:  "Add an SSH public key in Settings > System > SSH Keys, then disable password auth.",
					Passed:      false,
				}
			}
		}
	}

	return DriftCheck{
		CheckName:   "ssh",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// checkIGMP looks for IGMP snooping in settings.
func checkIGMP(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if !gold.RequireIGMP {
		return DriftCheck{
			CheckName:   "igmp",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	for _, s := range settings {
		// IGMP snooping can be found in various settings keys (network, advanced, etc)
		if igmpVal, ok := s["igmp_snooping"]; ok {
			igmpEnabled, _ := igmpVal.(bool)
			if !igmpEnabled {
				return DriftCheck{
					CheckName:   "igmp",
					Severity:    "warn",
					Description: "IGMP snooping is disabled — may cause multicast flooding",
					Suggestion:  "Enable IGMP snooping in Network Settings for each VLAN with multicast traffic.",
					Passed:      false,
				}
			}
		}
	}

	return DriftCheck{
		CheckName:   "igmp",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// checkChannelWidth2G looks for 2.4GHz channel width > 20MHz.
func checkChannelWidth2G(wlans []map[string]any, settings []map[string]any, gold GoldStandard) DriftCheck {
	if gold.MaxChannelWidth2G != 20 {
		return DriftCheck{
			CheckName:   "channel_width_2g",
			Severity:    "ok",
			Description: "✓ OK",
			Passed:      true,
		}
	}

	for _, w := range wlans {
		// Determine if this is a 2.4GHz WLAN
		band, _ := w["band"].(string)
		// If band is not explicitly set, assume 2.4GHz for older UniFi versions
		is2G := band == "2g" || band == ""

		if !is2G {
			continue
		}

		// Check channel_width
		widthVal := w["channel_width"]
		var width int
		switch v := widthVal.(type) {
		case float64:
			width = int(v)
		case int:
			width = v
		case string:
			fmt.Sscanf(v, "%d", &width)
		default:
			continue
		}

		if width > 20 {
			name, _ := w["name"].(string)
			if name == "" {
				name = "unknown"
			}
			return DriftCheck{
				CheckName:   "channel_width_2g",
				Severity:    "warn",
				Description: fmt.Sprintf("2.4GHz channel width is set to %dMHz on SSID '%s' — causes adjacent-channel interference", width, name),
				Suggestion:  "Lock 2.4GHz channel width to 20MHz in WLAN Advanced settings.",
				Passed:      false,
			}
		}
	}

	return DriftCheck{
		CheckName:   "channel_width_2g",
		Severity:    "ok",
		Description: "✓ OK",
		Passed:      true,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
