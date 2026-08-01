package unifideck

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GusConfig configures the Gus Cam pet-tracking feature.
type GusConfig struct {
	Enabled              bool     `json:"enabled"`
	CameraIDs            []string `json:"camera_ids"`
	DetectionIntervalSec int      `json:"detection_interval_sec"` // default 3
	PetDescription       string   `json:"pet_description"`        // "a dog named Gus"
	LogRetainDays        int      `json:"log_retain_days"`        // default 30
	DetectorURL          string   `json:"detector_url,omitempty"` // default http://127.0.0.1:8103
}

// SiteConnection represents a single UniFi Network or UISP server connection.
// Users can register multiple servers (e.g. home UDM Pro + Brian's UISP) and
// switch between them. Type is "unifi" or "uisp".
type SiteConnection struct {
	ID       string `json:"id"`                  // stable UUID
	Name     string `json:"name"`                // display name, e.g. "Home UDM Pro"
	Type     string `json:"type"`                // "unifi" | "uisp"
	Host     string `json:"host"`                // scheme + host, no trailing slash
	Token    string `json:"token"`               // API key or bearer token
	SiteName string `json:"site_name,omitempty"` // UniFi site (e.g. "default")
	ISPLabel string `json:"isp_label,omitempty"` // e.g. "Comcast Business" — used for WAN grouping
}

// AppConfig holds persisted settings for the UniFi Smash Deck server.
type AppConfig struct {
	Port string `json:"port"`
	// Multi-site: list of registered servers and the currently-active one.
	Sites        []SiteConnection `json:"sites,omitempty"`
	ActiveSiteID string           `json:"active_site_id,omitempty"`
	// Legacy single-site fields (kept for backwards compat + env var overrides).
	// When Sites is empty these are migrated into a single default Site on first
	// load. When Sites is non-empty the active Site wins.
	UnifiHost   string `json:"unifi_host"`
	UnifiSite   string `json:"unifi_site"`
	UnifiAPIKey string `json:"unifi_api_key"`
	// UnifiUser/UnifiPass kept for reading old settings files and migrating.
	UnifiUser string `json:"unifi_user,omitempty"`
	UnifiPass string `json:"unifi_pass,omitempty"`
	// SSH access to the UDM Pro OS (uses UNIFICERT_SSH_* env vars, shared with unifi-cert-smash-deck)
	SSHHost       string `json:"ssh_host,omitempty"`
	SSHUser       string `json:"ssh_user,omitempty"`
	SSHPort       string `json:"ssh_port,omitempty"`
	SSHKeyPath    string `json:"ssh_key_path,omitempty"`
	SSHPassword   string `json:"ssh_password,omitempty"`
	SSHKnownHosts string `json:"ssh_known_hosts,omitempty"`
	// Security
	HoneypotPorts []int `json:"honeypot_ports,omitempty"`
	// ControllerHoneypotIPs are the UDM-native decoy addresses. When an IPS
	// event targets one of these addresses it is promoted to a honeypot alert.
	ControllerHoneypotIPs []string       `json:"controller_honeypot_ips,omitempty"`
	AdaptixProfile        AdaptixProfile `json:"adaptix_profile,omitempty"`
	WindowsProfile        WindowsProfile `json:"windows_profile,omitempty"`
	SecurityWebhookURL    string         `json:"security_webhook_url,omitempty"`
	ThreatFeedMode        string         `json:"threat_feed_mode,omitempty"` // passive|balanced|aggressive
	// UISP (Ubiquiti ISP platform — airCube, sector APs, solar sites)
	UISPHost  string `json:"uisp_host,omitempty"`
	UISPToken string `json:"uisp_token,omitempty"`
	// Gus Cam pet tracking
	GusConfig GusConfig `json:"gus_cam,omitempty"`
	// Config drift detection
	GoldStandard GoldStandard `json:"gold_standard,omitempty"`
}

// DataDir returns the directory used for all persistent data files.
// It reads DATA_DIR from the environment; defaults to "./data" if unset.
// In the Docker image DATA_DIR is set to /app/data via ENV so the path is
// always explicit and independent of the process working directory.
func DataDir() string {
	if d := strings.TrimSpace(os.Getenv("DATA_DIR")); d != "" {
		return d
	}
	return "data"
}

func DefaultSettingsPath() string {
	return filepath.Join(DataDir(), "unifideck-settings.json")
}

func LoadAppConfig(path string) AppConfig {
	cfg := AppConfig{
		Port:           getenv("PORT", "8099"),
		UnifiHost:      getenv("UNIFI_HOST", ""),
		UnifiSite:      getenv("UNIFI_SITE", "default"),
		UnifiAPIKey:    getenv("UNIFI_API_KEY", ""),
		GusConfig:      GusConfig{Enabled: true},
		WindowsProfile: DefaultWindowsProfile(),
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		var stored AppConfig
		if json.Unmarshal(raw, &stored) == nil {
			// Preserve the persisted multi-site identity. Dropping these fields
			// causes migrateLegacyToSites to generate a new random site ID on
			// every restart, orphaning WAN/client samples and making dashboards
			// report 0 KB after reboot.
			cfg.Sites = stored.Sites
			cfg.ActiveSiteID = stored.ActiveSiteID
			if stored.Port != "" {
				cfg.Port = stored.Port
			}
			if stored.UnifiHost != "" {
				cfg.UnifiHost = stored.UnifiHost
			}
			if stored.UnifiSite != "" {
				cfg.UnifiSite = stored.UnifiSite
			}
			if stored.UnifiAPIKey != "" {
				cfg.UnifiAPIKey = stored.UnifiAPIKey
			}
			// Migrate: if old unifi_pass was set and we have no api_key yet, treat it as the API key.
			if cfg.UnifiAPIKey == "" && stored.UnifiPass != "" {
				cfg.UnifiAPIKey = stored.UnifiPass
			}
			if stored.UISPHost != "" {
				cfg.UISPHost = stored.UISPHost
			}
			if stored.UISPToken != "" {
				cfg.UISPToken = stored.UISPToken
			}
			// Preserve persisted UDM SSH settings when the environment does not
			// provide them. These are required by the historical WAN-flow audit.
			if stored.SSHHost != "" {
				cfg.SSHHost = stored.SSHHost
			}
			if stored.SSHUser != "" {
				cfg.SSHUser = stored.SSHUser
			}
			if stored.SSHPort != "" {
				cfg.SSHPort = stored.SSHPort
			}
			if stored.SSHKeyPath != "" {
				cfg.SSHKeyPath = stored.SSHKeyPath
			}
			if stored.SSHPassword != "" {
				cfg.SSHPassword = stored.SSHPassword
			}
			if stored.SSHKnownHosts != "" {
				cfg.SSHKnownHosts = stored.SSHKnownHosts
			}
			cfg.GusConfig = stored.GusConfig
			cfg.HoneypotPorts = stored.HoneypotPorts
			cfg.ControllerHoneypotIPs = stored.ControllerHoneypotIPs
			cfg.AdaptixProfile = stored.AdaptixProfile
			cfg.WindowsProfile = stored.WindowsProfile
			if cfg.WindowsProfile.Persona == "" {
				cfg.WindowsProfile = DefaultWindowsProfile()
			}
			cfg.SecurityWebhookURL = stored.SecurityWebhookURL
			cfg.ThreatFeedMode = stored.ThreatFeedMode
		}
	}
	// Env vars override the file only when explicitly set (non-empty).
	// Keep placeholder-looking values (the literal string "yourpassword" etc.) from .env.example out.
	if v := strings.TrimSpace(os.Getenv("UNIFI_HOST")); v != "" && v != "https://192.168.1.1" {
		cfg.UnifiHost = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_SITE")); v != "" {
		cfg.UnifiSite = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_API_KEY")); v != "" && v != "your-api-key-here" {
		cfg.UnifiAPIKey = v
	}
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		cfg.Port = p
	}
	if v := strings.TrimSpace(os.Getenv("UISP_HOST")); v != "" {
		cfg.UISPHost = v
	}
	if v := strings.TrimSpace(os.Getenv("UISP_TOKEN")); v != "" {
		cfg.UISPToken = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_HONEYPOT_IPS")); v != "" {
		cfg.ControllerHoneypotIPs = splitCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("ADAPTIX_HTTP_PATHS")); v != "" {
		cfg.AdaptixProfile.HTTPPaths = splitCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("ADAPTIX_HTTP_HEADER")); v != "" {
		cfg.AdaptixProfile.HTTPHeader = v
	}
	// SSH credentials (from UNIFICERT_SSH_* env vars, shared with unifi-cert-smash-deck)
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_HOST")); v != "" {
		cfg.SSHHost = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_USER")); v != "" {
		cfg.SSHUser = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_PORT")); v != "" {
		cfg.SSHPort = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_KEY")); v != "" {
		cfg.SSHKeyPath = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_PASSWORD")); v != "" {
		cfg.SSHPassword = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFICERT_SSH_KNOWN_HOSTS")); v != "" {
		cfg.SSHKnownHosts = v
	}
	if cfg.SSHUser == "" {
		cfg.SSHUser = "root"
	}
	if cfg.SSHPort == "" {
		cfg.SSHPort = "22"
	}
	// Gus Cam defaults
	if cfg.GusConfig.DetectionIntervalSec == 0 {
		cfg.GusConfig.DetectionIntervalSec = 3
	}
	if cfg.GusConfig.LogRetainDays == 0 {
		cfg.GusConfig.LogRetainDays = 30
	}
	if cfg.GusConfig.PetDescription == "" {
		cfg.GusConfig.PetDescription = "a dog"
	}
	// Multi-site migration: if no Sites exist yet but legacy fields are set,
	// promote them to the first Site entry. Env-var-provided credentials win.
	cfg.migrateLegacyToSites()
	return cfg
}

// migrateLegacyToSites promotes legacy single-site fields (UnifiHost/UISPHost)
// into the Sites list on first load, so every code path can treat Sites as the
// source of truth. Idempotent — skips entries that already exist by Host.
func (cfg *AppConfig) migrateLegacyToSites() {
	has := func(host string) bool {
		for _, s := range cfg.Sites {
			if strings.EqualFold(s.Host, host) {
				return true
			}
		}
		return false
	}
	if cfg.UnifiHost != "" && !has(cfg.UnifiHost) {
		cfg.Sites = append(cfg.Sites, SiteConnection{
			ID:       newSiteID(),
			Name:     "UniFi Controller",
			Type:     "unifi",
			Host:     cfg.UnifiHost,
			Token:    cfg.UnifiAPIKey,
			SiteName: cfg.UnifiSite,
		})
	}
	if cfg.UISPHost != "" && !has(cfg.UISPHost) {
		cfg.Sites = append(cfg.Sites, SiteConnection{
			ID:    newSiteID(),
			Name:  "UISP",
			Type:  "uisp",
			Host:  cfg.UISPHost,
			Token: cfg.UISPToken,
		})
	}
	// Ensure we have an active site selected if any exist.
	if cfg.ActiveSiteID == "" && len(cfg.Sites) > 0 {
		cfg.ActiveSiteID = cfg.Sites[0].ID
	}
	// Clear ActiveSiteID if it points to a deleted site.
	if cfg.ActiveSiteID != "" {
		found := false
		for _, s := range cfg.Sites {
			if s.ID == cfg.ActiveSiteID {
				found = true
				break
			}
		}
		if !found && len(cfg.Sites) > 0 {
			cfg.ActiveSiteID = cfg.Sites[0].ID
		}
	}
}

// ActiveSiteByType returns the active site of the requested type, or the first
// site of that type, or nil. Callers fall back to legacy fields when nil.
func (cfg *AppConfig) ActiveSiteByType(typ string) *SiteConnection {
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.ID == cfg.ActiveSiteID && s.Type == typ {
			return s
		}
	}
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Type == typ {
			return s
		}
	}
	return nil
}

// newSiteID generates a short stable ID for a site.
func newSiteID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("site-%d", time.Now().UnixNano())
	}
	return "site-" + hex.EncodeToString(b)
}

func SaveAppConfig(path string, cfg AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".unifideck-settings-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
