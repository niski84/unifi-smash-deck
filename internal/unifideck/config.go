package unifideck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// AppConfig holds persisted settings for the UniFi Smash Deck server.
type AppConfig struct {
	Port        string `json:"port"`
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
	HoneypotPorts      []int  `json:"honeypot_ports,omitempty"`
	SecurityWebhookURL string `json:"security_webhook_url,omitempty"`
	ThreatFeedMode     string `json:"threat_feed_mode,omitempty"` // passive|balanced|aggressive
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
		Port:        getenv("PORT", "8099"),
		UnifiHost:   getenv("UNIFI_HOST", ""),
		UnifiSite:   getenv("UNIFI_SITE", "default"),
		UnifiAPIKey: getenv("UNIFI_API_KEY", ""),
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		var stored AppConfig
		if json.Unmarshal(raw, &stored) == nil {
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
	// SSH credentials (from UNIFICERT_SSH_* env vars, shared with unifi-cert-smash-deck)
	cfg.SSHHost       = getenv("UNIFICERT_SSH_HOST", "")
	cfg.SSHUser       = getenv("UNIFICERT_SSH_USER", "root")
	cfg.SSHPort       = getenv("UNIFICERT_SSH_PORT", "22")
	cfg.SSHKeyPath    = getenv("UNIFICERT_SSH_KEY", "")
	cfg.SSHPassword   = getenv("UNIFICERT_SSH_PASSWORD", "")
	cfg.SSHKnownHosts = getenv("UNIFICERT_SSH_KNOWN_HOSTS", "")
	return cfg
}

func SaveAppConfig(path string, cfg AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
