package unifideck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// AppConfig holds persisted settings for the UniFi Smash Deck server.
type AppConfig struct {
	Port       string `json:"port"`
	UnifiHost  string `json:"unifi_host"`
	UnifiUser  string `json:"unifi_user"`
	UnifiPass  string `json:"unifi_pass"`
	UnifiSite  string `json:"unifi_site"`
}

func DefaultSettingsPath() string {
	return filepath.Clean("data/unifideck-settings.json")
}

func LoadAppConfig(path string) AppConfig {
	cfg := AppConfig{
		Port:      getenv("PORT", "8099"),
		UnifiHost: getenv("UNIFI_HOST", ""),
		UnifiUser: getenv("UNIFI_USER", ""),
		UnifiPass: getenv("UNIFI_PASS", ""),
		UnifiSite: getenv("UNIFI_SITE", "default"),
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
			if stored.UnifiUser != "" {
				cfg.UnifiUser = stored.UnifiUser
			}
			if stored.UnifiPass != "" {
				cfg.UnifiPass = stored.UnifiPass
			}
			if stored.UnifiSite != "" {
				cfg.UnifiSite = stored.UnifiSite
			}
		}
	}
	// Env always wins
	if v := strings.TrimSpace(os.Getenv("UNIFI_HOST")); v != "" {
		cfg.UnifiHost = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_USER")); v != "" {
		cfg.UnifiUser = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_PASS")); v != "" {
		cfg.UnifiPass = v
	}
	if v := strings.TrimSpace(os.Getenv("UNIFI_SITE")); v != "" {
		cfg.UnifiSite = v
	}
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		cfg.Port = p
	}
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
