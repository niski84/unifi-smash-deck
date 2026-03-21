package unifideck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Network represents a UniFi network/VLAN from rest/networkconf.
type Network struct {
	ID           string `json:"_id"`
	Name         string `json:"name"`
	Purpose      string `json:"purpose"`
	VlanID       int    `json:"vlan,omitempty"`
	Enabled      bool   `json:"enabled"`
	IPSubnet     string `json:"ip_subnet,omitempty"`
	NetworkGroup string `json:"networkgroup,omitempty"`
	DHCPEnabled  bool   `json:"dhcpd_enabled,omitempty"`
}

// Client represents a connected client device.
type Client struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Name     string `json:"name,omitempty"`
	VLAN     int    `json:"vlan,omitempty"`
	Signal   int    `json:"signal,omitempty"`
	Wired    bool   `json:"is_wired"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

// Device represents a UniFi network device (AP, switch, etc).
type Device struct {
	MAC     string `json:"mac"`
	Name    string `json:"name,omitempty"`
	Model   string `json:"model,omitempty"`
	Type    string `json:"type,omitempty"`
	State   int    `json:"state"`
	Version string `json:"version,omitempty"`
}

// SiteHealth represents health info for the site.
type SiteHealth struct {
	Subsystem string `json:"subsystem"`
	Status    string `json:"status"`
	NumUser   int    `json:"num_user,omitempty"`
	NumGuest  int    `json:"num_guest,omitempty"`
	NumIoT    int    `json:"num_iot,omitempty"`
}

// UnifiClient calls the UDM Pro API using an API key (X-API-KEY header).
// This matches the official local Network API described at:
//   UniFi Network > Settings > Control Plane > Integrations
type UnifiClient struct {
	host       string
	site       string
	apiKey     string
	httpClient *http.Client
}

func NewUnifiClient(host, apiKey, site string) *UnifiClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // UDM Pro uses self-signed cert
	}
	return &UnifiClient{
		host:   strings.TrimRight(host, "/"),
		apiKey: apiKey,
		site:   site,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
		},
	}
}

func (c *UnifiClient) IsConfigured() bool {
	return c.host != "" && c.apiKey != ""
}

// apiURL builds the full URL for a site-level network endpoint.
func (c *UnifiClient) apiURL(path string) string {
	site := c.site
	if site == "" {
		site = "default"
	}
	return fmt.Sprintf("%s/proxy/network/api/s/%s/%s", c.host, site, strings.TrimPrefix(path, "/"))
}

// doJSON performs a JSON API request using the X-API-KEY header.
func (c *UnifiClient) doJSON(ctx context.Context, method, url string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-KEY", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		snippet := strings.TrimSpace(string(rawBody))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("auth failed (HTTP %d) — check your API key. Response: %s", resp.StatusCode, snippet)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(rawBody))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("unifi API HTTP %d: %s", resp.StatusCode, snippet)
	}

	if out != nil && len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, out); err != nil {
			return fmt.Errorf("unifi decode: %w (body: %s)", err, string(rawBody[:min(200, len(rawBody))]))
		}
	}
	return nil
}

// ListNetworks returns all configured networks/VLANs.
func (c *UnifiClient) ListNetworks(ctx context.Context) ([]Network, error) {
	var resp struct {
		Data []Network `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/networkconf"), nil, &resp); err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	if resp.Meta.RC != "ok" {
		return nil, fmt.Errorf("list networks: unexpected rc=%s", resp.Meta.RC)
	}
	return resp.Data, nil
}

// SetNetworkEnabled enables or disables a network by ID.
func (c *UnifiClient) SetNetworkEnabled(ctx context.Context, networkID string, enabled bool) error {
	payload := map[string]any{"enabled": enabled}
	var resp struct {
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	url := c.apiURL("rest/networkconf/" + networkID)
	if err := c.doJSON(ctx, http.MethodPut, url, payload, &resp); err != nil {
		return fmt.Errorf("set network enabled: %w", err)
	}
	return nil
}

// ListClients returns all active clients on the site.
func (c *UnifiClient) ListClients(ctx context.Context) ([]Client, error) {
	var resp struct {
		Data []Client `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/sta"), nil, &resp); err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	return resp.Data, nil
}

// ListDevices returns all adopted UniFi devices.
func (c *UnifiClient) ListDevices(ctx context.Context) ([]Device, error) {
	var resp struct {
		Data []Device `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/device-basic"), nil, &resp); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return resp.Data, nil
}

// SiteHealthList returns health stats for the site.
func (c *UnifiClient) SiteHealthList(ctx context.Context) ([]SiteHealth, error) {
	var resp struct {
		Data []SiteHealth `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/health"), nil, &resp); err != nil {
		return nil, fmt.Errorf("site health: %w", err)
	}
	return resp.Data, nil
}

// TestConnection verifies the API key by fetching site health.
func (c *UnifiClient) TestConnection(ctx context.Context) (string, error) {
	health, err := c.SiteHealthList(ctx)
	if err != nil {
		return "", err
	}
	total := 0
	for _, h := range health {
		total += h.NumUser + h.NumGuest + h.NumIoT
	}
	if len(health) > 0 {
		return fmt.Sprintf("Connected — %d client(s) across %d subsystem(s)", total, len(health)), nil
	}
	return "Connected OK", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
