package unifideck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// Network represents a UniFi network/VLAN from rest/networkconf.
type Network struct {
	ID          string `json:"_id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	VlanID      int    `json:"vlan,omitempty"`
	Enabled     bool   `json:"enabled"`
	IPSubnet    string `json:"ip_subnet,omitempty"`
	NetworkGroup string `json:"networkgroup,omitempty"`
	DHCPEnabled  bool   `json:"dhcpd_enabled,omitempty"`
}

// Client represents a connected client device.
type Client struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Name       string `json:"name,omitempty"`
	NetworkID  string `json:"network_id,omitempty"`
	VLAN       int    `json:"vlan,omitempty"`
	SignalDBM  int    `json:"signal,omitempty"`
	Wired      bool   `json:"is_wired"`
	LastSeen   int64  `json:"last_seen,omitempty"`
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
	RxBytesR  int64  `json:"rx_bytes-r,omitempty"`
	TxBytesR  int64  `json:"tx_bytes-r,omitempty"`
}

// UnifiClient handles session auth and API calls to a UDM Pro.
type UnifiClient struct {
	host      string
	user      string
	pass      string
	site      string
	httpClient *http.Client
	jar        *cookiejar.Jar
	mu         sync.Mutex
	csrfToken  string
	loggedIn   bool
}

func NewUnifiClient(host, user, pass, site string) *UnifiClient {
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // UDM Pro uses self-signed cert
	}
	return &UnifiClient{
		host: strings.TrimRight(host, "/"),
		user: user,
		pass: pass,
		site: site,
		jar:  jar,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			Jar:       jar,
		},
	}
}

func (c *UnifiClient) IsConfigured() bool {
	return c.host != "" && c.user != "" && c.pass != ""
}

// login authenticates and stores the session cookie + CSRF token.
func (c *UnifiClient) login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	payload, _ := json.Marshal(map[string]string{"username": c.user, "password": c.pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/api/auth/login", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("unifi login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unifi login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unifi login failed: HTTP %d — %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Extract CSRF token from response headers (X-Csrf-Token or x-updated-csrf-token)
	if tok := resp.Header.Get("X-Csrf-Token"); tok != "" {
		c.csrfToken = tok
	} else if tok := resp.Header.Get("x-updated-csrf-token"); tok != "" {
		c.csrfToken = tok
	}
	c.loggedIn = true
	return nil
}

// apiURL builds the full URL for a site-level endpoint.
func (c *UnifiClient) apiURL(path string) string {
	site := c.site
	if site == "" {
		site = "default"
	}
	return fmt.Sprintf("%s/proxy/network/api/s/%s/%s", c.host, site, strings.TrimPrefix(path, "/"))
}

// doJSON performs a JSON request, re-logging in on 401.
func (c *UnifiClient) doJSON(ctx context.Context, method, url string, body any, out any) error {
	if !c.loggedIn {
		if err := c.login(ctx); err != nil {
			return err
		}
	}

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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.mu.Lock()
	if c.csrfToken != "" {
		req.Header.Set("X-Csrf-Token", c.csrfToken)
	}
	c.mu.Unlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Re-login on 401 and retry once
	if resp.StatusCode == http.StatusUnauthorized {
		c.mu.Lock()
		c.loggedIn = false
		c.mu.Unlock()
		if err := c.login(ctx); err != nil {
			return err
		}
		var retryReader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			retryReader = bytes.NewReader(b)
		}
		req2, _ := http.NewRequestWithContext(ctx, method, url, retryReader)
		req2.Header.Set("Accept", "application/json")
		if body != nil {
			req2.Header.Set("Content-Type", "application/json")
		}
		c.mu.Lock()
		if c.csrfToken != "" {
			req2.Header.Set("X-Csrf-Token", c.csrfToken)
		}
		c.mu.Unlock()
		resp2, err := c.httpClient.Do(req2)
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		resp = resp2
	}

	// Update CSRF token from response
	if tok := resp.Header.Get("X-Csrf-Token"); tok != "" {
		c.mu.Lock()
		c.csrfToken = tok
		c.mu.Unlock()
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unifi API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
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

// TestConnection verifies login and returns a brief status string.
func (c *UnifiClient) TestConnection(ctx context.Context) (string, error) {
	c.mu.Lock()
	c.loggedIn = false
	c.mu.Unlock()
	if err := c.login(ctx); err != nil {
		return "", err
	}
	health, err := c.SiteHealthList(ctx)
	if err != nil {
		return "login OK, health check failed: " + err.Error(), nil
	}
	for _, h := range health {
		if h.Subsystem == "lan" || h.Subsystem == "wlan" {
			return fmt.Sprintf("Connected — %d client(s)", h.NumUser+h.NumGuest+h.NumIoT), nil
		}
	}
	return "Connected OK", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
