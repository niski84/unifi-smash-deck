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

// ProtectCamera is a UniFi Protect camera from the bootstrap endpoint.
type ProtectCamera struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	State        string `json:"state"`
	MAC          string `json:"mac"`
	Host         string `json:"host,omitempty"`
	IsConnected  bool   `json:"isConnected"`
	IsRecording  bool   `json:"isRecording"`
	IsMotionDetected bool `json:"isMotionDetected"`
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

// getNetworkRaw fetches the full raw JSON object for a single network.
// UniFi requires the full object in PUT requests — partial patches are silently ignored.
func (c *UnifiClient) getNetworkRaw(ctx context.Context, networkID string) (map[string]any, error) {
	var resp struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			RC string `json:"rc"`
		} `json:"meta"`
	}
	// Fetch the single network object by ID from the list endpoint.
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/networkconf/"+networkID), nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		// Fall back to fetching all and finding by ID.
		var all struct {
			Data []map[string]any `json:"data"`
		}
		if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/networkconf"), nil, &all); err != nil {
			return nil, err
		}
		for _, n := range all.Data {
			if id, _ := n["_id"].(string); id == networkID {
				return n, nil
			}
		}
		return nil, fmt.Errorf("network %s not found", networkID)
	}
	return resp.Data[0], nil
}

// SetNetworkEnabled enables or disables a network by ID.
// It fetches the full object first and sends it back with only the enabled field changed,
// because the UniFi API silently ignores partial PUT payloads.
func (c *UnifiClient) SetNetworkEnabled(ctx context.Context, networkID string, enabled bool) error {
	obj, err := c.getNetworkRaw(ctx, networkID)
	if err != nil {
		return fmt.Errorf("get network for update: %w", err)
	}
	obj["enabled"] = enabled

	var putResp struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg,omitempty"`
		} `json:"meta"`
	}
	url := c.apiURL("rest/networkconf/" + networkID)
	if err := c.doJSON(ctx, http.MethodPut, url, obj, &putResp); err != nil {
		return fmt.Errorf("put network: %w", err)
	}
	if putResp.Meta.RC != "" && putResp.Meta.RC != "ok" {
		return fmt.Errorf("unifi rejected update: rc=%s msg=%s", putResp.Meta.RC, putResp.Meta.Msg)
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

// protectIntURL builds a URL under /proxy/protect/integration/v1/ (API-key compatible).
func (c *UnifiClient) protectIntURL(path string) string {
	return fmt.Sprintf("%s/proxy/protect/integration/v1/%s", c.host, strings.TrimPrefix(path, "/"))
}

// protectURL builds the URL under the legacy /proxy/protect/api/ path (session auth).
func (c *UnifiClient) protectURL(path string) string {
	return fmt.Sprintf("%s/proxy/protect/api/%s", c.host, strings.TrimPrefix(path, "/"))
}

// doRaw performs a request and returns the raw response body and content-type.
// Used for binary responses like camera snapshots.
func (c *UnifiClient) doRaw(ctx context.Context, method, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, "", fmt.Errorf("auth failed (HTTP %d) — check API key", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("not found (HTTP 404) — UniFi Protect may not be installed or camera ID is invalid")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 120 {
			snippet = snippet[:120]
		}
		return nil, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// ListCameras returns all cameras from UniFi Protect via the integration API.
func (c *UnifiClient) ListCameras(ctx context.Context) ([]ProtectCamera, error) {
	var list []ProtectCamera
	if err := c.doJSON(ctx, http.MethodGet, c.protectIntURL("cameras"), nil, &list); err != nil {
		return nil, fmt.Errorf("list cameras: %w", err)
	}
	return list, nil
}

// CameraSnapshot fetches a live JPEG snapshot for the given camera ID.
// Pass highQuality=true to request 1080p or higher resolution from Protect.
// If the camera does not support high quality, falls back to standard quality automatically.
func (c *UnifiClient) CameraSnapshot(ctx context.Context, cameraID string, highQuality bool) ([]byte, string, error) {
	base := c.protectIntURL("cameras/" + cameraID + "/snapshot")
	ts := timeNowMS()

	if highQuality {
		url := fmt.Sprintf("%s?ts=%d&force=true&highQuality=true", base, ts)
		if data, ct, err := c.doRaw(ctx, http.MethodGet, url); err == nil {
			return data, ct, nil
		}
		// Fall through to standard quality if HQ is unsupported.
	}

	url := fmt.Sprintf("%s?ts=%d&force=true", base, ts)
	data, ct, err := c.doRaw(ctx, http.MethodGet, url)
	if err != nil {
		return nil, "", fmt.Errorf("camera snapshot: %w", err)
	}
	return data, ct, nil
}

func timeNowMS() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
