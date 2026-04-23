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

// UISPClient talks to a UISP NMS instance (e.g. account.sbtnet.com/nms).
// Auth uses the x-auth-token header with a read-only or admin token.
type UISPClient struct {
	Host   string
	Token  string
	http   *http.Client
}

// NewUISPClient builds a client. Host should include scheme (e.g. https://foo).
func NewUISPClient(host, token string) *UISPClient {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	return &UISPClient{
		Host:  host,
		Token: strings.TrimSpace(token),
		http: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *UISPClient) IsConfigured() bool {
	return c.Host != "" && c.Token != ""
}

func (c *UISPClient) apiURL(path string) string {
	return c.Host + "/nms/api/v2.1" + path
}

func (c *UISPClient) doJSON(ctx context.Context, method, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-auth-token", c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uisp %s %s: %s: %s", method, url, resp.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// testUISPConnection calls /nms/info to validate the token.
func testUISPConnection(ctx context.Context, host, token string) (string, error) {
	c := NewUISPClient(host, token)
	if !c.IsConfigured() {
		return "", fmt.Errorf("host or token is empty")
	}
	var info struct {
		NetworkName  string `json:"networkName"`
		UNMSHostname string `json:"UNMSHostname"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("/nms/info"), &info); err != nil {
		return "", err
	}
	label := info.NetworkName
	if label == "" {
		label = info.UNMSHostname
	}
	if label == "" {
		label = "UISP"
	}
	return fmt.Sprintf("connected to %s", label), nil
}
