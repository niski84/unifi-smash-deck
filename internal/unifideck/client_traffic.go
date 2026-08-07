package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ClientTrafficSample is a per-client byte-counter reading at a point in time.
// Sampled every 5 minutes so we can diff consecutive samples to attribute WAN
// traffic to specific devices — answering "what downloaded 33 GB overnight?"
type ClientTrafficSample struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	TS       int64  `json:"ts"`
	// UniFi's client counters are from the gateway's perspective: tx_bytes is
	// gateway → client (download), rx_bytes is client → gateway (upload). This
	// is the opposite direction from a host's usual socket naming.
	RXBytes int64 `json:"rx_bytes"` // raw UDM counter: client → gateway
	TXBytes int64 `json:"tx_bytes"` // raw UDM counter: gateway → client
}

// FetchClientTraffic queries all active clients' cumulative byte counters.
// Uses GET /proxy/network/api/s/{site}/stat/sta — the same endpoint as
// ListClients but we extract the byte fields that the Client struct omits.
func FetchClientTraffic(ctx context.Context, site SiteConnection) ([]ClientTrafficSample, error) {
	siteName := siteNameOrDefault(site)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/sta",
		strings.TrimRight(site.Host, "/"),
		siteName)

	body, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, fmt.Errorf("fetch client traffic: %w", err)
	}

	var resp struct {
		Data []struct {
			MAC        string `json:"mac"`
			Name       string `json:"name"`
			IP         string `json:"ip"`
			Hostname   string `json:"hostname"`
			IsWired    bool   `json:"is_wired"`
			SwitchMAC  string `json:"sw_mac"`
			SwitchPort int    `json:"sw_port"`
			RXBytes    int64  `json:"rx_bytes"`
			TXBytes    int64  `json:"tx_bytes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode client traffic: %w", err)
	}

	// UniFi keeps disconnected wired stations in stat/sta. Fetch the live
	// switch port table so a stale station cannot produce a false "active"
	// traffic sample after its cable is unplugged or its outlet is switched off.
	portStates, err := fetchLiveSwitchPorts(ctx, site)
	if err != nil {
		return nil, fmt.Errorf("fetch live switch ports: %w", err)
	}

	now := time.Now().Unix()
	samples := make([]ClientTrafficSample, 0, len(resp.Data))
	for _, c := range resp.Data {
		if c.IsWired {
			state, known := portStates[trafficPortKey(c.SwitchMAC, c.SwitchPort)]
			if !known || !state {
				// The station record is historical or the physical link is down;
				// do not snapshot its stale counters as if it were connected.
				continue
			}
		}
		if c.RXBytes == 0 && c.TXBytes == 0 {
			continue // skip idle/no-data clients
		}
		samples = append(samples, ClientTrafficSample{
			MAC:      c.MAC,
			Name:     c.Name,
			IP:       c.IP,
			Hostname: c.Hostname,
			TS:       now,
			RXBytes:  c.RXBytes,
			TXBytes:  c.TXBytes,
		})
	}
	return samples, nil
}

func trafficPortKey(mac string, port int) string {
	return strings.ToLower(strings.TrimSpace(mac)) + fmt.Sprintf("/%d", port)
}

// fetchLiveSwitchPorts returns the current up/down state for every switch
// port. This is intentionally separate from stat/sta: station records are
// cached by UniFi, while port_table reflects the physical link.
func fetchLiveSwitchPorts(ctx context.Context, site SiteConnection) (map[string]bool, error) {
	siteName := siteNameOrDefault(site)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device",
		strings.TrimRight(site.Host, "/"), siteName)
	body, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			MAC       string `json:"mac"`
			PortTable []struct {
				PortIndex int  `json:"port_idx"`
				Up        bool `json:"up"`
			} `json:"port_table"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode switch ports: %w", err)
	}
	states := make(map[string]bool)
	for _, device := range resp.Data {
		for _, port := range device.PortTable {
			if port.PortIndex > 0 {
				states[trafficPortKey(device.MAC, port.PortIndex)] = port.Up
			}
		}
	}
	return states, nil
}

// ClientTrafficAttribution is the per-device delta over a time window.
// This is what the /api/isp/traffic/attribution endpoint returns — it tells
// you exactly which device downloaded/uploaded how much since a baseline.
type ClientTrafficAttribution struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	// rx_delta/tx_delta are retained as API names for frontend compatibility,
	// but their meanings are normalized: rx_delta is download and tx_delta is
	// upload. The raw UDM counter names are not exposed as direction labels.
	RXDelta    int64  `json:"rx_delta"`     // normalized bytes downloaded
	TXDelta    int64  `json:"tx_delta"`     // normalized bytes uploaded
	RXDeltaStr string `json:"rx_delta_str"` // human-readable
	TXDeltaStr string `json:"tx_delta_str"`
	TotalDelta int64  `json:"total_delta"`
}

// AttributeClientTraffic takes two snapshots (baseline + latest) and computes
// per-client deltas, sorted by total bytes transferred (descending). This is
// the core of "who downloaded 33 GB?" — diff the oldest and newest client
// samples within the time window.
func AttributeClientTraffic(baseline, latest []ClientTrafficSample) []ClientTrafficAttribution {
	byMAC := map[string]ClientTrafficSample{}
	for _, s := range latest {
		byMAC[s.MAC] = s
	}

	var results []ClientTrafficAttribution
	for _, base := range baseline {
		cur, ok := byMAC[base.MAC]
		if !ok {
			continue // client went offline — skip
		}
		// UDM client direction is gateway-relative, so normalize it here:
		// tx_bytes is download and rx_bytes is upload.
		rxDelta := cur.TXBytes - base.TXBytes
		txDelta := cur.RXBytes - base.RXBytes
		if rxDelta < 0 {
			rxDelta = cur.TXBytes // counter reset (client reconnected)
		}
		if txDelta < 0 {
			txDelta = cur.RXBytes
		}
		if rxDelta == 0 && txDelta == 0 {
			continue // no traffic in window
		}
		name := cur.Name
		if name == "" {
			name = cur.Hostname
		}
		if name == "" {
			name = cur.MAC
		}
		results = append(results, ClientTrafficAttribution{
			MAC:        cur.MAC,
			Name:       name,
			IP:         cur.IP,
			Hostname:   cur.Hostname,
			RXDelta:    rxDelta,
			TXDelta:    txDelta,
			RXDeltaStr: formatBytes(rxDelta),
			TXDeltaStr: formatBytes(txDelta),
			TotalDelta: rxDelta + txDelta,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalDelta > results[j].TotalDelta
	})
	return results
}
