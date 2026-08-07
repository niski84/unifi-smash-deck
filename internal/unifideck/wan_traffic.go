package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WANTrafficSample is a single reading of the gateway's WAN port cumulative
// byte counters. The UDM exposes only lifetime totals — "today" is computed by
// differencing against a baseline captured at local midnight (or process start,
// whichever came first today).
type WANTrafficSample struct {
	SiteID string `json:"site_id"`
	TS     int64  `json:"ts"`
	// Interface and Source make it possible to verify that this sample came
	// from the WAN-facing interface rather than a LAN/trunk port.
	Interface string `json:"interface"`
	Source    string `json:"source"`
	RXBytes   int64  `json:"rx_bytes"` // lifetime download bytes (internet → LAN)
	TXBytes   int64  `json:"tx_bytes"` // lifetime upload bytes (LAN → internet)
}

const expectedWANInterface = "eth8"

func localMidnightUnix(now time.Time) int64 {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
}

// FetchWANTraffic queries the gateway device's WAN uplink byte counters.
// Uses GET /proxy/network/api/s/{site}/stat/device and finds the device whose
// type is udm/ugw (the gateway), then reads its uplink.rx_bytes / tx_bytes.
//
// The uplink object is the WAN interface (eth8/Port 9) — a pure internet-facing
// port with no VLANs trunked on it. These counters represent real WAN traffic
// only, not internal LAN/VLAN traffic. Cross-validated against SSH /proc/net/dev
// eth8 — they match exactly.
func FetchWANTraffic(ctx context.Context, site SiteConnection) (*WANTrafficSample, error) {
	siteName := siteNameOrDefault(site)
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device",
		strings.TrimRight(site.Host, "/"),
		siteName)

	body, err := doHTTPRequest(ctx, url, site.Token)
	if err != nil {
		return nil, fmt.Errorf("fetch wan traffic: %w", err)
	}

	var resp struct {
		Data []struct {
			Type   string `json:"type"`
			Uplink struct {
				RXBytes int64  `json:"rx_bytes"`
				TXBytes int64  `json:"tx_bytes"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"uplink"`
			PortTable []struct {
				IsUplink bool  `json:"is_uplink"`
				RXBytes  int64 `json:"rx_bytes"`
				TXBytes  int64 `json:"tx_bytes"`
			} `json:"port_table"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode device list for wan traffic: %w", err)
	}

	for _, dev := range resp.Data {
		// Only the gateway (udm/ugw) has the WAN uplink. Do not trust an
		// arbitrary gateway counter: the WAN total must come from the known
		// internet-facing interface, not a LAN or switch uplink.
		if dev.Type != "udm" && dev.Type != "ugw" {
			continue
		}
		interfaceName := strings.ToLower(strings.TrimSpace(dev.Uplink.Name))
		comment := strings.ToLower(strings.TrimSpace(dev.Uplink.Comment))
		if interfaceName != expectedWANInterface && comment != "wan" {
			continue
		}
		sample := &WANTrafficSample{
			SiteID:    site.ID,
			TS:        time.Now().Unix(),
			Interface: dev.Uplink.Name,
			Source:    "gateway WAN uplink",
			RXBytes:   dev.Uplink.RXBytes,
			TXBytes:   dev.Uplink.TXBytes,
		}
		// Fall back only to a port explicitly marked as the uplink, and only
		// after the gateway itself identified its WAN interface above.
		if sample.RXBytes == 0 && sample.TXBytes == 0 {
			for _, p := range dev.PortTable {
				if p.IsUplink {
					sample.RXBytes = p.RXBytes
					sample.TXBytes = p.TXBytes
					sample.Source = "gateway WAN port_table uplink"
					break
				}
			}
		}
		if sample.RXBytes > 0 || sample.TXBytes > 0 {
			return sample, nil
		}
	}
	return nil, fmt.Errorf("no gateway (udm/ugw) with validated WAN interface %q found", expectedWANInterface)
}

// ── "Today" computation ──────────────────────────────────────────────────────

// ComputeTodayTraffic takes a sorted (oldest-first) list of WAN traffic samples
// and returns the download/upload bytes since local midnight.
//
// Strategy: find the first sample at or after today's local midnight (00:00)
// and use it as the baseline. Subtract that from the latest sample. If the
// earliest sample is after midnight (process started late), use it as the
// baseline. Handles counter rollover (gateway reboot) by clamping to zero.
func ComputeTodayTraffic(samples []WANTrafficSample) (rxToday, txToday int64) {
	if len(samples) == 0 {
		return 0, 0
	}

	return computeTodayTrafficAt(samples, time.Now())
}

func computeTodayTrafficAt(samples []WANTrafficSample, now time.Time) (rxToday, txToday int64) {
	if len(samples) == 0 {
		return 0, 0
	}

	// Truncate(24*time.Hour) truncates the absolute Unix time, which is UTC
	// aligned. Build midnight in the local location instead.
	midnight := localMidnightUnix(now)
	latest := samples[len(samples)-1]

	// Find the baseline: first sample at or after midnight.
	var baseline WANTrafficSample
	found := false
	for _, s := range samples {
		if s.TS >= midnight {
			baseline = s
			found = true
			break
		}
	}
	if !found {
		// No sample since midnight (shouldn't happen if poller runs), use earliest.
		baseline = samples[0]
	}

	rxToday = latest.RXBytes - baseline.RXBytes
	txToday = latest.TXBytes - baseline.TXBytes
	if rxToday < 0 {
		rxToday = 0 // counter rollover (gateway rebooted)
	}
	if txToday < 0 {
		txToday = 0
	}
	return rxToday, txToday
}
