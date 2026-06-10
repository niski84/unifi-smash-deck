package unifideck

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ── Shared finding types ──────────────────────────────────────────────────────

type FindingSeverity string

const (
	SevCritical FindingSeverity = "critical"
	SevWarning  FindingSeverity = "warning"
	SevInfo     FindingSeverity = "info"
	SevOK       FindingSeverity = "ok"
)

type HealthFinding struct {
	ID          string          `json:"id"`
	Category    string          `json:"category"` // "infrastructure","wifi","topology","security"
	Severity    FindingSeverity `json:"severity"`
	Title       string          `json:"title"`
	Detail      string          `json:"detail"`
	Fixable     bool            `json:"fixable,omitempty"`
	FixLabel    string          `json:"fix_label,omitempty"`
	FixEndpoint string          `json:"fix_endpoint,omitempty"` // POST URL relative to /api/
	FixBody     string          `json:"fix_body,omitempty"`     // JSON body for the fix POST
}

// ── Raw types for health checks ───────────────────────────────────────────────

type rawNetwork struct {
	ID          string `json:"_id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	Enabled     *bool  `json:"enabled"`
	WanGroup    string `json:"wan_networkgroup"`
	WanType     string `json:"wan_type"`
	IPSubnet    string `json:"ip_subnet"`
	VlanEnabled bool   `json:"vlan_enabled"`
	Vlan        int    `json:"vlan"`
}

type radioStats struct {
	Radio       string  `json:"radio"` // "ng"=2.4GHz "na"=5GHz
	Channel     int     `json:"channel"`
	NumSta      int     `json:"num_sta"`
	CUTotal     int     `json:"cu_total"`
	TxRetriesPct float64 `json:"tx_retries_pct"`
	TxPower     int     `json:"tx_power"`
	Satisfaction int    `json:"satisfaction"`
}

type radioConfig struct {
	Radio       string      `json:"radio"`
	TxPowerMode string      `json:"tx_power_mode"`
	Channel     interface{} `json:"channel"` // int or string depending on firmware
	Ht          int         `json:"ht"`
}

type portEntry struct {
	PortIdx   int    `json:"port_idx"`
	Name      string `json:"name"`
	Up        bool   `json:"up"`
	Speed     int    `json:"speed"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	PoeEnable bool   `json:"poe_enable"`
	PoePower  string `json:"poe_power,omitempty"` // API returns "4.50" as a string; empty when N/A
	PoeMode   string `json:"poe_mode,omitempty"`
	PoeGood   *bool  `json:"poe_good,omitempty"`
}

// poePowerWatts parses the PoePower string ("4.50") into a float64.
func (p portEntry) poePowerWatts() float64 {
	var w float64
	fmt.Sscanf(p.PoePower, "%f", &w)
	return w
}

type portOverride struct {
	PortIdx              int      `json:"port_idx"`
	Name                 string   `json:"name"`
	NativeNetworkID      string   `json:"native_networkconf_id"`
	TaggedNetworkIDs     []string `json:"tagged_networkconf_ids"`
	ExcludedNetworkIDs   []string `json:"excluded_networkconf_ids"`
	Forward              string   `json:"forward"`
	TaggedVLANMgmt       string   `json:"tagged_vlan_mgmt"` // "auto"|"block_all"|"custom"
}

type rawDevice struct {
	ID             string         `json:"_id"`
	Name           string         `json:"name"`
	MAC            string         `json:"mac"`
	Model          string         `json:"model"`
	Type           string         `json:"type"`
	Version        string         `json:"version"`
	Upgradable     bool           `json:"upgradable"`
	UpgradeFW      string         `json:"upgrade_to_firmware"`
	Uptime         int64          `json:"uptime"`
	State          int            `json:"state"`
	RebootRequired bool           `json:"reboot_required"`
	TotalMaxPower  float64        `json:"total_max_power,omitempty"`
	SysStats       struct {
		MemUsed  float64 `json:"mem_used"`
		MemTotal float64 `json:"mem_total"`
		LoadAvg1 string  `json:"loadavg_1"`
	} `json:"sys_stats"`
	RadioTableStats []radioStats   `json:"radio_table_stats"`
	RadioTable      []radioConfig  `json:"radio_table"`
	PortTable       []portEntry    `json:"port_table"`
	PortOverrides   []portOverride `json:"port_overrides"`
}

type rawSiteHealth struct {
	Subsystem string  `json:"subsystem"`
	Status    string  `json:"status"`
	WanIP     string  `json:"wan_ip"`
	Latency   int     `json:"latency"`
	Drops     int     `json:"drops"`
	UptimeStats map[string]struct {
		Availability float64 `json:"availability"`
		Downtime     int64   `json:"downtime"`
	} `json:"uptime_stats"`
}

type NetworkHealthResult struct {
	RunAt    time.Time       `json:"run_at"`
	Findings []HealthFinding `json:"findings"`
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

func fetchDevices(ctx context.Context, c *UnifiClient) ([]rawDevice, error) {
	var resp struct {
		Data []rawDevice `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/device"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func fetchNetworks(ctx context.Context, c *UnifiClient) ([]rawNetwork, error) {
	var resp struct {
		Data []rawNetwork `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/networkconf"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func fetchSiteHealth(ctx context.Context, c *UnifiClient) ([]rawSiteHealth, error) {
	var resp struct {
		Data []rawSiteHealth `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/health"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// isPrivateIP returns true if the given IP string is in RFC1918 space.
func isPrivateIP(ip string) bool {
	// Strip port if present
	if i := strings.LastIndex(ip, ":"); i > 0 && strings.Contains(ip, ".") {
		ip = ip[:i]
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate()
}

// ── Health check runner ───────────────────────────────────────────────────────

func RunNetworkHealthCheck(ctx context.Context, c *UnifiClient) (*NetworkHealthResult, error) {
	// Fan out all fetches concurrently.
	type result struct {
		devices  []rawDevice
		networks []rawNetwork
		health   []rawSiteHealth
		wlans    []WLAN
		clients  []rawSta
		devErr   error
		netErr   error
		hlthErr  error
		wlanErr  error
		cliErr   error
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		// Sequential but fast enough; if we want true parallel we'd use goroutines + errgroup.
		r.devices, r.devErr   = fetchDevices(ctx, c)
		r.networks, r.netErr  = fetchNetworks(ctx, c)
		r.health, r.hlthErr   = fetchSiteHealth(ctx, c)
		r.wlans, r.wlanErr    = c.ListWLANs(ctx)
		r.clients, r.cliErr   = listRawStations(ctx, c)
		ch <- r
	}()
	r := <-ch

	if r.devErr != nil  { return nil, fmt.Errorf("fetch devices: %w", r.devErr) }
	if r.netErr != nil  { return nil, fmt.Errorf("fetch networks: %w", r.netErr) }
	if r.hlthErr != nil { return nil, fmt.Errorf("fetch health: %w", r.hlthErr) }
	// wlan/client errors are non-fatal
	if r.wlanErr != nil { r.wlans = nil }
	if r.cliErr != nil  { r.clients = nil }

	var findings []HealthFinding

	// Build lookup maps
	netByID := map[string]rawNetwork{}
	for _, n := range r.networks { netByID[n.ID] = n }

	// ── 1. Double NAT ─────────────────────────────────────────────────────────
	for _, h := range r.health {
		if h.Subsystem == "wan" && h.WanIP != "" {
			if isPrivateIP(h.WanIP) {
				findings = append(findings, HealthFinding{
					ID: "double_nat", Category: "topology", Severity: SevCritical,
					Title:  fmt.Sprintf("Double NAT Detected (WAN IP: %s)", h.WanIP),
					Detail: fmt.Sprintf(
						"The UDM Pro's WAN IP is %s — a private RFC1918 address. "+
							"This means it is behind another router doing NAT. "+
							"Port forwarding, VPN, and UPnP will not work correctly. "+
							"Fix: put the upstream router (your Google Fiber Network Box) into bridge/passthrough mode, "+
							"or configure it to assign a DMZ to your UDM Pro's MAC address.",
						h.WanIP),
				})
			} else {
				findings = append(findings, HealthFinding{
					ID: "double_nat", Category: "topology", Severity: SevOK,
					Title:  "WAN IP is Public — No Double NAT",
					Detail: fmt.Sprintf("WAN IP %s is a routable public address.", h.WanIP),
				})
			}
		}
	}

	// ── 2. WAN uptime & latency ───────────────────────────────────────────────
	for _, h := range r.health {
		if h.Subsystem == "wan" {
			if h.Drops > 10 {
				findings = append(findings, HealthFinding{
					ID: "wan_drops", Category: "topology", Severity: SevWarning,
					Title:  fmt.Sprintf("WAN: %d Packet Drops Detected", h.Drops),
					Detail: fmt.Sprintf("%d drops recorded. May indicate ISP instability or a flaky cable between the ONT and UDM Pro.", h.Drops),
				})
			}
			if h.Latency > 30 {
				findings = append(findings, HealthFinding{
					ID: "wan_latency", Category: "topology", Severity: SevWarning,
					Title:  fmt.Sprintf("WAN Latency High: %dms", h.Latency),
					Detail: fmt.Sprintf("Average WAN latency of %dms is above the 30ms threshold. Investigate ISP or ONT issues.", h.Latency),
				})
			}
		}
	}

	// ── 3. WAN2 / unused secondary WAN ───────────────────────────────────────
	for _, n := range r.networks {
		if n.Purpose != "wan" { continue }
		if n.WanGroup == "WAN2" {
			enabled := n.Enabled == nil || *n.Enabled
			// Check uptime_stats in health
			var wan2Down bool
			for _, h := range r.health {
				if h.Subsystem == "wan" {
					if s, ok := h.UptimeStats["WAN2"]; ok && s.Availability == 0 {
						wan2Down = true
					}
				}
			}
			if enabled && wan2Down {
				findings = append(findings, HealthFinding{
					ID: "wan2_down", Category: "topology", Severity: SevWarning,
					Title:  "WAN2 (Internet 2) Is Enabled But 100% Down",
					Detail: "Internet 2 is configured as a failover WAN but has 0% availability — nothing is plugged in. " +
						"Disable it to clean up the dashboard and prevent unnecessary failover probing.",
					Fixable: true, FixLabel: "Disable WAN2",
					FixEndpoint: "network-health/networks/" + n.ID + "/disable",
				})
			} else if !enabled {
				findings = append(findings, HealthFinding{
					ID: "wan2_down", Category: "topology", Severity: SevOK,
					Title:  "WAN2 (Internet 2) Disabled",
					Detail: "Secondary WAN is correctly disabled.",
				})
			}
		}
	}

	// ── 4. Device memory & CPU ────────────────────────────────────────────────
	for _, d := range r.devices {
		if d.SysStats.MemTotal == 0 { continue }
		memPct := int(d.SysStats.MemUsed / d.SysStats.MemTotal * 100)
		if memPct >= 90 {
			findings = append(findings, HealthFinding{
				ID: "mem_" + d.ID, Category: "infrastructure", Severity: SevCritical,
				Title:  fmt.Sprintf("Memory Critical: %s at %d%%", d.Name, memPct),
				Detail: fmt.Sprintf("%s is using %d%% of its RAM. At this level you may see OOM kills, service crashes, or sluggish UI. "+
					"Consider reducing active services or upgrading hardware.", d.Name, memPct),
			})
		} else if memPct >= 80 {
			findings = append(findings, HealthFinding{
				ID: "mem_" + d.ID, Category: "infrastructure", Severity: SevWarning,
				Title:  fmt.Sprintf("Memory Elevated: %s at %d%%", d.Name, memPct),
				Detail: fmt.Sprintf("%s is using %d%% of its RAM. Worth monitoring — heavy traffic or more clients could push it into critical territory.", d.Name, memPct),
			})
		}
	}

	// ── 5. Device reboot required ─────────────────────────────────────────────
	for _, d := range r.devices {
		if d.RebootRequired {
			findings = append(findings, HealthFinding{
				ID: "reboot_" + d.ID, Category: "infrastructure", Severity: SevWarning,
				Title:  fmt.Sprintf("Reboot Required: %s", d.Name),
				Detail: fmt.Sprintf("%s has a pending reboot (likely after a firmware update). Schedule a maintenance window to reboot it.", d.Name),
			})
		}
	}

	// ── 6. Firmware upgrades available ───────────────────────────────────────
	for _, d := range r.devices {
		if d.Upgradable && d.UpgradeFW != "" {
			findings = append(findings, HealthFinding{
				ID: "fw_" + d.ID, Category: "infrastructure", Severity: SevInfo,
				Title:  fmt.Sprintf("Firmware Update Available: %s", d.Name),
				Detail: fmt.Sprintf("%s can be updated to firmware %s (currently %s).", d.Name, d.UpgradeFW, d.Version),
			})
		}
	}

	// ── 7. AP 2.4 GHz overload ────────────────────────────────────────────────
	for _, d := range r.devices {
		if d.Type != "uap" { continue }
		for _, rs := range d.RadioTableStats {
			if rs.Radio != "ng" { continue }
			if rs.NumSta >= 20 {
				sev := SevCritical
				if rs.NumSta < 25 { sev = SevWarning }
				findings = append(findings, HealthFinding{
					ID: "ap_overload_" + d.ID, Category: "wifi", Severity: sev,
					Title:  fmt.Sprintf("AP Overloaded: %s has %d clients on 2.4 GHz", d.Name, rs.NumSta),
					Detail: fmt.Sprintf(
						"%s is serving %d clients on 2.4 GHz (channel %d, %d%% utilization, %.0f%% TX retry rate). "+
							"Recommended max is ~15–18 for reliable IoT operation. "+
							"Solutions: add a second AP near the device cluster, or enable band steering on dual-band SSIDs "+
							"to migrate capable clients to 5 GHz.",
						d.Name, rs.NumSta, rs.Channel, rs.CUTotal, rs.TxRetriesPct),
				})
			}
			if rs.CUTotal >= 70 {
				findings = append(findings, HealthFinding{
					ID: "ap_util_" + d.ID, Category: "wifi", Severity: SevWarning,
					Title:  fmt.Sprintf("High 2.4 GHz Utilization: %s at %d%%", d.Name, rs.CUTotal),
					Detail: fmt.Sprintf("%s 2.4 GHz channel utilization is %d%%. Above 70%% causes significant performance degradation for all clients on the channel.", d.Name, rs.CUTotal),
				})
			}
			if rs.TxRetriesPct >= 20 {
				findings = append(findings, HealthFinding{
					ID: "ap_retry_" + d.ID, Category: "wifi", Severity: SevWarning,
					Title:  fmt.Sprintf("High TX Retry Rate: %s at %.0f%%", d.Name, rs.TxRetriesPct),
					Detail: fmt.Sprintf("%s has a %.0f%% TX retry rate on 2.4 GHz. High retries indicate RF interference, congestion, or clients at the edge of coverage.", d.Name, rs.TxRetriesPct),
				})
			}
		}
	}

	// ── 8. BSS Transition (band steering) ────────────────────────────────────
	for _, w := range r.wlans {
		if !w.Enabled { continue }
		bands := 0
		if strings.Contains(w.WlanBand, "2g") || w.WlanBand == "both" { bands++ }
		if strings.Contains(w.WlanBand, "5g") || w.WlanBand == "both" { bands++ }
		isDualBand := w.WlanBand == "both" || (len(w.WlanBand) > 2)
		_ = isDualBand
		// Check radio_table_stats via WLAN isn't directly available; check wlan_bands slice length
		// The WLAN struct has wlan_band; for "both" it supports steering
		if w.WlanBand == "both" {
			_ = bands
		}
	}
	// BSS transition check via WLAN bss_transition field — need to re-fetch raw wlans
	// Already have wlans; check bss_transition by checking the raw JSON via the existing ListWLANs
	// The WLAN struct doesn't include bss_transition — add it inline for this check
	type wlanRaw struct {
		ID            string `json:"_id"`
		Name          string `json:"name"`
		WlanBand      string `json:"wlan_band"`
		BssTransition bool   `json:"bss_transition"`
		Enabled       bool   `json:"enabled"`
	}
	var wlanResp struct {
		Data []wlanRaw `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/wlanconf"), nil, &wlanResp); err == nil {
		for _, w := range wlanResp.Data {
			if !w.Enabled || w.WlanBand != "both" { continue }
			if !w.BssTransition {
				findings = append(findings, HealthFinding{
					ID: "bss_" + w.ID, Category: "wifi", Severity: SevWarning,
					Title:  fmt.Sprintf("Band Steering Off: %s", w.Name),
					Detail: fmt.Sprintf("%q supports both 2.4 and 5 GHz but BSS Transition (802.11v band steering) is disabled. "+
						"Enabling it lets the AP suggest that capable clients move to 5 GHz, reducing 2.4 GHz congestion.", w.Name),
					Fixable: true, FixLabel: "Enable Band Steering",
					FixEndpoint: "network-health/wlans/" + w.ID + "/enable-bss-transition",
				})
			} else {
				findings = append(findings, HealthFinding{
					ID: "bss_" + w.ID, Category: "wifi", Severity: SevOK,
					Title:  fmt.Sprintf("Band Steering On: %s", w.Name),
					Detail: fmt.Sprintf("%q has BSS Transition enabled — capable clients will prefer 5 GHz.", w.Name),
				})
			}
		}
	}

	// ── 9. Switch ports at degraded speeds (10 or 100 Mbps) ─────────────────
	for _, d := range r.devices {
		if d.Type != "usw" { continue }
		for _, p := range d.PortTable {
			if !p.Up { continue }
			switch p.Speed {
			case 10:
				findings = append(findings, HealthFinding{
					ID: fmt.Sprintf("port10_%s_%d", d.ID, p.PortIdx), Category: "infrastructure", Severity: SevWarning,
					Title:  fmt.Sprintf("Port at 10 Mbps: %s port %d (%s)", d.Name, p.PortIdx, p.Name),
					Detail: fmt.Sprintf(
						"%s port %d (%q) is negotiating at 10 Mbps. "+
							"Almost always a damaged cable, bent RJ45 pin, or ancient NIC. Replace the patch cable first.",
						d.Name, p.PortIdx, p.Name),
				})
			case 100:
				// Only flag 100Mbps if the port has moved significant traffic (>500 MB),
				// indicating a device that should be capable of 1 Gbps.
				totalBytes := p.RxBytes + p.TxBytes
				if totalBytes > 500*1024*1024 {
					findings = append(findings, HealthFinding{
						ID: fmt.Sprintf("port100_%s_%d", d.ID, p.PortIdx), Category: "infrastructure", Severity: SevInfo,
						Title:  fmt.Sprintf("Port at 100 Mbps: %s port %d (%s)", d.Name, p.PortIdx, p.Name),
						Detail: fmt.Sprintf(
							"%s port %d (%q) is connected at 100 Mbps and has moved %.1f GB of traffic. "+
								"If the device supports Gigabit, try a different cable — 100 Mbps negotiation on a busy port "+
								"often means a marginal cable with damaged pairs.",
							d.Name, p.PortIdx, p.Name, float64(totalBytes)/1e9),
					})
				}
			}
		}
	}

	// ── 16. PoE budget per switch ─────────────────────────────────────────────
	for _, d := range r.devices {
		if d.Type != "usw" || d.TotalMaxPower == 0 { continue }
		var usedWatts float64
		for _, p := range d.PortTable {
			usedWatts += p.poePowerWatts()
		}
		pct := usedWatts / d.TotalMaxPower * 100
		switch {
		case pct >= 90:
			findings = append(findings, HealthFinding{
				ID: "poe_budget_" + d.ID, Category: "infrastructure", Severity: SevCritical,
				Title:  fmt.Sprintf("PoE Budget Critical: %s at %.0f%% (%.1f/%.0fW)", d.Name, pct, usedWatts, d.TotalMaxPower),
				Detail: fmt.Sprintf(
					"%s is consuming %.1fW of its %.0fW PoE budget (%.0f%%). "+
						"Adding or powering on another PoE device may cause existing devices to lose power unexpectedly. "+
						"Consider a switch with a higher PoE budget or reduce the number of PoE devices.",
					d.Name, usedWatts, d.TotalMaxPower, pct),
			})
		case pct >= 70:
			findings = append(findings, HealthFinding{
				ID: "poe_budget_" + d.ID, Category: "infrastructure", Severity: SevWarning,
				Title:  fmt.Sprintf("PoE Budget High: %s at %.0f%% (%.1f/%.0fW)", d.Name, pct, usedWatts, d.TotalMaxPower),
				Detail: fmt.Sprintf(
					"%s is consuming %.1fW of its %.0fW PoE budget (%.0f%%). "+
						"You have %.1fW of headroom — be mindful before adding more PoE devices.",
					d.Name, usedWatts, d.TotalMaxPower, pct, d.TotalMaxPower-usedWatts),
			})
		default:
			findings = append(findings, HealthFinding{
				ID: "poe_budget_" + d.ID, Category: "infrastructure", Severity: SevOK,
				Title:  fmt.Sprintf("PoE Budget OK: %s at %.0f%% (%.1f/%.0fW)", d.Name, pct, usedWatts, d.TotalMaxPower),
				Detail: fmt.Sprintf("%.1fW used of %.0fW capacity — %.1fW headroom available.", usedWatts, d.TotalMaxPower, d.TotalMaxPower-usedWatts),
			})
		}
	}

	// ── 17. Flaky clients (frequent reconnects) ───────────────────────────────
	now := time.Now().Unix()
	type flakyEntry struct{ name, uplink string; uptimeSec int64 }
	var flakyClients []flakyEntry
	for _, sta := range r.clients {
		if sta.DisconnectTimestamp == 0 || sta.AssocTime == 0 { continue }
		// Client is considered flaky if:
		//   - it disconnected within the last 6 hours, AND
		//   - its current uptime is under 1 hour (recently reconnected)
		disconnectedRecently := (now - sta.DisconnectTimestamp) < 6*3600
		shortUptime := sta.Uptime > 0 && sta.Uptime < 3600
		if disconnectedRecently && shortUptime {
			label := sta.Name
			if label == "" { label = sta.Hostname }
			if label == "" { label = sta.MAC }
			flakyClients = append(flakyClients, flakyEntry{name: label, uplink: sta.LastUplinkName, uptimeSec: sta.Uptime})
		}
	}
	if len(flakyClients) > 0 {
		names := make([]string, 0, len(flakyClients))
		for _, f := range flakyClients {
			uplinkInfo := ""
			if f.uplink != "" { uplinkInfo = " via " + f.uplink }
			names = append(names, fmt.Sprintf("%s%s (up %dm)", f.name, uplinkInfo, f.uptimeSec/60))
		}
		sev := SevInfo
		if len(flakyClients) >= 3 { sev = SevWarning }
		findings = append(findings, HealthFinding{
			ID: "flaky_clients", Category: "infrastructure", Severity: sev,
			Title:  fmt.Sprintf("%d Client(s) with Recent Disconnects", len(flakyClients)),
			Detail: fmt.Sprintf(
				"These clients disconnected within the last 6 hours and recently reconnected — "+
					"possible cable issues, power supply instability, or firmware loops: %s",
				strings.Join(names, "; ")),
		})
	}

	// ── 10. Port name vs VLAN mismatch ───────────────────────────────────────
	for _, d := range r.devices {
		if d.Type != "usw" { continue }
		for _, po := range d.PortOverrides {
			net, ok := netByID[po.NativeNetworkID]
			if !ok { continue }
			nameLower := strings.ToLower(po.Name)
			netLower  := strings.ToLower(net.Name)
			// Check for obvious mismatches (e.g. "IoT" in name but "Media" in actual VLAN)
			for _, candidate := range []string{"iot","media","work","guest","trusted","zone"} {
				inName := strings.Contains(nameLower, candidate)
				inNet  := strings.Contains(netLower, candidate)
				if inName && !inNet {
					findings = append(findings, HealthFinding{
						ID: fmt.Sprintf("port_mislabel_%s_%d", d.ID, po.PortIdx), Category: "topology", Severity: SevInfo,
						Title:  fmt.Sprintf("Port Mislabeled: %s port %d", d.Name, po.PortIdx),
						Detail: fmt.Sprintf(
							"Port %d on %s is named %q but its native VLAN is %q. "+
								"The label suggests a different network than what's configured. "+
								"Update the port name in the UniFi console to avoid confusion.",
							po.PortIdx, d.Name, po.Name, net.Name),
					})
					break
				}
			}
		}
	}

	// ── 11. IoT devices on wrong VLAN ────────────────────────────────────────
	iotSSID := ""
	for _, w := range r.wlans {
		if w.EnhancedIoT { iotSSID = w.Name; break }
	}
	type misplacedDevice struct {
		name  string
		mac   string
		essid string
	}
	var misplaced []misplacedDevice
	for _, sta := range r.clients {
		if sta.Wired || !isIoTOUI(sta.OUI) { continue }
		if iotSSID != "" && sta.ESSID != iotSSID && sta.ESSID != "" {
			label := sta.Name
			if label == "" { label = sta.Hostname }
			if label == "" { label = sta.MAC }
			misplaced = append(misplaced, misplacedDevice{name: label, mac: sta.MAC, essid: sta.ESSID})
		}
	}
	if len(misplaced) > 0 {
		names := make([]string, 0, len(misplaced))
		for _, m := range misplaced { names = append(names, fmt.Sprintf("%s (%s)", m.name, m.essid)) }
		findings = append(findings, HealthFinding{
			ID: "iot_wrong_vlan", Category: "topology", Severity: SevInfo,
			Title:  fmt.Sprintf("%d IoT Device(s) on Wrong SSID", len(misplaced)),
			Detail: fmt.Sprintf(
				"These IoT devices are connected to a non-IoT SSID. "+
					"They work but don't benefit from IoT-specific settings (2.4 GHz only, multicast enhancement). "+
					"To move them, re-pair from the %q SSID: %s",
				iotSSID, strings.Join(names, ", ")),
		})
	}

	// ── 12. Unnamed / unidentified devices ───────────────────────────────────
	var unnamedWifi, unnamedWired int
	for _, sta := range r.clients {
		if sta.Name == "" && sta.Hostname == "" {
			if sta.Wired { unnamedWired++ } else { unnamedWifi++ }
		}
	}
	if unnamedWifi+unnamedWired > 0 {
		findings = append(findings, HealthFinding{
			ID: "unnamed_devices", Category: "topology", Severity: SevInfo,
			Title:  fmt.Sprintf("%d Unnamed/Unidentified Device(s)", unnamedWifi+unnamedWired),
			Detail: fmt.Sprintf(
				"%d wired and %d wireless clients have no hostname or assigned name. "+
					"Use the Clients tab to identify and name them — named devices are much easier to troubleshoot.",
				unnamedWired, unnamedWifi),
		})
	}

	// ── 13. Client signal distribution ───────────────────────────────────────
	var poorCount int
	for _, sta := range r.clients {
		if !sta.Wired && sta.Signal < -75 && sta.Signal != 0 {
			poorCount++
		}
	}
	if poorCount > 0 {
		findings = append(findings, HealthFinding{
			ID: "poor_signal", Category: "wifi", Severity: SevWarning,
			Title:  fmt.Sprintf("%d Client(s) with Poor Signal (<-75 dBm)", poorCount),
			Detail: fmt.Sprintf(
				"%d wireless clients have signal below -75 dBm. "+
					"At this level you'll see high retry rates, low throughput, and intermittent drops. "+
					"Consider adding an AP, adjusting placement, or checking for RF interference.",
				poorCount),
		})
	}

	// ── 14. Camera VLAN isolation ─────────────────────────────────────────────
	// Check if Protect cameras are on a dedicated camera VLAN or sharing with user traffic
	cameraOUI := "1c:6a:1b" // Ubiquiti camera OUI prefix
	var camsOnUserVLAN int
	userVLANIDs := map[string]bool{}
	for _, w := range r.wlans {
		if !w.EnhancedIoT { userVLANIDs[w.NetworkConfID] = true }
	}
	for _, sta := range r.clients {
		if !sta.Wired { continue }
		if strings.HasPrefix(strings.ToLower(sta.MAC), cameraOUI) {
			// If IP is in a non-dedicated subnet, flag it
			if strings.HasPrefix(sta.IP, "192.168.4.") {
				camsOnUserVLAN++
			}
		}
	}
	if camsOnUserVLAN > 0 {
		findings = append(findings, HealthFinding{
			ID: "camera_vlan", Category: "topology", Severity: SevInfo,
			Title:  fmt.Sprintf("%d Camera(s) Sharing the Media VLAN", camsOnUserVLAN),
			Detail: fmt.Sprintf(
				"%d UniFi cameras are on the Media VLAN (192.168.4.x) alongside TVs and user devices. "+
					"Camera traffic is high-bandwidth and continuous. "+
					"A dedicated camera VLAN isolates that traffic and makes bandwidth accounting cleaner. "+
					"Note: UniFi Protect cameras work fine on any VLAN that can reach the UDM Pro's management IP.",
				camsOnUserVLAN),
		})
	}

	// ── 15. VLAN trunk gaps on AP uplinks ────────────────────────────────────
	if vlanResult, err := RunVLANAudit(ctx, c); err == nil {
		for _, f := range vlanResult.Findings {
			if f.Severity == SevOK {
				continue // don't pollute health-check OK list with audit OK
			}
			findings = append(findings, f)
		}
	}

	return &NetworkHealthResult{RunAt: time.Now(), Findings: findings}, nil
}

// ── Switch-port types & builder ───────────────────────────────────────────────

type SwitchPort struct {
	Idx       int     `json:"idx"`
	Name      string  `json:"name"`
	Up        bool    `json:"up"`
	SpeedMbps int     `json:"speed_mbps"`
	PoeMode   string  `json:"poe_mode"`
	PoeWatts  float64 `json:"poe_watts"`
	TxBytes   int64   `json:"tx_bytes"`
	RxBytes   int64   `json:"rx_bytes"`
}

type SwitchStatus struct {
	Name         string       `json:"name"`
	MAC          string       `json:"mac"`
	Model        string       `json:"model"`
	PoeMaxWatts  float64      `json:"poe_max_watts"`
	PoeUsedWatts float64      `json:"poe_used_watts"`
	PoePct       int          `json:"poe_pct"`
	Ports        []SwitchPort `json:"ports"`
}

type SwitchPortsResult struct {
	Switches []SwitchStatus `json:"switches"`
}

func BuildSwitchPortsResult(devices []rawDevice) *SwitchPortsResult {
	var switches []SwitchStatus
	for _, d := range devices {
		if d.Type != "usw" { continue }
		var usedWatts float64
		ports := make([]SwitchPort, 0, len(d.PortTable))
		for _, p := range d.PortTable {
			w := p.poePowerWatts()
			usedWatts += w
			ports = append(ports, SwitchPort{
				Idx:       p.PortIdx,
				Name:      p.Name,
				Up:        p.Up,
				SpeedMbps: p.Speed,
				PoeMode:   p.PoeMode,
				PoeWatts:  w,
				TxBytes:   p.TxBytes,
				RxBytes:   p.RxBytes,
			})
		}
		pct := 0
		if d.TotalMaxPower > 0 {
			pct = int(usedWatts / d.TotalMaxPower * 100)
		}
		switches = append(switches, SwitchStatus{
			Name:         d.Name,
			MAC:          d.MAC,
			Model:        d.Model,
			PoeMaxWatts:  d.TotalMaxPower,
			PoeUsedWatts: usedWatts,
			PoePct:       pct,
			Ports:        ports,
		})
	}
	return &SwitchPortsResult{Switches: switches}
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// handleNetworkHealth runs a full network health check and returns the findings.
func (s *HTTPServer) handleNetworkHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, err := RunNetworkHealthCheck(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: result})
}

// handleHealthFix handles fix actions: POST /api/health/{resource}/{id}/{action}
// e.g. POST /api/health/networks/{id}/disable
//      POST /api/health/wlans/{id}/enable-bss-transition
func (s *HTTPServer) handleHealthFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	// Path: health/{resource}/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/network-health/")
	parts := strings.SplitN(strings.Trim(path, "/"), "/", 3)
	if len(parts) < 3 {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "expected /api/health/{resource}/{id}/{action}"})
		return
	}
	resource, id, action := parts[0], parts[1], parts[2]

	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	switch resource {
	case "networks":
		switch action {
		case "disable":
			// Fetch full network object, set enabled=false
			var resp struct {
				Data []map[string]any `json:"data"`
			}
			if err := c.doJSON(ctx, http.MethodGet, c.apiURL("rest/networkconf/"+id), nil, &resp); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
			if len(resp.Data) == 0 {
				writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "network not found"})
				return
			}
			obj := resp.Data[0]
			obj["enabled"] = false
			var putResp struct{ Meta struct{ RC string `json:"rc"` } `json:"meta"` }
			if err := c.doJSON(ctx, http.MethodPut, c.apiURL("rest/networkconf/"+id), obj, &putResp); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
			s.logger.Info("health fix: disabled network id=%s", id)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"network_id": id, "action": "disable"}})
		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown network action: " + action})
		}

	case "wlans":
		switch action {
		case "enable-bss-transition":
			if err := c.UpdateWLANFields(ctx, id, map[string]any{"bss_transition": true}); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
			s.logger.Info("health fix: enabled bss_transition on wlan id=%s", id)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"wlan_id": id, "action": action}})
		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown wlan action: " + action})
		}

	default:
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown resource: " + resource})
	}
}

func (s *HTTPServer) handleSwitchPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"configured": false}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	devices, err := fetchDevices(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: BuildSwitchPortsResult(devices)})
}
