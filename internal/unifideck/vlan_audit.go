package unifideck

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// auditDevice is a minimal device shape that includes the uplink field not present
// in the shared rawDevice type (used by the health-check engine).
type auditDevice struct {
	ID            string         `json:"_id"`
	Name          string         `json:"name"`
	MAC           string         `json:"mac"`
	Type          string         `json:"type"`  // "uap" | "usw" | "udm" | ...
	State         int            `json:"state"` // 0=disconnected 1=connected
	PortOverrides []portOverride `json:"port_overrides"`
	Uplink        *struct {
		UplinkMAC        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"` // port on the upstream switch
		PortIdx          int    `json:"port_idx"`           // port on the AP/device itself
		Type             string `json:"type"`               // "wire" | "wifi"
	} `json:"uplink"`
}

// VLANAuditResult is the top-level response from RunVLANAudit.
type VLANAuditResult struct {
	RunAt      time.Time         `json:"run_at"`
	Findings   []HealthFinding   `json:"findings"`
	APTopology []APTopologyEntry `json:"ap_topology"`
}

// APTopologyEntry summarises one AP's VLAN requirements vs what's on its uplink port.
type APTopologyEntry struct {
	APName       string          `json:"ap_name"`
	APMAC        string          `json:"ap_mac"`
	UplinkSwitch string          `json:"uplink_switch"`
	UplinkPort   int             `json:"uplink_port"`
	PortMode     string          `json:"port_mode"`
	Status       FindingSeverity `json:"status"`
	VLANChecks   []VLANCheck     `json:"vlan_checks"`
}

// VLANCheck is a per-VLAN result for one AP.
type VLANCheck struct {
	NetworkID string `json:"network_id"`
	VLANName  string `json:"vlan_name"`
	VLANID    int    `json:"vlan_id,omitempty"`
	SSIDs     string `json:"ssids"`
	Trunked   bool   `json:"trunked"`
	IsNative  bool   `json:"is_native"`
	Problem   string `json:"problem,omitempty"`
}

// portKey uniquely identifies a port on a specific switch.
type portKey struct {
	mac  string
	port int
}

// ── Fetch ─────────────────────────────────────────────────────────────────────

func fetchAuditDevices(ctx context.Context, c *UnifiClient) ([]auditDevice, error) {
	var resp struct {
		Data []auditDevice `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL("stat/device"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// ── Port-mode helpers ─────────────────────────────────────────────────────────

// isTrunkAllPort returns true when a portOverride is configured to pass all VLANs.
// UniFi has two equivalent representations of "trunk everything":
//
//	forward:"all"
//	forward:"customize" + tagged_vlan_mgmt:"auto" + excluded_networkconf_ids:[]
func isTrunkAllPort(po *portOverride) bool {
	if po == nil {
		return true // no override = switch default = trunk-all
	}
	if po.Forward == "all" {
		return true
	}
	if po.Forward == "customize" && po.TaggedVLANMgmt == "auto" && len(po.ExcludedNetworkIDs) == 0 {
		return true
	}
	return false
}

// portModeLabel returns a human-readable description of a port's effective mode.
func portModeLabel(po *portOverride) string {
	if po == nil {
		return "default (no override — assuming trunk)"
	}
	switch po.Forward {
	case "all":
		return "trunk-all"
	case "customize":
		switch {
		case po.TaggedVLANMgmt == "auto" && len(po.ExcludedNetworkIDs) == 0:
			return "trunk-all (auto)"
		case po.TaggedVLANMgmt == "auto" && len(po.ExcludedNetworkIDs) > 0:
			return fmt.Sprintf("allow-all except %d VLAN(s)", len(po.ExcludedNetworkIDs))
		case po.TaggedVLANMgmt == "custom" && len(po.TaggedNetworkIDs) > 0:
			return fmt.Sprintf("allow-list (%d tagged VLANs)", len(po.TaggedNetworkIDs))
		case po.TaggedVLANMgmt == "custom" && len(po.ExcludedNetworkIDs) > 0:
			return fmt.Sprintf("allow-all except %d VLAN(s)", len(po.ExcludedNetworkIDs))
		default:
			return "native-only (access)"
		}
	default:
		return po.Forward
	}
}

// vlanReachable returns true if the given networkID is reachable through portCfg.
//
// UniFi switch port VLAN semantics:
//
//	forward:"all"
//	  → trunk-all, everything passes.
//
//	forward:"customize" + tagged_vlan_mgmt:"auto" + excluded_networkconf_ids:[]
//	  → trunk-all (auto-managed, nothing excluded).
//
//	forward:"customize" + tagged_vlan_mgmt:"auto"  + excluded_networkconf_ids:[x,y]
//	forward:"customize" + tagged_vlan_mgmt:"custom" + excluded_networkconf_ids:[x,y] (no allow-list)
//	  → BLOCKLIST mode: all VLANs pass except those in the exclusion list.
//	    (This is what the UI shows as "allow all except …".)
//
//	forward:"customize" + tagged_vlan_mgmt:"custom" + tagged_networkconf_ids:[x,y]
//	  → ALLOWLIST mode: only the explicitly listed tagged VLANs pass.
//
//	forward:"native" + tagged_vlan_mgmt:"block_all"
//	  → Access port: only the native VLAN passes, all tagged blocked.
func vlanReachable(po *portOverride, netID string) (trunked bool, isNative bool) {
	if isTrunkAllPort(po) {
		return true, po != nil && po.NativeNetworkID == netID
	}
	if po == nil {
		return true, false
	}
	if po.NativeNetworkID == netID {
		return true, true
	}

	// Blocked by explicit exclusion list — applies in every mode.
	for _, eid := range po.ExcludedNetworkIDs {
		if eid == netID {
			return false, false
		}
	}

	// Allowlist mode: tagged_networkconf_ids is populated — only those pass.
	if len(po.TaggedNetworkIDs) > 0 {
		for _, tid := range po.TaggedNetworkIDs {
			if tid == netID {
				return true, false
			}
		}
		return false, false
	}

	// Blocklist mode: excluded list set but no explicit allow-list.
	// Everything not in the exclusion list is allowed.
	if len(po.ExcludedNetworkIDs) > 0 {
		return true, false
	}

	// "auto" with nothing excluded = trunk-all (already handled by isTrunkAllPort,
	// but guard here in case of edge cases).
	if po.TaggedVLANMgmt == "auto" {
		return true, false
	}

	// "custom" with both lists empty = access port (native only, no tagged).
	return false, false
}

// ── Audit runner ──────────────────────────────────────────────────────────────

func RunVLANAudit(ctx context.Context, c *UnifiClient) (*VLANAuditResult, error) {
	type fetchResult struct {
		devices  []auditDevice
		wlans    []WLAN
		networks []rawNetwork
		devErr   error
		wlanErr  error
		netErr   error
	}
	ch := make(chan fetchResult, 1)
	go func() {
		var r fetchResult
		r.devices, r.devErr = fetchAuditDevices(ctx, c)
		r.wlans, r.wlanErr = c.ListWLANs(ctx)
		r.networks, r.netErr = fetchNetworks(ctx, c)
		ch <- r
	}()
	fr := <-ch

	if fr.devErr != nil {
		return nil, fmt.Errorf("fetch devices: %w", fr.devErr)
	}
	if fr.wlanErr != nil {
		return nil, fmt.Errorf("fetch wlans: %w", fr.wlanErr)
	}
	if fr.netErr != nil {
		return nil, fmt.Errorf("fetch networks: %w", fr.netErr)
	}

	// ── Build lookup maps ─────────────────────────────────────────────────────

	netByID := map[string]rawNetwork{}
	for _, n := range fr.networks {
		netByID[n.ID] = n
	}

	// All switch/gateway devices indexed by lowercase MAC.
	switchByMAC := map[string]auditDevice{}
	for _, d := range fr.devices {
		if d.Type == "usw" || d.Type == "udm" || d.Type == "usg" || d.Type == "uxg" {
			switchByMAC[strings.ToLower(d.MAC)] = d
		}
	}

	// portToDevice: which device is connected on the far end of each switch port?
	portToDevice := map[portKey]auditDevice{}
	for _, d := range fr.devices {
		if d.Uplink == nil || d.Uplink.Type != "wire" || d.Uplink.UplinkMAC == "" {
			continue
		}
		k := portKey{mac: strings.ToLower(d.Uplink.UplinkMAC), port: d.Uplink.UplinkRemotePort}
		portToDevice[k] = d
	}

	// Management network ID: the native VLAN that should be on all trunk ports.
	// Determined by consensus — it's whichever network ID is used as native on
	// the most correctly-configured AP uplink ports.
	mgmtNetID := detectManagementNetID(switchByMAC, portToDevice)

	// ssidsByNet: networkConfID → []SSID names (enabled WLANs only).
	ssidsByNet := map[string][]string{}
	for _, w := range fr.wlans {
		if w.Enabled && w.NetworkConfID != "" {
			ssidsByNet[w.NetworkConfID] = append(ssidsByNet[w.NetworkConfID], w.Name)
		}
	}

	var findings []HealthFinding
	var topology []APTopologyEntry

	// ── Check 1: AP uplink VLAN trunking ─────────────────────────────────────
	// For each wired AP, verify every enabled SSID's VLAN is reachable on the
	// upstream switch port.

	// Track per-VLAN reachability across all APs (used for roaming check later).
	// netID → {working APs, broken APs}
	type apSplit struct {
		working []string
		broken  []string
	}
	vlanAPStatus := map[string]*apSplit{}
	for netID := range ssidsByNet {
		vlanAPStatus[netID] = &apSplit{}
	}

	for _, d := range fr.devices {
		if d.Type != "uap" || d.State == 0 {
			continue
		}

		entry := APTopologyEntry{APName: d.Name, APMAC: d.MAC}

		if d.Uplink == nil || d.Uplink.Type != "wire" || d.Uplink.UplinkMAC == "" {
			entry.UplinkSwitch = "wireless mesh uplink"
			entry.PortMode = "mesh"
			entry.Status = SevInfo
			topology = append(topology, entry)
			continue
		}

		uplinkMAC := strings.ToLower(d.Uplink.UplinkMAC)
		uplinkPort := d.Uplink.UplinkRemotePort
		entry.UplinkPort = uplinkPort

		sw, found := switchByMAC[uplinkMAC]
		if !found {
			entry.UplinkSwitch = fmt.Sprintf("unmanaged device (%s)", uplinkMAC)
			entry.PortMode = "unmanaged"
			entry.Status = SevInfo
			topology = append(topology, entry)
			continue
		}
		entry.UplinkSwitch = sw.Name

		var portCfg *portOverride
		for i := range sw.PortOverrides {
			if sw.PortOverrides[i].PortIdx == uplinkPort {
				portCfg = &sw.PortOverrides[i]
				break
			}
		}
		entry.PortMode = portModeLabel(portCfg)

		var missingLabels []string
		var checks []VLANCheck

		for netID, ssids := range ssidsByNet {
			net, hasNet := netByID[netID]
			netName := netID
			vlanID := 0
			if hasNet {
				netName = net.Name
				vlanID = net.Vlan
			}

			trunked, isNative := vlanReachable(portCfg, netID)

			label := netName
			if vlanID > 0 {
				label = fmt.Sprintf("%s (VLAN %d)", netName, vlanID)
			}

			check := VLANCheck{
				NetworkID: netID,
				VLANName:  netName,
				VLANID:    vlanID,
				SSIDs:     strings.Join(ssids, ", "),
				Trunked:   trunked,
				IsNative:  isNative,
			}
			if !trunked {
				check.Problem = fmt.Sprintf(
					"VLAN %q not reachable on %s port %d (%s) — "+
						"clients on SSID(s) %q will get DHCP timeouts and no connectivity.",
					label, sw.Name, uplinkPort, entry.PortMode, check.SSIDs)
				missingLabels = append(missingLabels, label)
				vlanAPStatus[netID].broken = append(vlanAPStatus[netID].broken, d.Name)
			} else {
				vlanAPStatus[netID].working = append(vlanAPStatus[netID].working, d.Name)
			}
			checks = append(checks, check)
		}

		sort.Slice(checks, func(i, j int) bool {
			if checks[i].Trunked != checks[j].Trunked {
				return checks[i].Trunked
			}
			return checks[i].VLANName < checks[j].VLANName
		})
		entry.VLANChecks = checks

		if len(missingLabels) > 0 {
			entry.Status = SevCritical
			sort.Strings(missingLabels)
			findings = append(findings, HealthFinding{
				ID:       "vlan_trunk_gap_" + d.ID,
				Category: "topology",
				Severity: SevCritical,
				Title:    fmt.Sprintf("VLAN Trunk Gap: %s missing %d VLAN(s) on uplink port", d.Name, len(missingLabels)),
				Detail: fmt.Sprintf(
					"%s is wired to %s port %d (%s). "+
						"These VLANs are needed for active SSIDs but are NOT trunked on that port: %s. "+
						"Clients connecting to those SSIDs on this AP will get no DHCP and no internet. "+
						"Fix: Devices → %s → Ports → Port %d → set native VLAN to Zone00 and Tagged VLAN Management to Allow All.",
					d.Name, sw.Name, uplinkPort, entry.PortMode,
					strings.Join(missingLabels, ", "),
					sw.Name, uplinkPort),
			})
		} else {
			entry.Status = SevOK
		}

		topology = append(topology, entry)
	}

	// ── Check 2: SSID roaming dead zones ─────────────────────────────────────
	// If a VLAN works on some APs but not others, any client using that SSID
	// will lose connectivity when they roam to one of the broken APs.

	type roamingIssue struct {
		netID   string
		netName string
		vlanID  int
		ssids   []string
		working []string
		broken  []string
	}
	var roamingIssues []roamingIssue

	for netID, split := range vlanAPStatus {
		if len(split.working) > 0 && len(split.broken) > 0 {
			net := netByID[netID]
			ri := roamingIssue{
				netID:   netID,
				netName: net.Name,
				vlanID:  net.Vlan,
				ssids:   ssidsByNet[netID],
				working: split.working,
				broken:  split.broken,
			}
			sort.Strings(ri.working)
			sort.Strings(ri.broken)
			roamingIssues = append(roamingIssues, ri)
		}
	}
	sort.Slice(roamingIssues, func(i, j int) bool {
		return roamingIssues[i].netName < roamingIssues[j].netName
	})

	for _, ri := range roamingIssues {
		vlanLabel := ri.netName
		if ri.vlanID > 0 {
			vlanLabel = fmt.Sprintf("%s (VLAN %d)", ri.netName, ri.vlanID)
		}
		findings = append(findings, HealthFinding{
			ID:       "roaming_dead_zone_" + ri.netID,
			Category: "wifi",
			Severity: SevCritical,
			Title: fmt.Sprintf(
				"Roaming Dead Zone: %q — works on %d AP(s), fails on %d AP(s)",
				strings.Join(ri.ssids, "/"), len(ri.working), len(ri.broken)),
			Detail: fmt.Sprintf(
				"SSID(s) %q use VLAN %s. "+
					"That VLAN IS trunked correctly on: %s. "+
					"But it is NOT trunked on: %s. "+
					"A client connected on one of the working APs will lose internet the moment "+
					"they roam to a broken AP — the phone/laptop stays \"connected\" to WiFi "+
					"but gets no traffic. "+
					"Fix: correct the uplink port trunk config on the broken AP(s) listed above.",
				strings.Join(ri.ssids, ", "),
				vlanLabel,
				strings.Join(ri.working, ", "),
				strings.Join(ri.broken, ", ")),
		})
	}

	// ── Check 3: Switch-to-switch trunk port configuration ────────────────────
	// Every port connecting a managed switch to another managed switch should have:
	//   • Native VLAN = management network (Zone00)
	//   • Tagged VLAN management = Allow All (trunk-all)
	//
	// A wrong native VLAN means the downstream switch gets a management IP on the
	// wrong subnet and may be unreachable to UniFi.

	swTrunkFindings, swTrunkOK := checkSwitchTrunkPorts(switchByMAC, portToDevice, netByID, mgmtNetID)
	findings = append(findings, swTrunkFindings...)

	// If no critical issues at all, add a global OK.
	if len(findings) == 0 {
		wiredAPs := countWiredEntries(topology)
		findings = append(findings, HealthFinding{
			ID:       "vlan_audit_ok",
			Category: "topology",
			Severity: SevOK,
			Title:    "VLAN Configuration OK",
			Detail: fmt.Sprintf(
				"All %d wired AP uplinks are trunking the correct VLANs, "+
					"no roaming dead zones detected, and all switch trunk ports are properly configured.",
				wiredAPs),
		})
	} else if swTrunkOK > 0 {
		// Add an informational OK for the switch trunk check when APs had issues but switches were fine.
		findings = append(findings, HealthFinding{
			ID:       "switch_trunk_ports_ok",
			Category: "topology",
			Severity: SevOK,
			Title:    fmt.Sprintf("Switch Trunk Ports OK (%d port(s) checked)", swTrunkOK),
			Detail:   "All switch-to-switch uplink ports have Zone00 as native VLAN and are in trunk-all mode.",
		})
	}

	// Sort topology: problems first, then alphabetically.
	sort.Slice(topology, func(i, j int) bool {
		si, sj := severityRank(topology[i].Status), severityRank(topology[j].Status)
		if si != sj {
			return si < sj
		}
		return topology[i].APName < topology[j].APName
	})

	return &VLANAuditResult{
		RunAt:      time.Now(),
		Findings:   findings,
		APTopology: topology,
	}, nil
}

// ── Check 3 helper: switch trunk ports ───────────────────────────────────────

// checkSwitchTrunkPorts validates every switch-to-switch port across all managed
// switches. Returns (findings, okCount).
func checkSwitchTrunkPorts(
	switchByMAC map[string]auditDevice,
	portToDevice map[portKey]auditDevice,
	netByID map[string]rawNetwork,
	mgmtNetID string,
) ([]HealthFinding, int) {
	var findings []HealthFinding
	okCount := 0

	// Build a sorted list of switch MACs for stable output.
	swMACs := make([]string, 0, len(switchByMAC))
	for mac := range switchByMAC {
		swMACs = append(swMACs, mac)
	}
	sort.Strings(swMACs)

	mgmtName := "Zone00 (management)"
	if n, ok := netByID[mgmtNetID]; ok {
		mgmtName = n.Name + " (management)"
	}

	for _, swMAC := range swMACs {
		sw := switchByMAC[swMAC]

		// Collect the port overrides that exist, keyed by port index.
		overrideByPort := map[int]*portOverride{}
		for i := range sw.PortOverrides {
			overrideByPort[sw.PortOverrides[i].PortIdx] = &sw.PortOverrides[i]
		}

		// Check every port that connects to a downstream managed switch.
		for k, downstream := range portToDevice {
			if k.mac != swMAC {
				continue
			}
			if downstream.Type != "usw" {
				continue // only switch-to-switch ports matter here
			}
			// UDM/USG/UXG devices manage their switch ports internally and don't
			// expose port_overrides — skip them to avoid false positives.
			if sw.Type != "usw" {
				continue
			}

			po := overrideByPort[k.port] // may be nil = default profile

			portName := fmt.Sprintf("port %d", k.port)
			if po != nil && po.Name != "" {
				portName = fmt.Sprintf("port %d (%s)", k.port, po.Name)
			}

			// The one hard requirement for a switch-to-switch trunk port is that
			// the native (untagged) VLAN is the management network, so the
			// downstream switch can get a management IP and be adopted by UniFi.
			// We do NOT require trunk-all — intentionally restricted trunks
			// (e.g. a cameras-only switch that blocks Work/IoT) are valid.
			nativeID := ""
			if po != nil {
				nativeID = po.NativeNetworkID
			}

			if mgmtNetID != "" && nativeID != mgmtNetID {
				currentName := "none / unset"
				if nativeID != "" {
					if n, ok := netByID[nativeID]; ok {
						currentName = n.Name
						if n.Vlan > 0 {
							currentName = fmt.Sprintf("%s (VLAN %d)", n.Name, n.Vlan)
						}
					} else {
						currentName = nativeID
					}
				}
				findings = append(findings, HealthFinding{
					ID:       fmt.Sprintf("sw_trunk_%s_%d", sw.ID, k.port),
					Category: "topology",
					Severity: SevWarning,
					Title: fmt.Sprintf(
						"Switch Trunk Native VLAN Wrong: %s %s → %s",
						sw.Name, portName, downstream.Name),
					Detail: fmt.Sprintf(
						"%s %s connects to managed switch %s. "+
							"The native VLAN is %q but it should be %s. "+
							"With the wrong native VLAN, %s gets a management IP on the wrong subnet "+
							"and may appear offline or be unreachable in UniFi. "+
							"Fix: Devices → %s → Ports → Port %d → set Native VLAN to %s.",
						sw.Name, portName, downstream.Name,
						currentName, mgmtName,
						downstream.Name,
						sw.Name, k.port, mgmtName),
				})
			} else {
				okCount++
			}
		}
	}

	return findings, okCount
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// detectManagementNetID finds the network ID used as native VLAN on the most
// correctly-configured AP uplink ports — this is the management (Zone00) network.
// Falls back to the first network with vlan=0 and purpose="corporate".
func detectManagementNetID(
	switchByMAC map[string]auditDevice,
	portToDevice map[portKey]auditDevice,
) string {
	counts := map[string]int{}
	for swMAC, sw := range switchByMAC {
		for _, po := range sw.PortOverrides {
			k := portKey{mac: swMAC, port: po.PortIdx}
			dev, ok := portToDevice[k]
			if !ok || dev.Type != "uap" {
				continue
			}
			if isTrunkAllPort(&po) && po.NativeNetworkID != "" {
				counts[po.NativeNetworkID]++
			}
		}
	}
	best, bestCount := "", 0
	for id, n := range counts {
		if n > bestCount {
			best, bestCount = id, n
		}
	}
	return best
}

// severityRank maps FindingSeverity to a sort key (lower = worse = shown first).
func severityRank(s FindingSeverity) int {
	switch s {
	case SevCritical:
		return 0
	case SevWarning:
		return 1
	case SevInfo:
		return 2
	case SevOK:
		return 3
	default:
		return 4
	}
}

func countWiredEntries(entries []APTopologyEntry) int {
	n := 0
	for _, e := range entries {
		if e.PortMode != "mesh" && e.PortMode != "unmanaged" {
			n++
		}
	}
	return n
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

func (s *HTTPServer) handleVLANAudit(w http.ResponseWriter, r *http.Request) {
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
	result, err := RunVLANAudit(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: result})
}
