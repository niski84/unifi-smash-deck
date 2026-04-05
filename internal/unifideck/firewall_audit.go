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

// FirewallFinding is a single issue detected by the audit engine.
// Severity reuses the FindingSeverity type from network_health.go.
type FirewallFinding struct {
	ID             string           `json:"id"`
	Severity       FindingSeverity  `json:"severity"` // "critical"|"warning"|"info"
	Category       string           `json:"category"` // "zones"|"default-policy"|"rules"|"coverage"
	Title          string           `json:"title"`
	Detail         string           `json:"detail"`
	Recommendation string           `json:"recommendation"`
	RuleNames      []string         `json:"rule_names,omitempty"`
}

// AuditPolicy is a display-ready row for the policy table.
type AuditPolicy struct {
	ID          string `json:"id"`
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Action      string `json:"action"` // "ALLOW"|"BLOCK"
	Enabled     bool   `json:"enabled"`
	Predefined  bool   `json:"predefined"`
	SrcZone     string `json:"src_zone"`
	DstZone     string `json:"dst_zone"`
	SrcNetworks string `json:"src_networks"` // comma-separated or "ANY"
	DstNetworks string `json:"dst_networks"`
	SrcTarget   string `json:"src_target"` // "ANY"|"NETWORK"|"IP"|"CLIENT"
	DstTarget   string `json:"dst_target"`
	OriginType  string `json:"origin_type"`
}

// AuditNetEntry is one network's zone-assignment status for the overview table.
type AuditNetEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	VLAN     string `json:"vlan"`
	Subnet   string `json:"subnet"`
	Purpose  string `json:"purpose"`
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name"`
}

// FirewallAuditReport is the full result returned by GET /api/firewall-audit.
type FirewallAuditReport struct {
	RunAt        time.Time         `json:"run_at"`
	Configured   bool              `json:"configured"`
	PolicyCount  int               `json:"policy_count"`
	UserPolicies int               `json:"user_policies"`
	NetworkCount int               `json:"network_count"`
	Score        int               `json:"score"` // 0–100
	Critical     int               `json:"critical"`
	Warning      int               `json:"warning"`
	Info         int               `json:"info"`
	Findings     []FirewallFinding `json:"findings"`
	Policies     []AuditPolicy     `json:"policies"`
	Networks     []AuditNetEntry   `json:"networks"`
}

// ── Main entry point ──────────────────────────────────────────────────────────

// RunFirewallAudit fetches current UniFi ZBF configuration and returns a
// structured audit report with findings and a 0–100 score.
func RunFirewallAudit(ctx context.Context, c *UnifiClient) (*FirewallAuditReport, error) {
	report := &FirewallAuditReport{RunAt: time.Now().UTC(), Configured: c.IsConfigured()}
	if !c.IsConfigured() {
		return report, nil
	}

	policies, err := c.ListFirewallPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall audit policies: %w", err)
	}
	networks, err := c.ListNetworksRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall audit networks: %w", err)
	}

	report.PolicyCount = len(policies)
	report.NetworkCount = len(networks)

	// ── Build lookup maps ──────────────────────────────────────────────────────

	netName := map[string]string{}
	netVLAN := map[string]string{}
	netSubnet := map[string]string{}
	netPurpose := map[string]string{}
	for _, n := range networks {
		id := fwStr(n, "_id")
		if id == "" {
			continue
		}
		netName[id] = fwStr(n, "name")
		netPurpose[id] = fwStr(n, "purpose")
		netSubnet[id] = fwStr(n, "ip_subnet")
		if v, ok := n["vlan"]; ok && v != nil {
			netVLAN[id] = fmt.Sprintf("%v", v)
		} else {
			netVLAN[id] = "untagged"
		}
	}

	// Build zone→networks from TWO sources:
	// 1. firewall_zone_id on each network config (authoritative)
	// 2. zone_id on policy source/destination (adds policy-only zone references)
	zoneNets := map[string]map[string]bool{}
	netZone := map[string]string{}

	// Source 1: authoritative firewall_zone_id on network objects.
	for _, n := range networks {
		nid := fwStr(n, "_id")
		zid := fwStr(n, "firewall_zone_id")
		if nid == "" || zid == "" {
			continue
		}
		if zoneNets[zid] == nil {
			zoneNets[zid] = map[string]bool{}
		}
		zoneNets[zid][nid] = true
		netZone[nid] = zid
	}

	// Source 2: zone_id fields in policies (fills in any zones not covered above).
	for _, p := range policies {
		for _, side := range []string{"source", "destination"} {
			s, ok := p[side].(map[string]any)
			if !ok {
				continue
			}
			zid := fwStr(s, "zone_id")
			if zid == "" {
				continue
			}
			if zoneNets[zid] == nil {
				zoneNets[zid] = map[string]bool{}
			}
			for _, nid := range fwNetIDs(s) {
				zoneNets[zid][nid] = true
				if netZone[nid] == "" {
					netZone[nid] = zid
				}
			}
		}
	}

	// Primary internal zone = zone with most network members.
	var internalZoneID string
	maxNets := 0
	for zid, nets := range zoneNets {
		if len(nets) > maxNets {
			maxNets = len(nets)
			internalZoneID = zid
		}
	}

	// Zone name resolver.
	resolveZone := func(zid string) string {
		if zid == "" {
			return "?"
		}
		if zid == internalZoneID {
			return "Internal (LAN)"
		}
		nets := zoneNets[zid]
		if len(nets) == 0 {
			return "External (WAN)"
		}
		var names []string
		for nid := range nets {
			names = append(names, netName[nid])
		}
		sort.Strings(names)
		return "Zone[" + strings.Join(names, ",") + "]"
	}

	// ── Build AuditPolicy list ─────────────────────────────────────────────────

	for _, raw := range policies {
		ap := fwBuildPolicy(raw, resolveZone, netName)
		report.Policies = append(report.Policies, ap)
		if !ap.Predefined {
			report.UserPolicies++
		}
	}
	sort.Slice(report.Policies, func(i, j int) bool {
		if report.Policies[i].Index != report.Policies[j].Index {
			return report.Policies[i].Index < report.Policies[j].Index
		}
		return report.Policies[i].Name < report.Policies[j].Name
	})

	// ── Build network overview ─────────────────────────────────────────────────

	for _, n := range networks {
		nid := fwStr(n, "_id")
		zid := netZone[nid]
		report.Networks = append(report.Networks, AuditNetEntry{
			ID:       nid,
			Name:     netName[nid],
			VLAN:     netVLAN[nid],
			Subnet:   netSubnet[nid],
			Purpose:  netPurpose[nid],
			ZoneID:   zid,
			ZoneName: resolveZone(zid),
		})
	}

	// ── Run audit checks ───────────────────────────────────────────────────────

	var findings []FirewallFinding
	findings = append(findings, fwCheckUnzonedNetworks(networks, netZone, netName, netPurpose)...)
	findings = append(findings, fwCheckDefaultAllowCatchAll(policies, internalZoneID)...)
	findings = append(findings, fwCheckRedundantReturnRules(policies)...)
	findings = append(findings, fwCheckDisabledSecurityRules(policies)...)
	findings = append(findings, fwCheckDuplicateRules(policies)...)
	findings = append(findings, fwCheckSameIndexConflicts(policies)...)
	findings = append(findings, fwCheckAllowBeforeBlock(policies)...)
	findings = append(findings, fwCheckFragileIPRules(policies)...)
	findings = append(findings, fwCheckLegacyObjectRules(policies)...)
	findings = append(findings, fwCheckUncoveredNetworks(policies, networks, netZone, internalZoneID, netName, netPurpose)...)

	report.Findings = findings
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			report.Critical++
		case SevWarning:
			report.Warning++
		case SevInfo:
			report.Info++
		}
	}

	score := 100 - report.Critical*20 - report.Warning*8 - report.Info*2
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report, nil
}

// handleFirewallAudit handles GET /api/firewall-audit.
func (s *HTTPServer) handleFirewallAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	c := s.unifiClient()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := RunFirewallAudit(ctx, c)
	if err != nil {
		s.logger.Warn("firewall audit err=%v", err)
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: report})
}

// ── AuditPolicy builder ───────────────────────────────────────────────────────

func fwBuildPolicy(raw map[string]any, resolveZone func(string) string, netName map[string]string) AuditPolicy {
	ap := AuditPolicy{
		ID:         fwStr(raw, "_id"),
		Name:       fwStr(raw, "name"),
		Action:     fwStr(raw, "action"),
		Predefined: fwBool(raw, "predefined"),
		OriginType: fwStr(raw, "origin_type"),
	}
	if ap.Name == "" {
		ap.Name = fwStr(raw, "description")
	}
	if idx, ok := raw["index"].(float64); ok {
		ap.Index = int(idx)
	}
	if en, ok := raw["enabled"].(bool); ok {
		ap.Enabled = en
	}

	for _, key := range []string{"source", "destination"} {
		s, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		zid := fwStr(s, "zone_id")
		target := fwStr(s, "matching_target")
		netDisplay := fwNetDisplay(s, netName)
		if key == "source" {
			ap.SrcZone = resolveZone(zid)
			ap.SrcTarget = target
			ap.SrcNetworks = netDisplay
		} else {
			ap.DstZone = resolveZone(zid)
			ap.DstTarget = target
			ap.DstNetworks = netDisplay
		}
	}
	return ap
}

func fwNetDisplay(side map[string]any, netName map[string]string) string {
	target := fwStr(side, "matching_target")
	if target == "ANY" || target == "" {
		return "ANY"
	}
	ids := fwNetIDs(side)
	if len(ids) == 0 {
		return target
	}
	var names []string
	for _, id := range ids {
		if n := netName[id]; n != "" {
			names = append(names, n)
		} else {
			l := len(id)
			if l > 12 {
				l = 12
			}
			names = append(names, id[:l])
		}
	}
	return strings.Join(names, ", ")
}

// ── Check functions ───────────────────────────────────────────────────────────

func fwCheckUnzonedNetworks(networks []map[string]any, netZone, netName, netPurpose map[string]string) []FirewallFinding {
	var out []FirewallFinding
	for _, n := range networks {
		nid := fwStr(n, "_id")
		purpose := netPurpose[nid]
		if purpose == "wan" || purpose == "remote-user-vpn" {
			continue
		}
		if v, ok := n["enabled"].(bool); ok && !v {
			continue
		}
		if netZone[nid] != "" {
			continue
		}
		out = append(out, FirewallFinding{
			ID:             "unzoned-" + nid,
			Severity:       SevCritical,
			Category:       "zones",
			Title:          fmt.Sprintf("Network %q is not assigned to any firewall zone", netName[nid]),
			Detail:         "This VLAN has no Zone-Based Firewall zone assignment. ZBF policies cannot govern its inter-VLAN traffic — all access to and from this network is completely uncontrolled.",
			Recommendation: "Open Settings → Security → Zone-Based Firewall, edit the Internal zone, and add this network. Then add explicit BLOCK rules to define its isolation level.",
		})
	}
	return out
}

func fwCheckDefaultAllowCatchAll(policies []map[string]any, internalZoneID string) []FirewallFinding {
	const maxIdx = 2147483647
	for _, p := range policies {
		idx, _ := p["index"].(float64)
		if int(idx) != maxIdx || fwStr(p, "action") != "ALLOW" {
			continue
		}
		src, _ := p["source"].(map[string]any)
		dst, _ := p["destination"].(map[string]any)
		if fwStr(src, "zone_id") == internalZoneID &&
			fwStr(dst, "zone_id") == internalZoneID &&
			fwStr(src, "matching_target") == "ANY" &&
			fwStr(dst, "matching_target") == "ANY" {
			return []FirewallFinding{{
				ID:             "default-allow-internal",
				Severity:       SevWarning,
				Category:       "default-policy",
				Title:          "Default allow-all policy between internal VLANs (block-list model)",
				Detail:         "A catch-all ALLOW rule at the lowest priority means any VLAN can freely reach any other unless you've added an explicit BLOCK above it. One missing block rule and traffic flows unrestricted.",
				Recommendation: "Switch to default-deny: first add explicit ALLOW rules for every legitimate cross-VLAN flow (trusted→IoT, management→all, etc.), then replace this catch-all with a BLOCK ALL. This inverts to an allow-list posture where only approved traffic passes.",
			}}
		}
	}
	return nil
}

func fwCheckRedundantReturnRules(policies []map[string]any) []FirewallFinding {
	var out []FirewallFinding
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		name := fwRuleName(p)
		if fwStr(p, "action") == "ALLOW" && strings.Contains(strings.ToLower(name), "return") {
			out = append(out, FirewallFinding{
				ID:             "redundant-return-" + fwStr(p, "_id"),
				Severity:       SevWarning,
				Category:       "rules",
				Title:          fmt.Sprintf("Rule %q is a redundant return-traffic allow", name),
				Detail:         "UniFi's stateful firewall automatically permits return packets for any established connection. An explicit 'return traffic' ALLOW is unnecessary — and worse, it can allow traffic to initiate in the opposite direction, creating a security hole.",
				Recommendation: "Delete this rule. Return traffic for permitted connections is handled automatically by the stateful engine.",
				RuleNames:      []string{name},
			})
		}
	}
	return out
}

func fwCheckDisabledSecurityRules(policies []map[string]any) []FirewallFinding {
	var out []FirewallFinding
	for _, p := range policies {
		if fwBool(p, "predefined") || fwBool(p, "enabled") {
			continue
		}
		name := fwRuleName(p)
		action := fwStr(p, "action")
		lower := strings.ToLower(name)
		isBlock := action == "BLOCK" ||
			strings.Contains(lower, "block") ||
			strings.Contains(lower, "drop") ||
			strings.Contains(lower, "deny")
		if isBlock {
			out = append(out, FirewallFinding{
				ID:             "disabled-block-" + fwStr(p, "_id"),
				Severity:       SevWarning,
				Category:       "rules",
				Title:          fmt.Sprintf("Security rule %q is disabled", name),
				Detail:         "This rule looks like a security block or deny, but it is currently disabled. Traffic it was designed to stop is flowing unrestricted.",
				Recommendation: "Re-enable this rule if it should be active. If it is intentionally disabled and no longer needed, delete it to avoid ambiguity.",
				RuleNames:      []string{name},
			})
		}
	}
	return out
}

func fwCheckDuplicateRules(policies []map[string]any) []FirewallFinding {
	type key struct{ action, srcZone, srcNets, dstZone, dstNets string }
	seen := map[key][]string{}
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		src, _ := p["source"].(map[string]any)
		dst, _ := p["destination"].(map[string]any)
		// Skip IP/CLIENT targeted rules — their deduplication key must include
		// the actual IP targets, which we don't store here. Two rules that both
		// target "IP" in the same zone are almost certainly targeting different
		// IPs, not true duplicates.
		srcT := fwStr(src, "matching_target")
		dstT := fwStr(dst, "matching_target")
		if srcT == "IP" || srcT == "CLIENT" || dstT == "IP" || dstT == "CLIENT" {
			continue
		}
		sn := fwNetIDs(src)
		dn := fwNetIDs(dst)
		sort.Strings(sn)
		sort.Strings(dn)
		k := key{
			fwStr(p, "action"),
			fwStr(src, "zone_id"),
			strings.Join(sn, ","),
			fwStr(dst, "zone_id"),
			strings.Join(dn, ","),
		}
		seen[k] = append(seen[k], fwRuleName(p))
	}
	var out []FirewallFinding
	for _, names := range seen {
		if len(names) < 2 {
			continue
		}
		out = append(out, FirewallFinding{
			ID:             "duplicate-" + strings.Join(names, "_"),
			Severity:       SevWarning,
			Category:       "rules",
			Title:          fmt.Sprintf("Duplicate rules: %s", strings.Join(names, " / ")),
			Detail:         fmt.Sprintf("%d rules share identical source, destination, and action. Only the one with the lowest index takes effect; the others are dead weight that makes audits harder.", len(names)),
			Recommendation: "Delete the redundant rule(s), keeping only the one at the intended index.",
			RuleNames:      names,
		})
	}
	return out
}

func fwCheckSameIndexConflicts(policies []map[string]any) []FirewallFinding {
	// Index only matters within the same src→dst zone pair. Two rules in
	// different zone pairs with the same index number do not conflict.
	type zonePairIdx struct {
		srcZone, dstZone string
		index            int
	}
	groups := map[zonePairIdx][]string{}
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		src, _ := p["source"].(map[string]any)
		dst, _ := p["destination"].(map[string]any)
		idx, _ := p["index"].(float64)
		k := zonePairIdx{fwStr(src, "zone_id"), fwStr(dst, "zone_id"), int(idx)}
		groups[k] = append(groups[k], fwRuleName(p))
	}
	var out []FirewallFinding
	for k, names := range groups {
		if len(names) < 2 {
			continue
		}
		out = append(out, FirewallFinding{
			ID:             fmt.Sprintf("same-index-%d", k.index),
			Severity:       SevWarning,
			Category:       "rules",
			Title:          fmt.Sprintf("%d rules share index %d within the same zone pair — evaluation order is ambiguous", len(names), k.index),
			Detail:         fmt.Sprintf("Rules %q all have the same priority index within the same source→destination zone pair. Which fires first is non-deterministic.", strings.Join(names, ", ")),
			Recommendation: "Use PUT /proxy/network/v2/api/site/default/firewall-policies/batch-reorder to set an explicit ordered list of policy IDs for this zone pair.",
			RuleNames:      names,
		})
	}
	return out
}

func fwCheckAllowBeforeBlock(policies []map[string]any) []FirewallFinding {
	type pairKey struct{ srcZone, srcNets, dstZone, dstNets string }
	type rec struct {
		action string
		index  int
		name   string
	}
	pairs := map[pairKey][]rec{}
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		src, _ := p["source"].(map[string]any)
		dst, _ := p["destination"].(map[string]any)
		sn := fwNetIDs(src)
		dn := fwNetIDs(dst)
		sort.Strings(sn)
		sort.Strings(dn)
		k := pairKey{fwStr(src, "zone_id"), strings.Join(sn, ","), fwStr(dst, "zone_id"), strings.Join(dn, ",")}
		idx, _ := p["index"].(float64)
		pairs[k] = append(pairs[k], rec{fwStr(p, "action"), int(idx), fwRuleName(p)})
	}
	var out []FirewallFinding
	for _, recs := range pairs {
		for _, a := range recs {
			if a.action != "ALLOW" {
				continue
			}
			for _, b := range recs {
				if b.action != "BLOCK" || a.index >= b.index {
					continue
				}
				out = append(out, FirewallFinding{
					ID:             fmt.Sprintf("allow-before-block-%s-%s", a.name, b.name),
					Severity:       SevWarning,
					Category:       "rules",
					Title:          fmt.Sprintf("ALLOW %q (idx %d) shadows BLOCK %q (idx %d)", a.name, a.index, b.name, b.index),
					Detail:         "The ALLOW rule is evaluated first and matching traffic passes before the BLOCK rule is reached. The BLOCK has no effect on traffic that matches the ALLOW.",
					Recommendation: "If the block is intentional, lower its index below the allow. If both cover the same traffic, one is likely unintended.",
					RuleNames:      []string{a.name, b.name},
				})
			}
		}
	}
	return out
}

func fwCheckFragileIPRules(policies []map[string]any) []FirewallFinding {
	var out []FirewallFinding
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		name := fwRuleName(p)
		src, _ := p["source"].(map[string]any)
		dst, _ := p["destination"].(map[string]any)
		if t := fwStr(src, "matching_target"); t == "IP" || t == "CLIENT" {
			goto fragile
		}
		if t := fwStr(dst, "matching_target"); t == "IP" || t == "CLIENT" {
			goto fragile
		}
		continue
	fragile:
		out = append(out, FirewallFinding{
			ID:             "fragile-ip-" + fwStr(p, "_id"),
			Severity:       SevInfo,
			Category:       "rules",
			Title:          fmt.Sprintf("Rule %q targets specific IPs or client entries", name),
			Detail:         "IP address and client-entry rules break silently when devices get new DHCP leases, hardware is replaced, or IP reservations change.",
			Recommendation: "Convert to network/VLAN-based rules where possible. If specific IPs are required, assign those devices static DHCP reservations so the IP is stable.",
			RuleNames:      []string{name},
		})
	}
	return out
}

func fwCheckLegacyObjectRules(policies []map[string]any) []FirewallFinding {
	seen := map[string]bool{}
	var names []string
	for _, p := range policies {
		if fwStr(p, "origin_type") != "object_firewall_rule" {
			continue
		}
		n := fwRuleName(p)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []FirewallFinding{{
		ID:             "legacy-object-rules",
		Severity:       SevInfo,
		Category:       "rules",
		Title:          fmt.Sprintf("%d legacy firewall rules imported into ZBF", len(names)),
		Detail:         fmt.Sprintf("Rules %q were created in the legacy Network App firewall and bridged into ZBF compatibility mode. They create extra internal zones (visible as 'ZoneE'/'ZoneF'-style entries) and cannot be managed cleanly alongside native ZBF policies.", strings.Join(names, ", ")),
		Recommendation: "Recreate these as native ZBF policies. Then delete the original legacy firewall objects via Settings → Security → Firewall Rules to eliminate the extra zones and simplify the rule set.",
		RuleNames:      names,
	}}
}

func fwCheckUncoveredNetworks(policies, networks []map[string]any, netZone map[string]string, internalZoneID string, netName, netPurpose map[string]string) []FirewallFinding {
	inRules := map[string]bool{}
	for _, p := range policies {
		if fwBool(p, "predefined") {
			continue
		}
		for _, side := range []string{"source", "destination"} {
			s, _ := p[side].(map[string]any)
			for _, nid := range fwNetIDs(s) {
				inRules[nid] = true
			}
		}
	}
	var out []FirewallFinding
	for _, n := range networks {
		nid := fwStr(n, "_id")
		purpose := netPurpose[nid]
		if purpose == "wan" || purpose == "remote-user-vpn" {
			continue
		}
		if v, ok := n["enabled"].(bool); ok && !v {
			continue
		}
		if netZone[nid] != internalZoneID {
			continue
		}
		if !inRules[nid] {
			out = append(out, FirewallFinding{
				ID:             "uncovered-" + nid,
				Severity:       SevInfo,
				Category:       "coverage",
				Title:          fmt.Sprintf("Network %q has no user-defined firewall rules", netName[nid]),
				Detail:         "This VLAN is in the firewall zone but is not referenced by any user-defined rule. Its inter-VLAN access is governed entirely by the default catch-all policy.",
				Recommendation: "Add explicit ALLOW and BLOCK rules to make this network's security posture intentional rather than implicit.",
				RuleNames:      []string{netName[nid]},
			})
		}
	}
	return out
}

// ── Small helpers ─────────────────────────────────────────────────────────────

func fwStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func fwBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

func fwRuleName(p map[string]any) string {
	if n := fwStr(p, "name"); n != "" {
		return n
	}
	if n := fwStr(p, "description"); n != "" {
		return n
	}
	return "(unnamed)"
}

func fwNetIDs(side map[string]any) []string {
	var ids []string
	nets, ok := side["network_ids"].([]any)
	if !ok {
		return ids
	}
	for _, raw := range nets {
		if id, ok := raw.(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}
