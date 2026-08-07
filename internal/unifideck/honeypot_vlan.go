package unifideck

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// HoneypotVLAN scopes the listener to a UniFi network subnet. An empty list
// preserves the existing global listener behavior; once configured, only
// enabled matching VLANs generate honeypot events.
type HoneypotVLAN struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	VLAN        int    `json:"vlan"`
	IPSubnet    string `json:"ip_subnet"`
	Enabled     bool   `json:"enabled"`
}

func (s *HTTPServer) handleHoneypotVLANs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var vlans []HoneypotVLAN
		if err := json.NewDecoder(r.Body).Decode(&vlans); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		cfg := s.snapshotCfg()
		cfg.HoneypotVLANs = vlans
		if err := SaveAppConfig(s.settingsPath, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cfg)
		s.honeypotSrv.SetHoneypotVLANs(vlans)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: vlans})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}

	cfg := s.snapshotCfg()
	saved := make(map[string]HoneypotVLAN, len(cfg.HoneypotVLANs))
	for _, vlan := range cfg.HoneypotVLANs {
		saved[vlan.NetworkID] = vlan
	}
	client := s.unifiClient()
	if !client.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: cfg.HoneypotVLANs})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	networks, err := client.ListNetworks(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	rows := make([]HoneypotVLAN, 0, len(networks))
	for _, n := range networks {
		if n.Purpose == "wan" || n.Purpose == "remote-user-vpn" || strings.TrimSpace(n.IPSubnet) == "" {
			continue
		}
		vlan := HoneypotVLAN{NetworkID: n.ID, NetworkName: n.Name, VLAN: n.VlanID, IPSubnet: n.IPSubnet}
		if old, ok := saved[n.ID]; ok {
			vlan.Enabled = old.Enabled
		}
		rows = append(rows, vlan)
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: rows})
}
