package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── VLAN Labels ───────────────────────────────────────────────────────────────

// VLANPurpose is the user-defined usage type for a network VLAN.
type VLANPurpose string

const (
	PurposeIoT        VLANPurpose = "iot"
	PurposeCameras    VLANPurpose = "cameras"
	PurposeMedia      VLANPurpose = "media"
	PurposeTrusted    VLANPurpose = "trusted"
	PurposeWork       VLANPurpose = "work"
	PurposeManagement VLANPurpose = "management"
	PurposeGuest      VLANPurpose = "guest"
	PurposeOther      VLANPurpose = "other"
)

// VLANLabel associates a UniFi network ID with a user-defined purpose.
type VLANLabel struct {
	NetworkID string      `json:"network_id"`
	Purpose   VLANPurpose `json:"purpose"`
}

func vlanLabelsFile() string {
	return filepath.Join(DataDir(), "vlan-labels.json")
}

func loadVLANLabels() ([]VLANLabel, error) {
	b, err := os.ReadFile(vlanLabelsFile())
	if os.IsNotExist(err) {
		return []VLANLabel{}, nil
	}
	if err != nil {
		return nil, err
	}
	var labels []VLANLabel
	if err := json.Unmarshal(b, &labels); err != nil {
		return nil, err
	}
	return labels, nil
}

func saveVLANLabels(labels []VLANLabel) error {
	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(labels, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(vlanLabelsFile(), b, 0o600)
}

// VLANLabelRow combines a network record with its saved label for the wizard UI.
type VLANLabelRow struct {
	NetworkID   string      `json:"network_id"`
	NetworkName string      `json:"network_name"`
	VLAN        int         `json:"vlan"`
	IPSubnet    string      `json:"ip_subnet"`
	Purpose     VLANPurpose `json:"purpose"`
}

// handleVLANLabels serves GET (list) and POST (save).
// GET /api/vlan-labels  → returns networks merged with saved labels
// POST /api/vlan-labels → body: [{network_id, purpose}]
func (s *HTTPServer) handleVLANLabels(w http.ResponseWriter, r *http.Request) {
	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: []VLANLabelRow{}})
		return
	}

	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		networks, err := c.ListNetworks(ctx)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
			return
		}
		labels, _ := loadVLANLabels()
		purposeByID := make(map[string]VLANPurpose, len(labels))
		for _, l := range labels {
			purposeByID[l.NetworkID] = l.Purpose
		}
		var rows []VLANLabelRow
		for _, n := range networks {
			if n.Purpose == "wan" || n.Purpose == "remote-user-vpn" {
				continue
			}
			rows = append(rows, VLANLabelRow{
				NetworkID:   n.ID,
				NetworkName: n.Name,
				VLAN:        n.VlanID,
				IPSubnet:    n.IPSubnet,
				Purpose:     purposeByID[n.ID],
			})
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: rows})

	case http.MethodPost:
		var labels []VLANLabel
		if err := json.NewDecoder(r.Body).Decode(&labels); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		if err := saveVLANLabels(labels); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.logger.Info("vlan-labels saved: %d entries", len(labels))
		writeJSON(w, http.StatusOK, apiResp{Success: true})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// ── IGMP Snooping Diagnostics ─────────────────────────────────────────────────

// IGMPNetworkResult is one VLAN's IGMP snooping assessment.
type IGMPNetworkResult struct {
	NetworkID    string           `json:"network_id"`
	NetworkName  string           `json:"network_name"`
	VLAN         int              `json:"vlan"`
	Purpose      VLANPurpose      `json:"purpose"`
	IGMPEnabled  bool             `json:"igmp_enabled"`
	Recommend    bool             `json:"recommend"`
	Status       DiagnosticStatus `json:"status"`
	Note         string           `json:"note"`
	Fixable      bool             `json:"fixable"`
	FixAction    string           `json:"fix_action,omitempty"` // "enable" | "disable"
}

// IGMPSnoopingResult is the full report returned to the UI.
type IGMPSnoopingResult struct {
	RunAt    time.Time           `json:"run_at"`
	Networks []IGMPNetworkResult `json:"networks"`
}

// igmpRecommend returns the recommendation and rationale for a given purpose.
func igmpRecommend(p VLANPurpose) (recommend bool, note string) {
	switch p {
	case PurposeIoT:
		return true, "IoT devices rely on multicast (mDNS, SSDP). IGMP snooping keeps that traffic targeted and reduces flood on the VLAN."
	case PurposeCameras:
		return true, "Camera streams often use multicast. IGMP snooping ensures video traffic only reaches interested receivers."
	case PurposeMedia:
		return true, "Media devices (Chromecast, AirPlay, Plex) use multicast for discovery and streaming."
	case PurposeTrusted:
		return true, "Trusted networks may use multicast for file sharing and device discovery. Recommended on."
	case PurposeWork:
		return true, "Work networks can use multicast for conferencing and collaboration tools."
	case PurposeManagement:
		return false, "Management VLANs rarely use multicast. IGMP snooping adds unnecessary overhead."
	case PurposeGuest:
		return false, "Guest networks should isolate traffic. Multicast snooping is unnecessary and could expose device lists."
	case PurposeOther:
		return false, "Purpose is 'Other' — review manually to decide if multicast is needed on this VLAN."
	default:
		return false, "This VLAN has no label yet. Set a purpose above to get a personalized recommendation."
	}
}

// RunIGMPDiagnostics fetches networks, loads saved labels, and evaluates each VLAN.
func RunIGMPDiagnostics(ctx context.Context, c *UnifiClient) (*IGMPSnoopingResult, error) {
	networks, err := c.ListNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch networks: %w", err)
	}
	labels, _ := loadVLANLabels()

	purposeByID := make(map[string]VLANPurpose, len(labels))
	for _, l := range labels {
		purposeByID[l.NetworkID] = l.Purpose
	}

	var results []IGMPNetworkResult
	for _, n := range networks {
		if n.Purpose == "wan" || n.Purpose == "remote-user-vpn" {
			continue
		}
		purpose := purposeByID[n.ID]
		recommend, note := igmpRecommend(purpose)

		var status DiagnosticStatus
		var fixAction string
		if purpose == "" {
			status = StatusWarn
		} else if n.IGMPSnooping == recommend {
			status = StatusOK
		} else {
			status = StatusWarn
			if recommend {
				fixAction = "enable"
			} else {
				fixAction = "disable"
			}
		}

		results = append(results, IGMPNetworkResult{
			NetworkID:   n.ID,
			NetworkName: n.Name,
			VLAN:        n.VlanID,
			Purpose:     purpose,
			IGMPEnabled: n.IGMPSnooping,
			Recommend:   recommend,
			Status:      status,
			Note:        note,
			Fixable:     fixAction != "",
			FixAction:   fixAction,
		})
	}

	return &IGMPSnoopingResult{
		RunAt:    time.Now(),
		Networks: results,
	}, nil
}

// handleIGMPDiagnose runs the IGMP snooping report.
// GET /api/igmp/diagnose
func (s *HTTPServer) handleIGMPDiagnose(w http.ResponseWriter, r *http.Request) {
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
	result, err := RunIGMPDiagnostics(ctx, c)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: result})
}

// handleIGMPFix applies an IGMP snooping fix to a network.
// POST /api/igmp/networks/{id}/enable
// POST /api/igmp/networks/{id}/disable
func (s *HTTPServer) handleIGMPFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/igmp/networks/")
	parts := strings.SplitN(strings.Trim(path, "/"), "/", 2)
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "expected /api/igmp/networks/{id}/{action}"})
		return
	}
	netID, action := parts[0], parts[1]

	var enabled bool
	switch action {
	case "enable":
		enabled = true
	case "disable":
		enabled = false
	default:
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: fmt.Sprintf("unknown action %q", action)})
		return
	}

	c := s.unifiClient()
	if !c.IsConfigured() {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "UniFi not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	if err := c.UpdateNetworkFields(ctx, netID, map[string]any{"igmp_snooping": enabled}); err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	s.logger.Info("igmp fix: network=%s action=%s", netID, action)
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{"network_id": netID, "action": action}})
}

