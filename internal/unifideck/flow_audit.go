package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// UDMWANFlowRow is a source/destination aggregate read directly from the
// UDM's ace_audit.traffic_flow collection. It is deliberately separate from
// stat/sta client counters: traffic_flow contains the actual historical WAN
// flow records, while stat/sta may retain disconnected clients.
type UDMWANFlowRow struct {
	SourceMAC         string `json:"source_mac"`
	SourceIP          string `json:"source_ip"`
	DestinationIP     string `json:"destination_ip"`
	DestinationPort   int    `json:"destination_port"`
	UploadBytes       int64  `json:"upload_bytes"`
	DownloadBytes     int64  `json:"download_bytes"`
	FlowCount         int64  `json:"flow_count"`
	FirstFlowMS       int64  `json:"first_flow_ms"`
	LastFlowMS        int64  `json:"last_flow_ms"`
	CurrentName       string `json:"current_name,omitempty"`
	CurrentHostname   string `json:"current_hostname,omitempty"`
	CurrentSwitchMAC  string `json:"current_switch_mac,omitempty"`
	CurrentSwitchPort int    `json:"current_switch_port,omitempty"`
	CurrentLinkUp     *bool  `json:"current_link_up,omitempty"`
}

type udmClientLink struct {
	Name       string
	Hostname   string
	SwitchMAC  string
	SwitchPort int
	LinkUp     *bool
}

// QueryUDMWANFlows reads historical WAN flows from the UDM. UniFi's flow
// collection uses bytes_rx for client→gateway (upload) and bytes_tx for
// gateway→client (download), matching the direction of the WAN audit.
func QueryUDMWANFlows(cfg AppConfig, start, end time.Time) ([]UDMWANFlowRow, error) {
	client, err := udmSSHClient(cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	startMS := start.UnixMilli()
	endMS := end.UnixMilli()
	// These values are generated from time.Time, never user input, so the
	// Mongo expression cannot be used for command injection.
	js := fmt.Sprintf(`var q={"out.interface_name":"eth8",time:{$gte:%d,$lte:%d}}; db.traffic_flow.aggregate([{$match:q},{$group:{_id:{mac:"$source.mac",ip:"$source.ip",dst:"$destination.ip",port:"$destination.port"},upload:{$sum:"$data.bytes_rx"},download:{$sum:"$data.bytes_tx"},flows:{$sum:1},first:{$min:"$flow_start_time"},last:{$max:"$flow_end_time"}}},{$sort:{upload:-1}}]).forEach(function(x){print(JSON.stringify({source_mac:x._id.mac,source_ip:x._id.ip,destination_ip:x._id.dst,destination_port:x._id.port,upload_bytes:Number(x.upload),download_bytes:Number(x.download),flow_count:Number(x.flows),first_flow_ms:Number(x.first),last_flow_ms:Number(x.last)}))})`, startMS, endMS)

	output, err := udmRun(client, "mongo --quiet --host 127.0.0.1 --port 27117 ace_audit --eval '"+js+"'")
	if err != nil {
		return nil, err
	}

	var rows []UDMWANFlowRow
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "MongoDB shell version") {
			continue
		}
		var row UDMWANFlowRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("decode UDM flow row %q: %w", line, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// CurrentUDMClientLinks joins the retained station identity with the live
// switch port table. LinkUp is intentionally a pointer: nil means the current
// connection could not be resolved, while false is a real disconnected port.
func CurrentUDMClientLinks(cfg AppConfig) (map[string]udmClientLink, error) {
	c := NewUnifiClient(cfg.UnifiHost, cfg.UnifiAPIKey, cfg.UnifiSite)
	stations, err := c.ListStationsRaw(context.Background())
	if err != nil {
		return nil, err
	}
	devices, err := c.ListDevicesRaw(context.Background())
	if err != nil {
		return nil, err
	}
	portStates := make(map[string]bool)
	for _, device := range devices {
		mac, _ := device["mac"].(string)
		ports, _ := device["port_table"].([]any)
		for _, raw := range ports {
			port, _ := raw.(map[string]any)
			idx := intFromAny(port["port_idx"])
			if idx > 0 {
				up, _ := port["up"].(bool)
				portStates[trafficPortKey(mac, idx)] = up
			}
		}
	}
	links := make(map[string]udmClientLink)
	for _, station := range stations {
		mac, _ := station["mac"].(string)
		if mac == "" {
			continue
		}
		link := udmClientLink{}
		link.Name, _ = station["name"].(string)
		link.Hostname, _ = station["hostname"].(string)
		link.SwitchMAC, _ = station["sw_mac"].(string)
		link.SwitchPort = intFromAny(station["sw_port"])
		if link.SwitchMAC != "" && link.SwitchPort > 0 {
			if up, ok := portStates[trafficPortKey(link.SwitchMAC, link.SwitchPort)]; ok {
				link.LinkUp = &up
			}
		}
		links[strings.ToLower(mac)] = link
	}
	return links, nil
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
