package unifideck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FleetPoller polls multiple sites in the background and stores time-series data.
type FleetPoller struct {
	db       *FleetDB
	getCfg   func() AppConfig
	interval time.Duration
	stopCh   chan struct{}
}

// NewFleetPoller creates a new fleet poller.
func NewFleetPoller(db *FleetDB, getCfg func() AppConfig, interval time.Duration) *FleetPoller {
	return &FleetPoller{
		db:       db,
		getCfg:   getCfg,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the background polling goroutine.
func (p *FleetPoller) Start() {
	go p.loop()
}

// Stop signals the poller to stop.
func (p *FleetPoller) Stop() {
	close(p.stopCh)
}

// loop is the main polling loop that runs periodically.
func (p *FleetPoller) loop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Poll immediately on start
	cfg := p.getCfg()
	p.pollAll(cfg)

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			cfg := p.getCfg()
			p.pollAll(cfg)
		}
	}
}

// pollAll polls all configured UniFi sites concurrently with a semaphore.
func (p *FleetPoller) pollAll(cfg AppConfig) {
	// Find all UniFi sites
	var sites []SiteConnection
	for _, site := range cfg.Sites {
		if site.Type == "unifi" && site.Host != "" && site.Token != "" {
			sites = append(sites, site)
		}
	}

	// Also check legacy single-site config
	if cfg.UnifiHost != "" && cfg.UnifiAPIKey != "" && len(sites) == 0 {
		sites = append(sites, SiteConnection{
			ID:       "legacy",
			Name:     "default",
			Type:     "unifi",
			Host:     cfg.UnifiHost,
			Token:    cfg.UnifiAPIKey,
			SiteName: cfg.UnifiSite,
		})
	}

	if len(sites) == 0 {
		return
	}

	// Use a semaphore to limit concurrency to 10
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, site := range sites {
		wg.Add(1)
		go func(s SiteConnection) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			p.pollSite(context.Background(), s)
		}(site)
	}

	wg.Wait()
	log.Printf("[fleet-poller] polled %d sites", len(sites))
}

// pollSite polls a single site and stores the results.
func (p *FleetPoller) pollSite(ctx context.Context, site SiteConnection) {
	siteName := siteNameOrDefault(site)

	// Fetch raw devices from the API
	devs, err := p.fetchRawDevices(ctx, site)
	if err != nil {
		log.Printf("[fleet-poller] site %s: fetch devices error: %v", site.Name, err)
		return
	}

	// Convert raw devices to snapshots
	ts := time.Now().Unix()
	var devSnaps []DeviceSnapshot
	var totalPoeDraw float64

	for _, dev := range devs {
		status := 0 // disconnected
		if dev.State == 1 {
			status = 1 // connected
		}

		// Compute RAM percentage
		ramPct := 0.0
		if dev.SysStats.MemTotal > 0 {
			ramPct = (dev.SysStats.MemUsed / dev.SysStats.MemTotal) * 100.0
		}

		// Parse CPU from LoadAvg1
		cpuPct := 0.0
		if val, err := strconv.ParseFloat(dev.SysStats.LoadAvg1, 64); err == nil {
			cpuPct = val * 100.0 // Assume load average is 0-1 scale
		}

		// Sum PoE power from port_table
		var poeDraw float64
		for _, port := range dev.PortTable {
			if port.PoeEnable {
				if val, err := strconv.ParseFloat(port.PoePower, 64); err == nil {
					poeDraw += val
				}
			}
		}
		totalPoeDraw += poeDraw

		devSnaps = append(devSnaps, DeviceSnapshot{
			DeviceID:    dev.ID,
			SiteID:      site.ID,
			Name:        dev.Name,
			Model:       dev.Model,
			Firmware:    dev.Version,
			DeviceType:  dev.Type,
			TS:          ts,
			Status:      status,
			CPUPct:      cpuPct,
			RAMPct:      ramPct,
			UptimeS:     dev.Uptime,
			PoeDraw_W:   poeDraw,
			PoeBudget_W: dev.TotalMaxPower,
			TempC:       0.0,
			ULMbps:      0.0,
			DLMbps:      0.0,
		})
	}

	// Store device snapshots
	if len(devSnaps) > 0 {
		if err := p.db.SnapshotDevices(devSnaps); err != nil {
			log.Printf("[fleet-poller] site %s: snapshot devices error: %v", site.Name, err)
		}
	}

	// Build and store site snapshot
	ss := SiteSnapshot{
		SiteID:       site.ID,
		SiteName:     siteName,
		TS:           ts,
		DeviceCount:  len(devSnaps),
		ClientCount:  0, // TODO: fetch from network health
		AlertCount:   0, // TODO: fetch from health subsystem
		WanLatencyMS: 0.0,
		WanLossPct:   0.0,
		WanIsUp:      true,
		ISPLabel:     site.ISPLabel,
	}

	// Fetch WAN health and merge into site snapshot
	if wan, err := FetchWANHealth(ctx, site); err != nil {
		log.Printf("[fleet-poller] site %s: WAN health error: %v", site.Name, err)
	} else {
		ss.WanLatencyMS = wan.LatencyMS
		ss.WanLossPct = wan.LossPct
		ss.WanIsUp = wan.IsUp
		if err2 := p.db.SnapshotWAN(*wan); err2 != nil {
			log.Printf("[fleet-poller] site %s: WAN snapshot error: %v", site.Name, err2)
		}
	}

	// Fetch WAN byte counters (internet download/upload). Sampled on every
	// poll so "today" can be computed from the baseline at local midnight.
	if wt, err := FetchWANTraffic(ctx, site); err != nil {
		log.Printf("[fleet-poller] site %s: WAN traffic error: %v", site.Name, err)
	} else {
		log.Printf("[fleet-poller] site %s: WAN sample interface=%s source=%s download_counter=%d upload_counter=%d",
			site.Name, wt.Interface, wt.Source, wt.RXBytes, wt.TXBytes)
		if err2 := p.db.SnapshotWANTraffic(*wt); err2 != nil {
			log.Printf("[fleet-poller] site %s: WAN traffic snapshot error: %v", site.Name, err2)
		}
	}

	// Fetch per-client byte counters so traffic can be attributed to specific
	// devices. This answers "who downloaded 33 GB overnight?" by diffing
	// consecutive samples.
	if ct, err := FetchClientTraffic(ctx, site); err != nil {
		log.Printf("[fleet-poller] site %s: client traffic error: %v", site.Name, err)
	} else if err2 := p.db.SnapshotClientTraffic(site.ID, ct); err2 != nil {
		log.Printf("[fleet-poller] site %s: client traffic snapshot error: %v", site.Name, err2)
	}

	if err := p.db.SnapshotSite(ss); err != nil {
		log.Printf("[fleet-poller] site %s: snapshot site error: %v", site.Name, err)
	}
}

// fetchRawDevices fetches the list of devices from the UniFi API.
func (p *FleetPoller) fetchRawDevices(ctx context.Context, site SiteConnection) ([]fleetDevice, error) {
	siteName := siteNameOrDefault(site)

	// Build the API URL
	url := fmt.Sprintf("%s/proxy/network/api/s/%s/stat/device",
		strings.TrimRight(site.Host, "/"),
		siteName)

	// Create request with insecure TLS
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   25 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-KEY", site.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(rawBody[:min(200, len(rawBody))]))
	}

	// Parse response
	var respData struct {
		Data []fleetDevice `json:"data"`
	}

	if err := json.Unmarshal(rawBody, &respData); err != nil {
		return nil, fmt.Errorf("decode device list: %w", err)
	}

	return respData.Data, nil
}

// fleetDevice is the raw device object from the UniFi API stat/device endpoint.
type fleetDevice struct {
	ID           string `json:"_id"`
	Name         string `json:"name"`
	MAC          string `json:"mac"`
	Model        string `json:"model"`
	Type         string `json:"type"`
	Version      string `json:"version"`
	State        int    `json:"state"`
	Uptime       int64  `json:"uptime"`
	TotalMaxPower float64 `json:"total_max_power"`
	SysStats     struct {
		MemUsed  float64 `json:"mem_used"`
		MemTotal float64 `json:"mem_total"`
		LoadAvg1 string  `json:"loadavg_1"`
	} `json:"sys_stats"`
	PortTable    []struct {
		PoeEnable bool   `json:"poe_enable"`
		PoePower  string `json:"poe_power"`
	} `json:"port_table"`
}

// siteNameOrDefault returns the site name or "default" if empty.
func siteNameOrDefault(site SiteConnection) string {
	if site.SiteName != "" {
		return site.SiteName
	}
	return "default"
}
