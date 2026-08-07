package unifideck

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// IPSThreatPoller polls the UniFi IDS/IPS event feed on a 5-minute interval
// and normalises events into ThreatStore.
type IPSThreatPoller struct {
	store       *ThreatStore
	tracker     *ClientTracker
	stopCh      chan struct{}
	mu          sync.RWMutex
	lastPoll    time.Time
	lastSuccess time.Time
	lastError   string
	feedState   string
	honeypotIPs map[string]struct{}
}

func NewIPSThreatPoller(store *ThreatStore, tracker *ClientTracker) *IPSThreatPoller {
	return &IPSThreatPoller{
		store:       store,
		tracker:     tracker,
		stopCh:      make(chan struct{}),
		feedState:   "not_started",
		honeypotIPs: make(map[string]struct{}),
	}
}

type ThreatPollerStatus struct {
	State         string `json:"state"`
	LastPollMs    int64  `json:"last_poll_ms,omitempty"`
	LastSuccessMs int64  `json:"last_success_ms,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

func (p *IPSThreatPoller) SetHoneypotIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.honeypotIPs = make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			p.honeypotIPs[ip] = struct{}{}
		}
	}
}

func (p *IPSThreatPoller) Status() ThreatPollerStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return ThreatPollerStatus{State: p.feedState, LastPollMs: unixMilli(p.lastPoll), LastSuccessMs: unixMilli(p.lastSuccess), LastError: p.lastError}
}

func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

type fetchIPSFn func(ctx context.Context, since time.Time) ([]IPSEvent, error)

func (p *IPSThreatPoller) Start(fetch fetchIPSFn) {
	go func() {
		p.poll(fetch)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.poll(fetch)
			case <-p.stopCh:
				return
			}
		}
	}()
}

func (p *IPSThreatPoller) Stop() {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
}

func (p *IPSThreatPoller) poll(fetch fetchIPSFn) {
	p.mu.Lock()
	p.lastPoll = time.Now()
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Go back 1 minute before the last known event to avoid gaps at boundaries.
	since := time.Unix(0, 0)
	if last := p.store.LastTimestamp(); last > 0 {
		since = time.UnixMilli(last).Add(-time.Minute)
	}

	events, err := fetch(ctx, since)
	if err != nil {
		p.mu.Lock()
		p.lastError = err.Error()
		if err == ErrThreatManagementUnavailable {
			p.feedState = "disabled"
		} else {
			p.feedState = "error"
		}
		p.mu.Unlock()
		if err == ErrThreatManagementUnavailable {
			log.Printf("[threats/ips] unavailable — enable UniFi Threat Management/IPS to ingest controller alerts")
		} else {
			log.Printf("[threats/ips] poll error: %v", err)
		}
		return
	}
	p.mu.Lock()
	p.lastSuccess = time.Now()
	p.lastError = ""
	p.feedState = "ok"
	p.mu.Unlock()

	ipLookup := p.ipSnapshot()
	newCount := 0
	for _, e := range events {
		te := p.convert(e, ipLookup)
		if p.store.Add(te) {
			newCount++
			log.Printf("[threats/ips] new event src=%s sig=%q sev=%d", te.SrcIP, te.Signature, te.Severity)
		}
	}
	log.Printf("[threats/ips] poll OK — %d fetched, %d new", len(events), newCount)
}

// ipSnapshot builds a map of IP → {MAC, Name} from the current client tracker state.
func (p *IPSThreatPoller) ipSnapshot() map[string]struct{ MAC, Name string } {
	p.tracker.mu.Lock()
	defer p.tracker.mu.Unlock()
	m := make(map[string]struct{ MAC, Name string }, len(p.tracker.known))
	for _, tc := range p.tracker.known {
		if tc.IP == "" {
			continue
		}
		name := tc.Name
		if name == "" {
			name = tc.Hostname
		}
		if name == "" {
			name = tc.MAC
		}
		m[tc.IP] = struct{ MAC, Name string }{tc.MAC, name}
	}
	return m
}

func (p *IPSThreatPoller) convert(e IPSEvent, ipLookup map[string]struct{ MAC, Name string }) ThreatEvent {
	id := e.ID
	if id == "" {
		id = fmt.Sprintf("ips-%d-%s-%d", e.TimestampMs(), e.SrcIP, e.SrcPort)
	}
	p.mu.RLock()
	controllerHoneypot := false
	if _, ok := p.honeypotIPs[e.DstIP]; ok {
		controllerHoneypot = true
	}
	p.mu.RUnlock()
	kind := ThreatKindIPS
	severity := e.Alert.Severity
	category := e.Alert.Category
	signature := e.Alert.Signature
	if controllerHoneypot {
		kind = ThreatKindHoneypot
		severity = 1
		category = "Controller Honeypot"
		if signature == "" {
			signature = "UniFi controller honeypot hit"
		}
	}
	te := ThreatEvent{
		ID:        id,
		Kind:      kind,
		Timestamp: e.TimestampMs(),
		SrcIP:     e.SrcIP,
		DstIP:     e.DstIP,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		Proto:     e.Proto,
		Severity:  severity,
		Category:  category,
		Signature: signature,
		Action:    e.Alert.Action,
	}
	if client, ok := ipLookup[e.SrcIP]; ok {
		te.ClientMAC = client.MAC
		te.ClientName = client.Name
	}
	return te
}
