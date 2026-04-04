package unifideck

import (
	"context"
	"fmt"
	"log"
	"time"
)

// IPSThreatPoller polls the UniFi IDS/IPS event feed on a 5-minute interval
// and normalises events into ThreatStore.
type IPSThreatPoller struct {
	store   *ThreatStore
	tracker *ClientTracker
	stopCh  chan struct{}
}

func NewIPSThreatPoller(store *ThreatStore, tracker *ClientTracker) *IPSThreatPoller {
	return &IPSThreatPoller{
		store:   store,
		tracker: tracker,
		stopCh:  make(chan struct{}),
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Go back 1 minute before the last known event to avoid gaps at boundaries.
	since := time.Unix(0, 0)
	if last := p.store.LastTimestamp(); last > 0 {
		since = time.UnixMilli(last).Add(-time.Minute)
	}

	events, err := fetch(ctx, since)
	if err != nil {
		log.Printf("[threats/ips] poll error: %v", err)
		return
	}

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
	te := ThreatEvent{
		ID:        id,
		Kind:      ThreatKindIPS,
		Timestamp: e.TimestampMs(),
		SrcIP:     e.SrcIP,
		DstIP:     e.DstIP,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		Proto:     e.Proto,
		Severity:  e.Alert.Severity,
		Category:  e.Alert.Category,
		Signature: e.Alert.Signature,
		Action:    e.Alert.Action,
	}
	if client, ok := ipLookup[e.SrcIP]; ok {
		te.ClientMAC = client.MAC
		te.ClientName = client.Name
	}
	return te
}
