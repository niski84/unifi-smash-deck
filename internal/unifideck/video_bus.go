package unifideck

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Frame is a single camera snapshot distributed by the VideoBus.
type Frame struct {
	CameraID   string
	CameraName string
	JPEG       []byte
	CapturedAt time.Time
}

type cameraSource struct {
	cameraID   string
	cameraName string
	interval   time.Duration
	cancel     context.CancelFunc
}

// VideoBus polls cameras and fan-outs frames to registered subscribers.
// Multiple subsystems (GusCam, future analytics) subscribe without duplicating HTTP requests.
type VideoBus struct {
	mu          sync.RWMutex
	client      func() *UnifiClient
	sources     map[string]*cameraSource // cameraID -> source
	subscribers map[string][]chan Frame  // cameraID -> subscriber chans
	nextID      atomic.Int64
	wg          sync.WaitGroup
}

// NewVideoBus creates a bus using clientFn to get a fresh UnifiClient per request.
func NewVideoBus(clientFn func() *UnifiClient) *VideoBus {
	return &VideoBus{
		client:      clientFn,
		sources:     make(map[string]*cameraSource),
		subscribers: make(map[string][]chan Frame),
	}
}

// AddCamera registers a camera to be polled at the given interval.
// Safe to call before or after Start. If the camera is already registered, the
// existing poller is canceled and replaced — this matters when callers restart
// (e.g. GusCam.Stop()/Start() on config change), otherwise the second Start
// would silently spawn no goroutine and the bus would go dark.
func (b *VideoBus) AddCamera(ctx context.Context, cameraID, cameraName string, interval time.Duration) {
	b.mu.Lock()
	if existing, ok := b.sources[cameraID]; ok {
		existing.cancel()
		delete(b.sources, cameraID)
	}
	cctx, cancel := context.WithCancel(ctx)
	src := &cameraSource{cameraID: cameraID, cameraName: cameraName, interval: interval, cancel: cancel}
	b.sources[cameraID] = src
	b.mu.Unlock()

	b.wg.Add(1)
	go b.poll(cctx, src)
}

// Subscribe returns a channel that receives frames from the given cameras.
// Pass "*" to subscribe to all cameras added to the bus.
// Frames are dropped if the consumer is slow (buffer size 2).
func (b *VideoBus) Subscribe(cameraIDs ...string) chan Frame {
	ch := make(chan Frame, 2)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range cameraIDs {
		b.subscribers[id] = append(b.subscribers[id], ch)
	}
	// If "*" requested, also register for any future cameras.
	for _, id := range cameraIDs {
		if id == "*" {
			// mark as wildcard — handled in publish
			b.subscribers["*"] = append(b.subscribers["*"], ch)
			break
		}
	}
	return ch
}

// Unsubscribe removes ch from all camera subscriptions and closes it.
func (b *VideoBus) Unsubscribe(ch chan Frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, chans := range b.subscribers {
		filtered := chans[:0]
		for _, c := range chans {
			if c != ch {
				filtered = append(filtered, c)
			}
		}
		b.subscribers[id] = filtered
	}
	close(ch)
}

// Stop cancels all camera pollers. Safe to call multiple times.
func (b *VideoBus) Stop() {
	b.mu.RLock()
	for _, src := range b.sources {
		src.cancel()
	}
	b.mu.RUnlock()
	b.wg.Wait()
}

func (b *VideoBus) poll(ctx context.Context, src *cameraSource) {
	defer b.wg.Done()
	ticker := time.NewTicker(src.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			client := b.client()
			if client == nil {
				continue
			}
			jpeg, _, err := client.CameraSnapshot(ctx, src.cameraID, true)
			if err != nil {
				log.Printf("[videobus] snapshot error cam=%s: %v", src.cameraID, err)
				continue
			}
			f := Frame{
				CameraID:   src.cameraID,
				CameraName: src.cameraName,
				JPEG:       jpeg,
				CapturedAt: time.Now(),
			}
			b.publish(f)
		}
	}
}

func (b *VideoBus) publish(f Frame) {
	b.mu.RLock()
	targets := make([]chan Frame, 0, 4)
	for _, ch := range b.subscribers[f.CameraID] {
		targets = append(targets, ch)
	}
	for _, ch := range b.subscribers["*"] {
		targets = append(targets, ch)
	}
	b.mu.RUnlock()

	for _, ch := range targets {
		select {
		case ch <- f:
		default: // drop frame if consumer is slow
		}
	}
}
