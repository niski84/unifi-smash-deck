package unifideck

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/jpeg"
	"log"
	"math"
	"sync"
	"time"
)

// GusStatus is the current tracking state returned by the API.
type GusStatus struct {
	Active     bool         `json:"active"`
	CameraID   string       `json:"camera_id,omitempty"`
	CameraName string       `json:"camera_name,omitempty"`
	LastSeen   time.Time    `json:"last_seen,omitempty"`
	Confidence float64      `json:"confidence"`
	Enabled    bool         `json:"enabled"`
	// LastBox is the most recent confirmed detection bounding box (normalized 0-1).
	LastBox    *BoundingBox `json:"last_box,omitempty"`
	// LastMotionBox is the most recent motion region, even without dog confirmation.
	LastMotionBox *BoundingBox `json:"last_motion_box,omitempty"`
	LastMotionAt  time.Time    `json:"last_motion_at,omitempty"`
}

// detResult carries a detection plus its score and the cropped JPEG (if found).
type detResult struct {
	det     Detection
	score   float64 // confidence × normalized box area; 0 if not found
	cropped []byte  // cropped JPEG around the pet
	raw     []byte  // full camera frame for this result
	at      time.Time
}

// GusCam orchestrates the video bus, pet detector, frame cropper, and output stream.
// All configured cameras are detected in parallel; the best-scoring view wins.
type GusCam struct {
	bus      *VideoBus
	detector *PetDetector
	logStore *PetLogStore
	cfg      GusConfig

	mu        sync.RWMutex
	status    GusStatus
	lastFrame []byte
	// Per-camera raw frames — only the primary (first) camera is shown when no detection.
	rawFrames  map[string][]byte
	primaryCam string
	lastLogAt  time.Time

	subsMu sync.Mutex
	subs   []chan []byte

	ctx    context.Context
	cancel context.CancelFunc
}

// NewGusCam creates the engine. Call Start to begin tracking.
func NewGusCam(bus *VideoBus, detector *PetDetector, logStore *PetLogStore, cfg GusConfig) *GusCam {
	ctx, cancel := context.WithCancel(context.Background())
	g := &GusCam{
		bus:       bus,
		detector:  detector,
		logStore:  logStore,
		cfg:       cfg,
		rawFrames: make(map[string][]byte),
		ctx:       ctx,
		cancel:    cancel,
	}
	if len(cfg.CameraIDs) > 0 {
		g.primaryCam = cfg.CameraIDs[0]
	}
	return g
}

// Start registers cameras on the bus and begins parallel detection. Non-blocking.
func (g *GusCam) Start() {
	if !g.cfg.Enabled || len(g.cfg.CameraIDs) == 0 {
		log.Printf("[guscam] disabled or no cameras configured")
		return
	}
	log.Printf("[guscam] starting — %d cameras in parallel, detection every %ds",
		len(g.cfg.CameraIDs), g.cfg.DetectionIntervalSec)

	interval := time.Duration(g.cfg.DetectionIntervalSec) * time.Second
	if interval < time.Second {
		interval = time.Second
	}

	results := make(chan detResult, len(g.cfg.CameraIDs)*2)

	for _, id := range g.cfg.CameraIDs {
		g.bus.AddCamera(g.ctx, id, id, interval)
		sub := g.bus.Subscribe(id)
		go g.cameraWorker(id, sub, results)
	}

	go g.selector(results)
}

// Stop shuts down the tracking engine.
func (g *GusCam) Stop() {
	g.cancel()
}

// Status returns the current tracking status.
func (g *GusCam) Status() GusStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := g.status
	s.Enabled = g.cfg.Enabled
	return s
}

// LatestFrame returns the most recent output JPEG frame.
func (g *GusCam) LatestFrame() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastFrame
}

// Subscribe returns a channel that receives JPEG frames from the Gus Cam output.
func (g *GusCam) Subscribe() chan []byte {
	ch := make(chan []byte, 2)
	g.subsMu.Lock()
	g.subs = append(g.subs, ch)
	g.subsMu.Unlock()
	return ch
}

// Unsubscribe removes and closes a subscriber channel.
func (g *GusCam) Unsubscribe(ch chan []byte) {
	g.subsMu.Lock()
	defer g.subsMu.Unlock()
	out := g.subs[:0]
	for _, c := range g.subs {
		if c != ch {
			out = append(out, c)
		}
	}
	g.subs = out
	close(ch)
}

// ForceLogEntry injects a manual detection event — used for testing the pipeline.
func (g *GusCam) ForceLogEntry() error {
	g.mu.RLock()
	raw := g.rawFrames[g.primaryCam]
	g.mu.RUnlock()
	if len(raw) == 0 {
		return fmt.Errorf("no frame available yet — wait for the first snapshot")
	}
	entry := PetLogEntry{
		CameraID:   g.primaryCam,
		CameraName: g.primaryCam,
		At:         time.Now(),
		Confidence: 1.0,
	}
	return g.logStore.Add(entry, raw)
}

// cameraWorker detects on every arriving frame, crops immediately, and feeds results downstream.
func (g *GusCam) cameraWorker(cameraID string, frames chan Frame, results chan<- detResult) {
	for {
		select {
		case <-g.ctx.Done():
			return
		case f, ok := <-frames:
			if !ok {
				return
			}
			// Store raw frame per-camera so the fallback view is stable.
			g.mu.Lock()
			g.rawFrames[cameraID] = f.JPEG
			g.mu.Unlock()

			det, err := g.detector.Detect(g.ctx, f)
			if err != nil {
				log.Printf("[guscam] detect error cam=%s: %v", cameraID, err)
				results <- detResult{det: det, raw: f.JPEG, at: time.Now()}
				continue
			}

			// Track motion region even when YOLO didn't confirm a dog.
			if det.MotionBox != nil {
				g.mu.Lock()
				g.status.LastMotionBox = det.MotionBox
				g.status.LastMotionAt = time.Now()
				g.mu.Unlock()
			}

			area := (det.Box.XMax - det.Box.XMin) * (det.Box.YMax - det.Box.YMin)
			score := det.Confidence * area

			var cropped []byte
			if det.Found && score > 0.005 {
				if c, err := cropJPEG(f.JPEG, det.Box); err == nil {
					cropped = c
				} else {
					cropped = f.JPEG
				}
			}

			select {
			case results <- detResult{det: det, score: score, cropped: cropped, raw: f.JPEG, at: time.Now()}:
			case <-g.ctx.Done():
				return
			}
		}
	}
}

// selector receives detections from all cameras, tracks per-camera scores,
// and emits the best-scoring camera's frame (or primary camera when idle).
func (g *GusCam) selector(results <-chan detResult) {
	scores := make(map[string]*detResult)
	staleInterval := time.Duration(g.cfg.DetectionIntervalSec*3) * time.Second
	staleTicker := time.NewTicker(staleInterval)
	defer staleTicker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			return

		case r, ok := <-results:
			if !ok {
				return
			}
			if r.det.Found && r.score > 0.005 {
				scores[r.det.CameraID] = &r
			} else {
				delete(scores, r.det.CameraID)
			}
			g.applyBest(scores)

		case <-staleTicker.C:
			for id, s := range scores {
				if time.Since(s.at) > staleInterval {
					delete(scores, id)
				}
			}
			g.applyBest(scores)
		}
	}
}

// applyBest finds the highest-scoring camera and updates status + output frame.
// When no detection, shows only the primary (first configured) camera — no bouncing.
func (g *GusCam) applyBest(scores map[string]*detResult) {
	var best *detResult
	for _, s := range scores {
		if best == nil || s.score > best.score {
			best = s
		}
	}

	if best == nil {
		// No detection — show the primary camera's latest raw frame only.
		g.mu.Lock()
		g.status.Active = false
		raw := g.rawFrames[g.primaryCam]
		g.mu.Unlock()

		if len(raw) > 0 {
			g.mu.Lock()
			g.lastFrame = raw
			g.mu.Unlock()
			g.broadcast(raw)
		}
		return
	}

	det := best.det
	log.Printf("[guscam] best cam=%s conf=%.0f%% score=%.3f",
		det.CameraName, det.Confidence*100, best.score)

	box := best.det.Box
	g.mu.Lock()
	g.lastFrame = best.cropped
	prevMotion := g.status.LastMotionBox
	prevMotionAt := g.status.LastMotionAt
	g.status = GusStatus{
		Active:        true,
		CameraID:      det.CameraID,
		CameraName:    det.CameraName,
		LastSeen:      det.At,
		Confidence:    det.Confidence,
		Enabled:       g.cfg.Enabled,
		LastBox:       &box,
		LastMotionBox: prevMotion,
		LastMotionAt:  prevMotionAt,
	}
	shouldLog := time.Since(g.lastLogAt) > 5*time.Minute
	g.mu.Unlock()

	g.broadcast(best.cropped)

	if shouldLog && best.cropped != nil {
		entry := PetLogEntry{
			CameraID:   det.CameraID,
			CameraName: det.CameraName,
			At:         det.At,
			Confidence: det.Confidence,
		}
		if err := g.logStore.Add(entry, best.cropped); err != nil {
			log.Printf("[guscam] pet log write error: %v", err)
		} else {
			g.mu.Lock()
			g.lastLogAt = time.Now()
			g.mu.Unlock()
		}
	}
}

func (g *GusCam) broadcast(frame []byte) {
	if len(frame) == 0 {
		return
	}
	g.subsMu.Lock()
	defer g.subsMu.Unlock()
	for _, ch := range g.subs {
		select {
		case ch <- frame:
		default:
		}
	}
}

// cropJPEG crops a JPEG using a normalized BoundingBox with 6% padding.
func cropJPEG(jpegData []byte, box BoundingBox) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(jpegData))
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	w := float64(bounds.Dx())
	h := float64(bounds.Dy())

	const pad = 0.06
	x0 := math.Max(0, box.XMin-pad)
	y0 := math.Max(0, box.YMin-pad)
	x1 := math.Min(1, box.XMax+pad)
	y1 := math.Min(1, box.YMax+pad)

	rect := image.Rect(
		int(x0*w), int(y0*h),
		int(x1*w), int(y1*h),
	)

	type subImager interface {
		SubImage(image.Rectangle) image.Image
	}
	si, ok := img.(subImager)
	if !ok {
		return nil, fmt.Errorf("image type does not support SubImage")
	}
	sub := si.SubImage(rect)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, sub, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
