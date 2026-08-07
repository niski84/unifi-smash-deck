package unifideck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PetLogEntry records a confirmed sighting of the pet.
type PetLogEntry struct {
	ID         string    `json:"id"`
	CameraID   string    `json:"camera_id"`
	CameraName string    `json:"camera_name"`
	At         time.Time `json:"at"`
	Confidence float64   `json:"confidence"`
	ImageFile  string    `json:"image_file"` // relative filename, e.g. "abc123_crop.jpg"
}

// PetLogStore persists pet log entries as JPEG crops + a JSON index.
type PetLogStore struct {
	mu      sync.Mutex
	dir     string
	entries []PetLogEntry
}

// NewPetLogStore loads existing entries from dir (creates dir if absent).
func NewPetLogStore(dir string) *PetLogStore {
	s := &PetLogStore{dir: dir}
	_ = os.MkdirAll(dir, 0o755)
	s.load()
	return s
}

func (s *PetLogStore) indexPath() string { return filepath.Join(s.dir, "index.json") }

func (s *PetLogStore) load() {
	raw, err := os.ReadFile(s.indexPath())
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &s.entries)
}

func (s *PetLogStore) save() error {
	b, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath(), b, 0o644)
}

// Add saves a new pet log entry with the provided cropped JPEG.
func (s *PetLogStore) Add(e PetLogEntry, cropJPEG []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := fmt.Sprintf("%d", e.At.UnixMilli())
	e.ID = id
	imgFile := id + "_crop.jpg"
	e.ImageFile = imgFile

	if err := os.WriteFile(filepath.Join(s.dir, imgFile), cropJPEG, 0o644); err != nil {
		return fmt.Errorf("pet log write image: %w", err)
	}

	s.entries = append(s.entries, e)
	sort.Slice(s.entries, func(i, j int) bool {
		return s.entries[i].At.After(s.entries[j].At)
	})
	return s.save()
}

// List returns up to limit entries, most recent first. 0 = all.
func (s *PetLogStore) List(limit int) []PetLogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PetLogEntry, len(s.entries))
	copy(out, s.entries)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Image returns the crop JPEG for a log entry by ID.
func (s *PetLogStore) Image(id string) ([]byte, error) {
	s.mu.Lock()
	var imgFile string
	for _, e := range s.entries {
		if e.ID == id {
			imgFile = e.ImageFile
			break
		}
	}
	s.mu.Unlock()
	if imgFile == "" {
		return nil, fmt.Errorf("not found")
	}
	return os.ReadFile(filepath.Join(s.dir, imgFile))
}

// Prune removes entries older than retainDays and their image files.
func (s *PetLogStore) Prune(retainDays int) {
	if retainDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retainDays)
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []PetLogEntry
	for _, e := range s.entries {
		if e.At.Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, e.ImageFile))
		} else {
			kept = append(kept, e)
		}
	}
	s.entries = kept
	_ = s.save()
}
