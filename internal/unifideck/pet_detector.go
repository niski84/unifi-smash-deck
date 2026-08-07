package unifideck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"time"
)

// BoundingBox holds normalized coordinates (0.0–1.0 relative to image dimensions).
type BoundingBox struct {
	XMin float64 `json:"x_min"`
	YMin float64 `json:"y_min"`
	XMax float64 `json:"x_max"`
	YMax float64 `json:"y_max"`
}

// Detection is the result of running the PetDetector on a Frame.
type Detection struct {
	Found      bool         `json:"found"`
	Confidence float64      `json:"confidence"`
	Box        BoundingBox  `json:"box"`
	MotionBox  *BoundingBox `json:"motion_box,omitempty"` // motion region even when no dog confirmed
	CameraID   string       `json:"camera_id"`
	CameraName string       `json:"camera_name"`
	At         time.Time    `json:"at"`
}

// PetDetector calls the local YOLOv11 FastAPI sidecar to detect pets in frames.
type PetDetector struct {
	url    string
	client *http.Client
}

// NewPetDetector creates a detector pointing at the given sidecar URL.
// Defaults to http://127.0.0.1:8103 if url is empty.
func NewPetDetector(url string) *PetDetector {
	if url == "" {
		url = "http://127.0.0.1:8103"
	}
	return &PetDetector{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Detect sends a JPEG frame to the sidecar and returns the detection result.
func (d *PetDetector) Detect(ctx context.Context, f Frame) (Detection, error) {
	det := Detection{CameraID: f.CameraID, CameraName: f.CameraName, At: f.CapturedAt}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("image", "frame.jpg")
	if err != nil {
		return det, fmt.Errorf("multipart create: %w", err)
	}
	if _, err := fw.Write(f.JPEG); err != nil {
		return det, fmt.Errorf("multipart write: %w", err)
	}
	w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.url+"/detect?camera_id="+f.CameraID, &body)
	if err != nil {
		return det, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := d.client.Do(req)
	if err != nil {
		return det, fmt.Errorf("sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Found      bool        `json:"found"`
		Confidence float64     `json:"confidence"`
		Box        BoundingBox `json:"box"`
		Motion     struct {
			Detected bool         `json:"detected"`
			Box      *BoundingBox `json:"box"`
		} `json:"motion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return det, fmt.Errorf("sidecar response: %w", err)
	}

	det.Found = result.Found
	det.Confidence = result.Confidence
	det.Box = result.Box
	if result.Motion.Detected && result.Motion.Box != nil {
		det.MotionBox = result.Motion.Box
	}
	return det, nil
}
