import io
import logging
import os
import threading
import time
from collections import defaultdict

import numpy as np
from fastapi import FastAPI, File, Query, UploadFile
from PIL import Image, ImageChops, ImageFilter
from ultralytics import YOLO

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guscam-sidecar")

app = FastAPI(title="Gus Cam Detection Sidecar")

# Model is env-configurable. yolo11n (nano) misses small/occluded dogs; yolo11l is
# far more reliable. The model is LAZY-LOADED and auto-unloaded after idle, so when
# Argus pauses detection the GPU memory is freed automatically.
MODEL_NAME = os.getenv("YOLO_MODEL", "yolo11l.pt")
IDLE_UNLOAD_SEC = int(os.getenv("IDLE_UNLOAD_SEC", "180"))  # 0 = never unload

_model = None
_model_lock = threading.Lock()
_last_used = 0.0


def get_model():
    """Load the model on first use (and after an idle unload)."""
    global _model, _last_used
    _last_used = time.time()
    if _model is None:
        with _model_lock:
            if _model is None:
                log.info(f"loading model {MODEL_NAME}")
                _model = YOLO(MODEL_NAME)
    return _model


def unload_model():
    global _model
    with _model_lock:
        if _model is not None:
            log.info("unloading model (freeing GPU memory)")
            _model = None
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except Exception:
                pass


def _idle_watcher():
    while True:
        time.sleep(30)
        if IDLE_UNLOAD_SEC > 0 and _model is not None and time.time() - _last_used > IDLE_UNLOAD_SEC:
            unload_model()


threading.Thread(target=_idle_watcher, daemon=True).start()

DOG_CLASS = 16
PERSON_CLASS = 0
CAT_CLASS = 15
MIN_CONFIDENCE = 0.15  # lower threshold — snapshots are small/blurry
# Reject a "dog" hit when a person/cat scores higher in the same region. Kills
# high-confidence night-IR false positives (a human blob misread as a dog). A
# Gus-specific model would do better; this is a cheap, principled guard.
REJECT_NONDOG = os.getenv("REJECT_NONDOG", "1") != "0"
# Inference resolution. Cameras are 2688px wide but YOLO's default 640 downscales a
# distant dog into nothing. 1280 recovered recall 65%->88% on the test set; tune via env.
IMGSZ = int(os.getenv("YOLO_IMGSZ", "1280"))

# Per-camera previous frame cache for motion detection.
_prev_frames: dict[str, Image.Image] = defaultdict(lambda: None)


def motion_bbox(prev: Image.Image, curr: Image.Image, threshold: int = 25, min_area: float = 0.01) -> tuple | None:
    """Return normalized (x_min,y_min,x_max,y_max) of the motion region, or None if too small."""
    diff = ImageChops.difference(prev.convert("L"), curr.convert("L"))
    diff = diff.filter(ImageFilter.GaussianBlur(radius=3))
    arr = np.array(diff)
    mask = arr > threshold
    if not mask.any():
        return None
    rows = np.where(mask.any(axis=1))[0]
    cols = np.where(mask.any(axis=0))[0]
    h, w = arr.shape
    y0, y1 = int(rows[0]), int(rows[-1])
    x0, x1 = int(cols[0]), int(cols[-1])
    # Reject noise (motion region < min_area of frame)
    area = ((x1 - x0) / w) * ((y1 - y0) / h)
    if area < min_area:
        return None
    # Normalize to 0-1, add 10% padding
    pad_x = 0.10 * (x1 - x0) / w
    pad_y = 0.10 * (y1 - y0) / h
    return (
        max(0.0, x0 / w - pad_x),
        max(0.0, y0 / h - pad_y),
        min(1.0, x1 / w + pad_x),
        min(1.0, y1 / h + pad_y),
    )


def crop_to_box(img: Image.Image, box: tuple) -> Image.Image:
    w, h = img.size
    x0, y0, x1, y1 = box
    return img.crop((int(x0 * w), int(y0 * h), int(x1 * w), int(y1 * h)))


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME, "imgsz": IMGSZ, "loaded": _model is not None}


@app.post("/load")
def load():
    get_model()
    return {"status": "ok", "loaded": True}


@app.post("/unload")
def unload():
    unload_model()
    return {"status": "ok", "loaded": False}


@app.post("/detect")
async def detect(image: UploadFile = File(...), camera_id: str = Query("default", alias="camera_id")):
    data = await image.read()
    curr = Image.open(io.BytesIO(data)).convert("RGB")
    prev = _prev_frames.get(camera_id)
    _prev_frames[camera_id] = curr

    # --- Motion-gated detection ---
    # If we have a previous frame, find the motion region and run YOLO there first.
    # This lets YOLO see a zoomed-in crop where the dog actually is, dramatically
    # improving detection on low-res snapshots.
    search_regions: list[tuple | None] = []
    motion_box = None
    if prev is not None:
        try:
            prev_resized = prev.resize(curr.size)
            motion_box = motion_bbox(prev_resized, curr)
        except Exception as e:
            log.warning(f"motion diff failed: {e}")

    if motion_box:
        search_regions.append(motion_box)   # try motion crop first
    search_regions.append(None)             # full frame fallback

    best_conf = 0.0
    best_box = None
    matched_region = None

    for region in search_regions:
        if region is not None:
            search_img = crop_to_box(curr, region)
        else:
            search_img = curr

        classes = [PERSON_CLASS, CAT_CLASS, DOG_CLASS] if REJECT_NONDOG else [DOG_CLASS]
        results = get_model()(search_img, verbose=False, classes=classes, imgsz=IMGSZ)

        region_dog_conf = 0.0
        region_dog_xyxyn = None
        region_other_conf = 0.0  # best non-dog (person/cat) in this region
        for r in results:
            for box in r.boxes:
                cls = int(box.cls[0])
                conf = float(box.conf[0])
                if cls == DOG_CLASS:
                    if conf > region_dog_conf:
                        region_dog_conf = conf
                        region_dog_xyxyn = box.xyxyn[0].tolist()
                else:
                    region_other_conf = max(region_other_conf, conf)

        # Accept the dog only if it's above threshold AND the dominant interpretation
        # of that region (not beaten by a person/cat → rejects night-human blobs).
        if (region_dog_xyxyn is not None and region_dog_conf >= MIN_CONFIDENCE
                and region_dog_conf >= region_other_conf and region_dog_conf > best_conf):
            best_conf = region_dog_conf
            x1, y1, x2, y2 = region_dog_xyxyn
            if region is not None:
                rx0, ry0, rx1, ry1 = region
                rw, rh = rx1 - rx0, ry1 - ry0
                x1 = rx0 + x1 * rw
                y1 = ry0 + y1 * rh
                x2 = rx0 + x2 * rw
                y2 = ry0 + y2 * rh
            best_box = {"x_min": x1, "y_min": y1, "x_max": x2, "y_max": y2}
            matched_region = "motion" if region else "full"
        elif region_other_conf > region_dog_conf and region_other_conf >= 0.4:
            log.info(f"rejected non-dog: other={region_other_conf:.2f} > dog={region_dog_conf:.2f}")

        if best_box:
            break  # found in this region, no need for full-frame search

    motion_info = {
        "detected": motion_box is not None,
        "box": {"x_min": motion_box[0], "y_min": motion_box[1],
                "x_max": motion_box[2], "y_max": motion_box[3]} if motion_box else None,
    }

    if best_box is None:
        return {
            "found": False, "confidence": 0.0,
            "box": {"x_min": 0.0, "y_min": 0.0, "x_max": 0.0, "y_max": 0.0},
            "motion": motion_info,
        }

    log.info(f"dog detected conf={best_conf:.2f} region={matched_region} box={best_box}")
    return {"found": True, "confidence": best_conf, "box": best_box, "motion": motion_info}
