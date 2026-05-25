"""Configuration constants for the NSA/V-Detector model."""

# Maximum self rows used for both negative selection (fit) and inference.
SELF_REF_CAP = 3_000

# Distance matrix budget for laptop-friendly memory use.
MAX_DISTANCE_MATRIX_ENTRIES = 4_000_000
PREDICT_CHUNK = 5_000

DEFAULT_FUSION_WEIGHTS = {
    "detector": 0.40,
    "distance": 0.25,
    "density": 0.20,
    "self_boundary": 0.15,
}

MIN_COMPONENT_SCALES = {
    "distance": 0.05,
    "density": 0.05,
    "detector": 1.0,
    "self_boundary": 0.10,
}

DISABLED_FUSION_CALIBRATION = {
    "mode": "disabled_legacy",
    "score_mode": "disabled",
    "active": False,
    "reason": "Weighted fusion is disabled; active NSA decision uses v_detector_match OR self_distance > threshold.",
}
