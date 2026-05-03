"""
Shared Application State
=========================
Central in-memory store shared across all route modules.
All routers import `_state` from here to read/write live data.

Also provides `_build_engine()` — constructs a DetectionEngine
from the persisted artefacts and the currently active model.
"""

from app.core.pipeline import (
    load_nsa, load_iso, load_preprocessor,
)
from app.core.detection import DetectionEngine


# ── In-memory state ──────────────────────────────────────────────────────
_state: dict = {
    "status":         "idle",       # idle | learning | active | error
    "training_logs":  [],
    "alerts":         [],
    "last_result":    None,
    "active_model":   "nsa",        # "nsa" or "isolation_forest"
    "packet_count":   0,
    "anomaly_count":  0,
    # Live capture
    "capture_active": False,
    "sniffer":        None,         # PacketSniffer instance
    "ws_clients":     [],           # active WebSocket connections
    # Live chart ring buffer (60 data points)
    "chart_normal":   [0] * 60,
    "chart_anomaly":  [0] * 60,
    "chart_ts":       [],
    "flows_completed": 0,
    # Batch detection
    "detect_status":       "idle",  # idle | running | done | error
    "detect_logs":         [],
    "last_detect_result":  None,
}


def _build_engine() -> DetectionEngine:
    """Build a DetectionEngine from the persisted artefacts."""
    prep = load_preprocessor()
    model = load_iso() if _state["active_model"] == "isolation_forest" else load_nsa()
    return DetectionEngine(model, prep, active_model=_state["active_model"])
