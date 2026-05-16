"""
Shared Application State
=========================
Central in-memory store shared across all route modules.
All routers import `_state` from here to read/write live data.

Also provides `_build_engine()` — constructs a DetectionEngine
from the persisted artefacts and the currently active model.
"""

from app.core.pipeline import (
    load_nsa, load_iso, load_preprocessor, load_self_boundary,
    load_pca_self_boundary,
)
from app.core.detection import DetectionEngine
from pathlib import Path
import json


SETTINGS_PATH = Path(__file__).parent / "artefacts" / "runtime_settings.json"


def _load_runtime_settings() -> dict:
    try:
        if SETTINGS_PATH.exists():
            with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def save_runtime_settings() -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "active_model": _state.get("active_model", "nsa"),
    }
    with SETTINGS_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


_runtime_settings = _load_runtime_settings()
_initial_active_model = _runtime_settings.get("active_model", "nsa")
if _initial_active_model not in {"nsa", "isolation_forest"}:
    _initial_active_model = "nsa"


# ── In-memory state ──────────────────────────────────────────────────────
_state: dict = {
    "status":         "idle",       # idle | learning | active | error
    "training_logs":  [],
    "alerts":         [],
    "last_result":    None,
    "active_model":   _initial_active_model,  # "nsa" or "isolation_forest"
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
    raw_sb = load_self_boundary()
    pca_sb = load_pca_self_boundary()
    return DetectionEngine(
        model, prep,
        active_model=_state["active_model"],
        self_boundary=raw_sb,
        pca_self_boundary=pca_sb,
    )
