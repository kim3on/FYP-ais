"""
Detection Router
=================
POST /api/detect             — batch anomaly detection on an uploaded log file
GET  /api/detect/logs        — poll detection log lines
GET  /api/detect/result      — last completed detection result
POST /api/detect/sample      — detect anomaly in a single JSON flow
"""

import traceback

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from typing import Optional
from datetime import datetime

from app.core.pipeline import models_ready
from app.state import _state, _build_engine

router = APIRouter(prefix="/api/detect", tags=["detection"])


@router.post("")
async def detect(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    limit: Optional[int] = None,
):
    """
    Upload a network log (CSV or Parquet) and run batch anomaly detection
    in the background.  Returns immediately; poll /api/detect/logs for
    progress and /api/detect/result for the final result.
    """
    if not models_ready():
        raise HTTPException(
            status_code=400,
            detail="Models not trained yet. Please upload a dataset and train first.",
        )
    if _state["detect_status"] == "running":
        raise HTTPException(status_code=409, detail="Detection already in progress")

    dataset_bytes   = await file.read()
    upload_filename = file.filename or ""

    _state["detect_status"]      = "running"
    _state["detect_logs"]        = []
    _state["last_detect_result"] = None

    _limit = int(limit) if limit else None

    def dlog(msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        _state["detect_logs"].append(f"[{ts}] {msg}")

    def run_detection():
        try:
            dlog("[DETECT] Starting batch detection...")
            dlog(f"[DETECT] File: {upload_filename or 'unknown'}")
            if _limit:
                dlog(f"[DETECT] Sample limit: {_limit:,} rows")

            engine = _build_engine()
            dlog(f"[DETECT] Model: {_state['active_model'].upper()}")
            dlog("[DETECT] Loading and preprocessing file...")

            result = engine.detect_from_csv(
                dataset_bytes, limit=_limit, filename=upload_filename
            )

            _state["alerts"].extend(result["alerts"])
            _state["packet_count"]  += result["total_checked"]
            _state["anomaly_count"] += result["anomalies_found"]
            _state["last_detect_result"] = result
            _state["detect_status"] = "done"

            if result["alerts"]:
                from app.core.database import SessionLocal
                from app.models.db_models import AlertDB
                db = SessionLocal()
                try:
                    db_alerts = []
                    for a in result["alerts"]:
                        db_alerts.append(AlertDB(
                            alert_id=a["alert_id"],
                            timestamp=a["timestamp"],
                            attack_type=a["attack_type"],
                            src_ip=a.get("src_ip", "N/A"),
                            dst_ip=a.get("dst_ip", "N/A"),
                            dst_port=int(a.get("dst_port", 0) or 0),
                            protocol=a.get("protocol", "N/A"),
                            severity=a["severity"],
                            confidence=a["confidence"],
                            confidence_pct=a["confidence_pct"],
                            is_false_positive=False,
                            is_zero_day=a["is_zero_day"],
                            raw_features=a.get("raw_features", {})
                        ))
                    db.add_all(db_alerts)
                    db.commit()
                except Exception as e:
                    dlog(f"[ERROR] DB Save failed: {e}")
                    db.rollback()
                finally:
                    db.close()

            dlog(f"[OK] Checked {result['total_checked']:,} flows.")
            dlog(
                f"[OK] Anomalies found: {result['anomalies_found']:,}  "
                f"({result.get('detection_rate_pct', 0):.1f}%)"
            )
            sev = result.get("severity_counts", {})
            dlog(
                f"[OK] Severity — Critical: {sev.get('critical',0)}  "
                f"High: {sev.get('high',0)}  "
                f"Medium: {sev.get('medium',0)}  "
                f"Low: {sev.get('low',0)}"
            )
            dlog("[COMPLETE] Detection finished.")

        except Exception as e:
            _state["detect_status"] = "error"
            dlog(f"[ERROR] Detection failed: {e}")
            dlog(traceback.format_exc())

    background_tasks.add_task(run_detection)
    return {"message": "Detection started", "status": "running"}


@router.get("/logs")
async def detect_logs():
    """Poll detection log lines and current status."""
    return {
        "logs":   _state["detect_logs"],
        "status": _state["detect_status"],
    }


@router.get("/result")
async def detect_result():
    """Return the last completed detection result."""
    if _state["last_detect_result"] is not None:
        return _state["last_detect_result"]
    raise HTTPException(status_code=404, detail="No detection result yet")


@router.post("/sample")
async def detect_sample(features: dict):
    """
    Detect anomaly in a single network flow (JSON body = feature dict).
    Useful for real-time per-packet monitoring from a packet sniffer.
    """
    if not models_ready():
        raise HTTPException(status_code=400, detail="Models not trained")

    engine = _build_engine()
    result = engine.detect_sample(features)
    _state["packet_count"] += 1
    if result["anomalies_found"] > 0:
        _state["alerts"].extend(result["alerts"])
        _state["anomaly_count"] += result["anomalies_found"]
    return result
