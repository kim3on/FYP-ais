"""
Detection Router
=================
POST /api/detect             — batch anomaly detection on an uploaded log file
GET  /api/detect/logs        — poll detection log lines
GET  /api/detect/result      — last completed detection result
POST /api/detect/sample      — detect anomaly in a single JSON flow
"""

import traceback

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile, Depends
from typing import Optional
from datetime import datetime

from app.core.pipeline import engine_ready
from app.core.datasets import DATASET_CICIDS2017, normalize_dataset_type
from app.state import _state, _build_engine
from app.routers.auth import get_current_user, require_admin_user

router = APIRouter(
    prefix="/api/detect",
    tags=["detection"],
    dependencies=[Depends(get_current_user)]
)


@router.post("")
async def detect(
    background_tasks: BackgroundTasks,
    user=Depends(require_admin_user),
    file: UploadFile = File(...),
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    dataset_type: str = DATASET_CICIDS2017,
    limit_form: Optional[int] = Form(None, alias="limit"),
    offset_form: Optional[int] = Form(None, alias="offset"),
):
    """
    Upload a network log (CSV or Parquet) and run batch anomaly detection
    in the background.  Returns immediately; poll /api/detect/logs for
    progress and /api/detect/result for the final result.
    """
    try:
        _dataset_type = normalize_dataset_type(dataset_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not engine_ready(_state["active_model"], _dataset_type):
        raise HTTPException(
            status_code=400,
            detail=f"{_state['active_model']} is not ready for {_dataset_type}. Please train or select a matching model first.",
        )
    if _state["detect_status"] == "running":
        raise HTTPException(status_code=409, detail="Detection already in progress")

    dataset_bytes   = await file.read()
    upload_filename = file.filename or ""
    if _dataset_type != DATASET_CICIDS2017 and not upload_filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="NSL-KDD detection accepts CSV-with-headers files only")

    _state["detect_status"]      = "running"
    _state["detect_logs"]        = []
    _state["last_detect_result"] = None

    raw_limit = limit if limit is not None else limit_form
    raw_offset = offset if offset is not None else offset_form
    _limit = int(raw_limit) if raw_limit else None
    _offset = max(int(raw_offset), 0) if raw_offset else 0

    def dlog(msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        _state["detect_logs"].append(f"[{ts}] {msg}")

    def run_detection():
        try:
            dlog("[DETECT] Starting batch detection...")
            dlog(f"[DETECT] File: {upload_filename or 'unknown'}")
            if _limit:
                dlog(f"[DETECT] Sample limit: {_limit:,} rows")
            if _offset:
                dlog(f"[DETECT] Start row offset: {_offset:,}")

            engine = _build_engine(_dataset_type)
            dlog(f"[DETECT] Dataset: {_dataset_type}")
            dlog(f"[DETECT] Model: {_state['active_model'].upper()}")
            dlog(f"[DETECT] Trained target FPR: {engine.trained_target_fpr * 100:.1f}%")
            dlog("[DETECT] Loading and preprocessing file...")

            result = engine.detect_from_csv(
                dataset_bytes,
                limit=_limit,
                offset=_offset,
                filename=upload_filename,
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
                        # Safely convert dst_port to int, defaulting to 0 if 'N/A' or invalid
                        try:
                            dst_port = int(a.get("dst_port", 0) or 0)
                        except (ValueError, TypeError):
                            dst_port = 0

                        db_alerts.append(AlertDB(
                            alert_id=a["alert_id"],
                            timestamp=a["timestamp"],
                            attack_type=a["attack_type"],
                            src_ip=a.get("src_ip", "N/A"),
                            dst_ip=a.get("dst_ip", "N/A"),
                            dst_port=dst_port,
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
async def detect_sample(features: dict, user=Depends(require_admin_user)):
    """
    Detect anomaly in a single network flow (JSON body = feature dict).
    Useful for real-time per-packet monitoring from a packet sniffer.
    """
    if _state.get("active_dataset_type") != DATASET_CICIDS2017:
        raise HTTPException(
            status_code=400,
            detail="Live/sample detection is CICIDS2017-only. Train or select a CICIDS2017 model for live capture.",
        )

    if not engine_ready(_state["active_model"], DATASET_CICIDS2017):
        raise HTTPException(status_code=400, detail=f"{_state['active_model']} model is not trained")

    engine = _build_engine(DATASET_CICIDS2017)
    result = engine.detect_sample(features)
    _state["packet_count"] += 1
    if result["anomalies_found"] > 0:
        _state["alerts"].extend(result["alerts"])
        _state["anomaly_count"] += result["anomalies_found"]
    return result
