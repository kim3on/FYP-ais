"""
Training Router
================
POST /api/train              — upload dataset and start background training
GET  /api/train/logs         — poll training log lines
GET  /api/train/result       — retrieve last training result
"""

import json
import os
import traceback
from datetime import datetime
import numpy as np

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile, Depends
from fastapi.responses import Response

from app.core.pipeline import (
    MAX_DAE_LATENT_DIM,
    MAX_DAE_NOISE_STD,
    MAX_BENIGN_ROW_LIMIT,
    MAX_ISO_ESTIMATORS,
    MAX_TRAINING_ATTEMPTS,
    MAX_TRAINING_DETECTORS,
    MIN_DAE_LATENT_DIM,
    MIN_DAE_NOISE_STD,
    MIN_BENIGN_ROWS_HARD,
    MIN_ISO_ESTIMATORS,
    MIN_TRAINING_DETECTORS,
    TrainingPipeline,
    load_nsa,
    result_path,
)
from app.core.datasets import DATASET_CICIDS2017, DATASET_NSL_KDD, normalize_dataset_type
from app.core.preprocessor import (
    DEFAULT_DAE_LATENT_DIM,
    DEFAULT_DAE_NOISE_STD,
    REPRESENTATION_DAE,
    REPRESENTATION_PCA,
    normalize_representation,
)
from app.core.training_runs import (
    extract_training_run_record,
    list_training_run_records,
    training_records_to_csv,
)
from app.state import _state, save_runtime_settings
from app.routers.auth import get_current_user

router = APIRouter(
    prefix="/api/train",
    tags=["training"],
    dependencies=[Depends(get_current_user)]
)


@router.post("")
async def train(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    r:              float = 0.3,
    r_s:            float | None = None,
    max_detectors:  int   = 3000,
    max_attempts:   int   = 100_000,
    contamination:  float = 0.05,
    iso_n_estimators: int = 100,
    test_size:      float = 0.2,
    n_pca_components: int | None = 25,
    target_fpr:     float = 0.10,
    benign_row_limit: int | None = 20_000,
    dataset_type:    str = DATASET_CICIDS2017,
    representation:  str = REPRESENTATION_PCA,
    dae_latent_dim:  int = DEFAULT_DAE_LATENT_DIM,
    dae_noise_std:   float = DEFAULT_DAE_NOISE_STD,
):
    """
    Upload a training dataset (CSV or Parquet) and start the training pipeline.
    Training runs in the background; poll /api/train/logs for progress.

    Config params (query string or form fields):
      r              — Self-gap detection threshold  (default 0.3)
      r_s            — V-Detector self-tolerance     (default: auto from r)
      max_detectors  — max mature V-detectors        (default 3 000)
      max_attempts   — max candidate gen attempts    (default 100 000)
      contamination  — IsoForest contamination       (default 0.05)
      iso_n_estimators — IsoForest trees             (default 100)
      target_fpr     — target benign false-positive rate for calibration (default 0.10)
      test_size      — train/test split fraction     (default 0.2)
      representation — pca or dae; dae is CICIDS2017-only experimental mode
    """
    if _state["status"] == "learning":
        raise HTTPException(status_code=409, detail="Training already in progress")

    try:
        _dataset_type = normalize_dataset_type(dataset_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        _representation = normalize_representation(representation)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if _dataset_type == DATASET_NSL_KDD and _representation == REPRESENTATION_DAE:
        raise HTTPException(
            status_code=400,
            detail="Denoising AE representation is supported only for CICIDS2017",
        )

    fname = (file.filename or "").lower()
    allowed_exts = (".csv",) if _dataset_type == DATASET_NSL_KDD else ('.csv', '.parquet', '.pq', '')
    if not any(fname.endswith(ext) for ext in allowed_exts):
        expected = ".csv" if _dataset_type == DATASET_NSL_KDD else ".csv or .parquet"
        raise HTTPException(status_code=400, detail=f"Only {expected} files accepted")

    dataset_bytes     = await file.read()
    upload_filename   = file.filename or ""
    _state["status"]  = "learning"
    _state["training_logs"] = []

    def log_cb(msg: str):
        _state["training_logs"].append(msg)

    # Capture config values into closure
    _r             = float(np.clip(r, 0.01, 5.0))
    _r_s           = float(np.clip(r_s, 0.01, 5.0)) if r_s is not None else None
    _max_detectors = int(np.clip(max_detectors, MIN_TRAINING_DETECTORS, MAX_TRAINING_DETECTORS))
    _max_attempts  = int(np.clip(max_attempts, _max_detectors, MAX_TRAINING_ATTEMPTS))
    _contamination = float(np.clip(contamination, 0.001, 0.20))
    _iso_n_estimators = int(np.clip(iso_n_estimators, MIN_ISO_ESTIMATORS, MAX_ISO_ESTIMATORS))
    _test_size     = float(np.clip(test_size, 0.10, 0.40))
    _n_pca         = int(n_pca_components) if n_pca_components is not None else None
    _target_fpr    = float(np.clip(target_fpr, 0.01, 0.20))
    _dae_latent_dim = int(np.clip(dae_latent_dim, MIN_DAE_LATENT_DIM, MAX_DAE_LATENT_DIM))
    _dae_noise_std = float(np.clip(dae_noise_std, MIN_DAE_NOISE_STD, MAX_DAE_NOISE_STD))
    _benign_row_limit = (
        int(np.clip(benign_row_limit, MIN_BENIGN_ROWS_HARD, MAX_BENIGN_ROW_LIMIT))
        if benign_row_limit and benign_row_limit > 0
        else None
    )

    def run_training():
        try:
            pipeline = TrainingPipeline(
                r=_r,
                r_s=_r_s,
                max_detectors=_max_detectors,
                max_attempts=_max_attempts,
                contamination=_contamination,
                iso_n_estimators=_iso_n_estimators,
                test_size=_test_size,
                n_pca_components=_n_pca,
                target_fpr=_target_fpr,
                benign_row_limit=_benign_row_limit,
                dataset_type=_dataset_type,
                representation=_representation,
                dae_latent_dim=_dae_latent_dim,
                dae_noise_std=_dae_noise_std,
            )
            result = pipeline.run(dataset_bytes, log_callback=log_cb, filename=upload_filename)
            _state["last_result"] = result
            _state["active_dataset_type"] = _dataset_type
            _state["status"] = "active"
            save_runtime_settings()
        except Exception as e:
            _state["status"] = "error"
            _state["training_logs"].append(f"[ERROR] Training failed: {e}")
            _state["training_logs"].append(traceback.format_exc())

    background_tasks.add_task(run_training)
    return {
        "message": "Training started",
        "status":  "learning",
        "config": {
            "r":             _r,
            "r_s":           _r_s,
            "max_detectors": _max_detectors,
            "max_attempts":  _max_attempts,
            "contamination": _contamination,
            "iso_n_estimators": _iso_n_estimators,
            "test_size":     _test_size,
            "n_pca_components": _n_pca,
            "benign_row_limit": _benign_row_limit,
            "target_fpr": _target_fpr,
            "dataset_type": _dataset_type,
            "representation": _representation,
            "dae_latent_dim": _dae_latent_dim,
            "dae_noise_std": _dae_noise_std,
        },
    }


@router.get("/logs")
async def training_logs():
    """Stream the current training log lines."""
    return {"logs": _state["training_logs"], "status": _state["status"]}


@router.get("/result")
async def training_result(dataset_type: str | None = None):
    """Return the last completed training result."""
    selected = dataset_type or _state.get("active_dataset_type", DATASET_CICIDS2017)
    if _state["last_result"] and (
        dataset_type is None
        or _state["last_result"].get("dataset_type") == normalize_dataset_type(selected)
    ):
        return _attach_comparison_record(_sync_repaired_nsa_calibration(_state["last_result"], selected))

    path = result_path(selected)
    if os.path.exists(path):
        with open(path) as f:
            return _attach_comparison_record(_sync_repaired_nsa_calibration(json.load(f), selected))

    raise HTTPException(status_code=404, detail="No training result available yet")


@router.get("/runs")
async def training_runs(dataset_type: str | None = None, limit: int = 20):
    """Return compact training-run records for NSA/IsoFor comparison."""
    selected = normalize_dataset_type(dataset_type) if dataset_type else None
    records = _training_run_records_with_latest_fallback(selected, limit)
    return {
        "runs": records,
        "dataset_type": selected,
        "limit": max(1, min(int(limit or 20), 200)),
    }


@router.get("/runs/export.csv")
async def training_runs_export(dataset_type: str | None = None, limit: int = 200):
    """Export compact training-run comparison records as CSV."""
    selected = normalize_dataset_type(dataset_type) if dataset_type else None
    records = _training_run_records_with_latest_fallback(selected, limit)
    csv_text = training_records_to_csv(records)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dataset_part = selected or "all"
    return Response(
        content="\ufeff" + csv_text,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="training_runs_{dataset_part}_{stamp}.csv"'
        },
    )


def _attach_comparison_record(result: dict) -> dict:
    if not isinstance(result, dict):
        return result
    if result.get("comparison_record"):
        return result
    synced = dict(result)
    synced["comparison_record"] = extract_training_run_record(synced)
    return synced


def _training_run_records_with_latest_fallback(dataset_type: str | None, limit: int) -> list[dict]:
    records = list_training_run_records(dataset_type, limit)
    if records:
        return records
    selected = dataset_type or _state.get("active_dataset_type", DATASET_CICIDS2017)
    path = result_path(selected)
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            latest = _attach_comparison_record(json.load(f))
    except Exception:
        return []
    return [latest["comparison_record"]]


def _sync_repaired_nsa_calibration(result: dict, dataset_type: str | None) -> dict:
    """Reflect runtime repair of old pathological NSA thresholds in result JSON."""
    if not isinstance(result, dict):
        return result

    try:
        nsa = load_nsa(normalize_dataset_type(dataset_type))
        summary = nsa.summary() if nsa else {}
    except Exception:
        return result

    calibration = summary.get("calibration") or {}
    if not calibration.get("repair_note"):
        return result

    synced = dict(result)
    nsa_summary = dict(synced.get("nsa_summary") or {})
    nsa_summary["score_threshold"] = summary.get("score_threshold")
    nsa_summary["calibration"] = calibration
    synced["nsa_summary"] = nsa_summary

    for key in ("calibration_summary", "nsa_calibration_summary"):
        existing = synced.get(key)
        if isinstance(existing, dict):
            patched = dict(existing)
            patched.update({
                "threshold": calibration.get("threshold"),
                "score_scale": calibration.get("score_scale"),
                "target_achieved": calibration.get("target_achieved"),
                "repair_note": calibration.get("repair_note"),
            })
            synced[key] = patched

    return synced
