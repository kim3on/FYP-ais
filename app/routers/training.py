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
import numpy as np

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile, Depends

from app.core.pipeline import (
    MAX_BENIGN_ROW_LIMIT,
    MAX_TRAINING_ATTEMPTS,
    MAX_TRAINING_DETECTORS,
    MIN_BENIGN_ROWS_HARD,
    MIN_TRAINING_DETECTORS,
    RESULTS_PATH,
    TrainingPipeline,
)
from app.state import _state
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
    max_detectors:  int   = 1500,
    max_attempts:   int   = 40_000,
    contamination:  float = 0.05,
    test_size:      float = 0.2,
    n_pca_components: int | None = 25,
    target_fpr:     float = 0.05,
    benign_row_limit: int | None = 20_000,
):
    """
    Upload a training dataset (CSV or Parquet) and start the training pipeline.
    Training runs in the background; poll /api/train/logs for progress.

    Config params (query string or form fields):
      r              — Self-gap detection threshold  (default 0.3)
      r_s            — V-Detector self-tolerance     (default: auto from r)
      max_detectors  — max mature V-detectors        (default 1 500)
      max_attempts   — max candidate gen attempts    (default 40 000)
      contamination  — IsoForest contamination       (default 0.05)
      test_size      — train/test split fraction     (default 0.2)
    """
    if _state["status"] == "learning":
        raise HTTPException(status_code=409, detail="Training already in progress")

    fname = (file.filename or "").lower()
    if not any(fname.endswith(ext) for ext in ('.csv', '.parquet', '.pq', '')):
        raise HTTPException(status_code=400, detail="Only .csv or .parquet files accepted")

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
    _test_size     = float(np.clip(test_size, 0.10, 0.40))
    _n_pca         = int(n_pca_components) if n_pca_components is not None else None
    _target_fpr    = float(np.clip(target_fpr, 0.01, 0.20))
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
                test_size=_test_size,
                n_pca_components=_n_pca,
                target_fpr=_target_fpr,
                benign_row_limit=_benign_row_limit,
            )
            result = pipeline.run(dataset_bytes, log_callback=log_cb, filename=upload_filename)
            _state["last_result"] = result
            _state["status"] = "active"
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
            "test_size":     _test_size,
            "n_pca_components": _n_pca,
            "benign_row_limit": _benign_row_limit,
        },
    }


@router.get("/logs")
async def training_logs():
    """Stream the current training log lines."""
    return {"logs": _state["training_logs"], "status": _state["status"]}


@router.get("/result")
async def training_result():
    """Return the last completed training result."""
    if _state["last_result"]:
        return _state["last_result"]

    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            return json.load(f)

    raise HTTPException(status_code=404, detail="No training result available yet")
