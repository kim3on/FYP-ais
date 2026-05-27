"""
Compact training-run extraction and history logging.

The full training result stays as the latest detailed artifact. This module
creates a small append-only record that is easier to compare across runs.
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Iterable

from app.core.datasets import ARTEFACT_DIR, normalize_dataset_type


TRAINING_RUNS_PATH = os.path.join(ARTEFACT_DIR, "training_runs.jsonl")


def _safe_get(mapping: dict | None, *path, default=None):
    current = mapping or {}
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def _round_float(value, digits: int = 6):
    try:
        if value is None:
            return None
        return round(float(value), digits)
    except (TypeError, ValueError):
        return None


def _labelled_metrics(metrics: dict | None) -> dict:
    metrics = metrics or {}
    if not metrics.get("available"):
        return {"available": False}
    keys = (
        "recall",
        "true_positive_rate",
        "false_negative_rate",
        "false_positive_rate",
        "precision",
        "f1",
        "accuracy",
        "tp",
        "fn",
        "fp",
        "tn",
        "n_eval_attacks_used",
        "n_eval_benign_used",
        "verification_mode",
        "verification_only",
    )
    extracted = {"available": True}
    for key in keys:
        value = metrics.get(key)
        extracted[key] = _round_float(value, 6) if isinstance(value, float) else value
    return extracted


def _nsa_record(result: dict) -> dict:
    summary = result.get("nsa_summary") or {}
    calibration = result.get("nsa_calibration_summary") or result.get("calibration_summary") or summary.get("calibration") or {}
    eval_ = result.get("nsa_eval") or {}
    return {
        "config": {
            "max_detectors": summary.get("max_detectors"),
            "max_attempts": summary.get("max_attempts"),
        },
        "mature_detectors": summary.get("mature_detectors"),
        "self_samples": summary.get("n_self_samples"),
        "fitted_r": _round_float(summary.get("r_fitted", summary.get("r"))),
        "fitted_r_s": _round_float(summary.get("r_s_fitted", summary.get("r_s"))),
        "threshold": _round_float(calibration.get("threshold", summary.get("score_threshold"))),
        "score_scale": _round_float(calibration.get("score_scale", summary.get("score_scale"))),
        "observed_benign_fpr": _round_float(calibration.get("observed_fpr", eval_.get("false_positive_rate"))),
        "normal_pass_rate": _round_float(calibration.get("normal_pass_rate")),
        "self_intrusion_rate": _round_float(_safe_get(result, "ais_metrics", "self_intrusion_rate", default=eval_.get("self_intrusion_rate"))),
        "silhouette": _round_float(_safe_get(eval_, "silhouette", "value", default=eval_.get("silhouette_score"))),
        "labelled_verification": _labelled_metrics(result.get("post_run_labelled_verification")),
    }


def _iso_record(result: dict) -> dict:
    summary = result.get("iso_summary") or {}
    calibration = result.get("iso_calibration_summary") or summary.get("threshold_calibration") or {}
    eval_ = result.get("iso_eval") or {}
    return {
        "config": {
            "contamination": _round_float(summary.get("contamination")),
            "n_estimators": summary.get("n_estimators"),
        },
        "contamination": _round_float(summary.get("contamination")),
        "estimators": summary.get("n_estimators"),
        "training_samples": summary.get("n_training_samples"),
        "threshold": _round_float(calibration.get("threshold", summary.get("score_threshold"))),
        "score_scale": _round_float(calibration.get("score_scale", summary.get("score_scale"))),
        "observed_benign_fpr": _round_float(calibration.get("observed_fpr", eval_.get("false_positive_rate"))),
        "normal_pass_rate": _round_float(calibration.get("normal_pass_rate")),
        "silhouette": _round_float(_safe_get(eval_, "silhouette", "value", default=eval_.get("silhouette_score"))),
        "labelled_verification": _labelled_metrics(result.get("iso_post_run_labelled_verification")),
    }


def extract_training_run_record(result: dict) -> dict:
    dataset_type = normalize_dataset_type(result.get("dataset_type"))
    split_sizes = result.get("split_sizes") or {}
    validation = result.get("validation_stats") or {}
    pca_components = result.get("pca_components")
    feature_count = result.get("feature_count", validation.get("n_features"))
    if pca_components is None:
        pca_components = _safe_get(result, "nsa_summary", "n_features", default=_safe_get(result, "iso_summary", "n_features"))
    return {
        "run_id": result.get("run_id"),
        "trained_at": result.get("trained_at"),
        "dataset_type": dataset_type,
        "dataset_display": result.get("dataset_display"),
        "duration_seconds": result.get("duration_seconds"),
        "target_fpr": _round_float(_safe_get(result, "nsa_calibration_summary", "target_fpr", default=_safe_get(result, "calibration_summary", "target_fpr"))),
        "benign_rows_available": result.get("benign_rows_available"),
        "benign_rows_used": result.get("benign_rows_used"),
        "benign_row_limit": result.get("benign_row_limit"),
        "feature_count": feature_count,
        "pca_components": pca_components,
        "split_sizes": {
            "benign_train": split_sizes.get("benign_train"),
            "benign_calibration": split_sizes.get("benign_calibration"),
            "benign_test": split_sizes.get("benign_test"),
            "attack_rows_available": split_sizes.get("attack_rows_available"),
        },
        "model_configs": result.get("model_configs") or {},
        "models": {
            "nsa": _nsa_record(result),
            "isolation_forest": _iso_record(result),
        },
        "verification_mode": "post_run_labelled_verification",
        "verification_only": True,
    }


def append_training_run_record(result: dict) -> dict:
    record = extract_training_run_record(result)
    os.makedirs(os.path.dirname(TRAINING_RUNS_PATH), exist_ok=True)
    with open(TRAINING_RUNS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n")
    return record


def list_training_run_records(dataset_type: str | None = None, limit: int = 20) -> list[dict]:
    selected = normalize_dataset_type(dataset_type) if dataset_type else None
    limit = max(1, min(int(limit or 20), 200))
    if not os.path.exists(TRAINING_RUNS_PATH):
        return []
    records: list[dict] = []
    with open(TRAINING_RUNS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if selected and record.get("dataset_type") != selected:
                continue
            records.append(record)
    return records[-limit:][::-1]


def training_records_to_csv(records: Iterable[dict]) -> str:
    fields = [
        "run_id",
        "trained_at",
        "dataset_type",
        "duration_seconds",
        "target_fpr",
        "benign_rows_used",
        "feature_count",
        "pca_components",
        "nsa_mature_detectors",
        "nsa_observed_benign_fpr",
        "nsa_normal_pass_rate",
        "nsa_silhouette",
        "nsa_label_recall",
        "nsa_label_f1",
        "iso_estimators",
        "iso_contamination",
        "iso_observed_benign_fpr",
        "iso_normal_pass_rate",
        "iso_silhouette",
        "iso_label_recall",
        "iso_label_f1",
    ]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for record in records:
        nsa = _safe_get(record, "models", "nsa", default={})
        iso = _safe_get(record, "models", "isolation_forest", default={})
        writer.writerow({
            "run_id": record.get("run_id"),
            "trained_at": record.get("trained_at"),
            "dataset_type": record.get("dataset_type"),
            "duration_seconds": record.get("duration_seconds"),
            "target_fpr": record.get("target_fpr"),
            "benign_rows_used": record.get("benign_rows_used"),
            "feature_count": record.get("feature_count"),
            "pca_components": record.get("pca_components"),
            "nsa_mature_detectors": nsa.get("mature_detectors"),
            "nsa_observed_benign_fpr": nsa.get("observed_benign_fpr"),
            "nsa_normal_pass_rate": nsa.get("normal_pass_rate"),
            "nsa_silhouette": nsa.get("silhouette"),
            "nsa_label_recall": _safe_get(nsa, "labelled_verification", "recall"),
            "nsa_label_f1": _safe_get(nsa, "labelled_verification", "f1"),
            "iso_estimators": iso.get("estimators"),
            "iso_contamination": iso.get("contamination"),
            "iso_observed_benign_fpr": iso.get("observed_benign_fpr"),
            "iso_normal_pass_rate": iso.get("normal_pass_rate"),
            "iso_silhouette": iso.get("silhouette"),
            "iso_label_recall": _safe_get(iso, "labelled_verification", "recall"),
            "iso_label_f1": _safe_get(iso, "labelled_verification", "f1"),
        })
    return out.getvalue()
