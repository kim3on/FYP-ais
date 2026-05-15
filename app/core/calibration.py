"""Calibration helpers for unsupervised anomaly thresholds."""

from __future__ import annotations

import math

import numpy as np


def calibration_reliability(n_samples: int) -> str:
    """Return a simple reliability label for benign calibration sample size."""
    if n_samples < 200:
        return "experimental"
    if n_samples < 1000:
        return "prototype"
    return "stable"


def conformal_threshold(
    scores: np.ndarray,
    target_fpr: float,
    *,
    min_threshold: float | None = None,
) -> dict:
    """
    Choose a benign-only conformal threshold for strict ``score > threshold``.

    For sorted benign scores s_(1) <= ... <= s_(n), choose
    k = ceil((n + 1) * (1 - alpha)), clamped to [1, n].
    """
    values = np.asarray(scores, dtype=np.float64)
    values = values[np.isfinite(values)]
    if len(values) == 0:
        raise ValueError("Cannot calibrate threshold without finite benign scores")

    alpha = float(np.clip(target_fpr, 0.0001, 0.5))
    sorted_scores = np.sort(values)
    n = len(sorted_scores)
    rank = int(math.ceil((n + 1) * (1.0 - alpha)))
    rank = max(1, min(rank, n))
    threshold = float(sorted_scores[rank - 1])
    if min_threshold is not None:
        threshold = max(threshold, float(min_threshold))

    observed_fpr = float((values > threshold).mean())
    return {
        "threshold": threshold,
        "target_fpr": alpha,
        "observed_fpr": observed_fpr,
        "normal_pass_rate": 1.0 - observed_fpr,
        "rank_index": rank,
        "rank_index_zero_based": rank - 1,
        "n_calibration_samples": int(n),
        "reliability": calibration_reliability(n),
    }
