"""
V-Detector Negative Selection Algorithm (NSA) — Artificial Immune System Core
================================================================================
Implements a **true** Negative Selection Algorithm using the V-Detector variant
(Ji & Dasgupta, 2004).  Each detector has a *variable radius* equal to its
distance to the nearest self sample minus a safety margin, so detectors
automatically expand to cover as much non-self space as possible.

Biological fidelity
--------------------
- **Thymus selection (training):** random candidates within ``r_s`` of self
  are deleted — only those that do NOT react to self survive.
- **Mature T-cell repertoire (detectors):** surviving detectors are the
  PRIMARY classification mechanism.  Each has its own activation radius.
- **Self-gap fallback:** samples far from all self AND all detectors are
  still flagged — analogous to innate immune response for truly novel threats.
- **Detector aging:** each detector tracks how many batches have passed
  since it last matched a sample.  Stale detectors can be replaced via
  ``refresh()`` to model finite T-cell lifespan.

Key parameters
--------------
- ``r_s`` — self-tolerance radius (thymus stringency).  Small value (e.g. 0.05)
  lets detectors get close to the self boundary for fine-grained coverage.
- ``r`` — self-gap detection threshold.  Samples further than ``r`` from ALL
  self reference points trigger the fallback (innate) response.
  *Decoupled from ``r_s``* to allow independent tuning.

Performance design
------------------
Same O(n_test × n_ref) squared-distance decomposition as before, plus a
second pass against the detector set with variable-radius comparison.
"""

import os

import joblib
import numpy as np

from app.models.nsa_calibration import NSACalibrationMixin
from app.models.nsa_config import (
    DEFAULT_FUSION_WEIGHTS,
    DISABLED_FUSION_CALIBRATION,
    MAX_DISTANCE_MATRIX_ENTRIES,
    MIN_COMPONENT_SCALES,
    PREDICT_CHUNK,
    SELF_REF_CAP,
)
from app.models.nsa_scoring import NSAScoringMixin
from app.models.nsa_training import NSATrainingMixin


class NegativeSelectionDetector(NSATrainingMixin, NSACalibrationMixin, NSAScoringMixin):
    """
    V-Detector Negative Selection Algorithm.

    Detectors are the PRIMARY classification mechanism.  Each detector has a
    variable activation radius (V-Detector), providing multi-scale coverage of
    the non-self space.  A self-gap fallback catches anomalies in regions not
    yet covered by any detector.

    Parameters
    ----------
    r : float
        Self-gap detection threshold — samples further than ``r`` (normalised
        Euclidean distance) from every self-reference point are flagged via
        the fallback path.  Also used as the default for ``r_s`` if ``r_s``
        is not specified.
    r_s : float or None
        Self-tolerance radius for negative selection (thymus stringency).
        Detector candidates within ``r_s`` of any self sample are deleted.
        Accepted detectors receive a variable radius =
        ``dist_to_nearest_self − r_s``.  If ``None``, defaults to
        ``min(r * 0.1, 0.05)`` — a small fraction of ``r``.
    max_detectors : int
        Maximum number of mature detectors to generate.
    max_attempts : int
        Maximum random candidates to try before stopping.
    random_state : int
        Reproducibility seed.
    """

    def __init__(
        self,
        r: float = 0.15,
        r_s: float | None = None,
        max_detectors: int = 3000,
        max_attempts: int = 100_000,
        random_state: int = 42,
        confidence_threshold: float = 0.05,
        auto_threshold: bool = True,
    ):
        self.r = r
        self.r_s = r_s if r_s is not None else min(r * 0.1, 0.05)
        self.max_detectors = max_detectors
        self.max_attempts = max_attempts
        self.random_state = random_state
        self.confidence_threshold = confidence_threshold
        self.auto_threshold = auto_threshold
        self.target_fpr = 0.10

        # Fitted state
        self.detectors_: np.ndarray | None = None
        self.det_radii_: np.ndarray | None = None        # V-Detector variable radii
        self._det_sq_: np.ndarray | None = None          # precomputed ||detectors||²
        self.self_samples_: np.ndarray | None = None     # full set (audit only)
        self.self_reference_: np.ndarray | None = None   # capped set for matching
        self._ref_sq_: np.ndarray | None = None          # precomputed ||ref||²
        self.n_features_: int | None = None
        self.is_fitted_: bool = False
        self.meta_: dict = {}
        self.score_threshold_: float | None = None
        self.score_scale_: float | None = None
        self.calibration_: dict = {}
        self.fusion_threshold_: float | None = None
        self.fusion_score_scale_: float | None = None
        self.fusion_weights_: dict = {}
        self.fusion_component_scales_: dict = {}
        self.fusion_calibration_: dict = {}

        # Detector aging — tracks staleness per detector
        self._det_match_counts_: np.ndarray | None = None   # lifetime match count
        self._det_idle_batches_: np.ndarray | None = None   # batches since last match

    @staticmethod
    def _chunk_size(n_ref: int, default: int = PREDICT_CHUNK) -> int:
        n_ref = max(int(n_ref), 1)
        return max(1, min(default, MAX_DISTANCE_MATRIX_ENTRIES // n_ref))

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError("Detector not fitted. Call fit() first.")
        self._ensure_compat()

    def _ensure_compat(self):
        """Populate fields missing from older persisted artifacts."""
        if not hasattr(self, "fusion_threshold_"):
            self.fusion_threshold_ = None
        if not hasattr(self, "fusion_score_scale_"):
            self.fusion_score_scale_ = None
        if not hasattr(self, "fusion_weights_"):
            self.fusion_weights_ = {}
        if not hasattr(self, "fusion_component_scales_"):
            self.fusion_component_scales_ = {}
        if not hasattr(self, "fusion_calibration_"):
            self.fusion_calibration_ = {}
        self._repair_pathological_self_gap_threshold()

    def _repair_pathological_self_gap_threshold(self):
        """
        Repair artifacts produced by the old max-distance fallback calibration.

        That bug set score_threshold_ to one extreme benign outlier whenever
        detector-only FPR exceeded target, disabling self-gap detection.
        """
        calibration = getattr(self, "calibration_", {}) or {}
        if calibration.get("mode") != "unsupervised_benign_pure_nsa":
            return

        try:
            threshold = float(self.score_threshold_)
            score_max = float(calibration.get("score_max"))
            score_p99 = float(calibration.get("score_p99"))
            score_p95 = float(calibration.get("score_p95"))
        except (TypeError, ValueError):
            return

        values = np.asarray([threshold, score_max, score_p99, score_p95], dtype=np.float64)
        if not np.isfinite(values).all():
            return
        if score_p95 <= 0.0 or threshold < score_max * 0.999:
            return

        outlier_floor = max(score_p99 * 20.0, score_p95 * 20.0, float(self.r) * 20.0, 1e-9)
        if score_max <= outlier_floor:
            return

        repaired_threshold = score_p95
        repaired_scale = max(score_p99, repaired_threshold * 1.5, repaired_threshold + 1e-9)
        self.score_threshold_ = repaired_threshold
        self.score_scale_ = repaired_scale
        calibration["threshold"] = round(float(repaired_threshold), 6)
        calibration["score_scale"] = round(float(repaired_scale), 6)
        calibration["target_achieved"] = False
        calibration["repair_note"] = (
            "Repaired from max-distance outlier threshold; use retraining to "
            "regenerate a clean calibration artifact."
        )
        self.calibration_ = calibration
        self.meta_["score_threshold"] = self.score_threshold_
        self.meta_["calibration"] = self.calibration_

    # ------------------------------------------------------------------ #
    #  PERSISTENCE                                                         #
    # ------------------------------------------------------------------ #

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> "NegativeSelectionDetector":
        return joblib.load(path)

    # ------------------------------------------------------------------ #
    #  REPRESENTATION                                                      #
    # ------------------------------------------------------------------ #

    def summary(self) -> dict:
        if not self.is_fitted_:
            return {"status": "not_fitted"}
        self._ensure_compat()
        return {
            "status": "fitted",
            **self.meta_,
            "score_threshold": self.score_threshold_,
            "fusion_threshold": getattr(self, "fusion_threshold_", None),
            "target_fpr": self.target_fpr,
            "calibration": self.calibration_,
            "fusion_calibration": getattr(self, "fusion_calibration_", {}),
            "fusion_weights": getattr(self, "fusion_weights_", {}),
            "fusion_component_scales": getattr(self, "fusion_component_scales_", {}),
            "active_antibodies": int(len(self.detectors_)) if self.detectors_ is not None else 0,
        }

    def __repr__(self):
        status = "fitted" if self.is_fitted_ else "unfitted"
        return (
            f"NegativeSelectionDetector("
            f"r={self.r}, r_s={self.r_s}, "
            f"max_detectors={self.max_detectors}, status={status})"
        )
