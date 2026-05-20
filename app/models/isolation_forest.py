"""
Isolation Forest Baseline Model
================================
Wraps sklearn's IsolationForest to match the same interface as the NSA
detector, so both models can be swapped transparently in the pipeline.

Used as:
  - An unsupervised BENIGN-only performance BENCHMARK against the AIS/NSA model.
  - An alternative detection engine selectable from the Settings page.

The Isolation Forest works by randomly isolating data points in a tree
structure.  Anomalies are points that require fewer splits to isolate
(they are naturally "different" from the majority).
"""

import numpy as np
import joblib
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest as _IsolationForest

from app.core.calibration import conformal_threshold


class IsolationForestDetector:
    """
    Isolation Forest anomaly detector with the same fit/predict interface
    as NegativeSelectionDetector.

    Parameters
    ----------
    contamination : float
        scikit-learn fallback contamination. In AIS-Detect, the primary
        decision threshold is calibrated from BENIGN calibration rows only.
    n_estimators : int
        Number of base estimators (trees) in the ensemble.
    random_state : int
        Reproducibility seed.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._model = _IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted_: bool = False
        self.meta_: dict = {}
        self.score_calibration_: dict = {}
        self.score_threshold_: float | None = None
        self.threshold_calibration_: dict = {}
        self.score_scale_: float | None = None

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        """
        Train on BENIGN/self traffic only.

        Attack labels are not used for fitting or threshold selection. The
        sklearn contamination setting is retained only as a legacy fallback
        until calibrate_threshold() is called.

        Parameters
        ----------
        X : ndarray (n_samples, n_features) — normalised features
        """
        self._model.fit(X)
        self.is_fitted_ = True
        train_raw = -self._model.decision_function(X)
        finite = train_raw[np.isfinite(train_raw)]
        if len(finite) == 0:
            score_min, score_max = 0.0, 1.0
        else:
            score_min = float(np.quantile(finite, 0.01))
            score_max = float(np.quantile(finite, 0.99))
            if score_max <= score_min:
                score_min = float(finite.min())
                score_max = float(finite.max())
            if score_max <= score_min:
                score_max = score_min + 1e-9
        self.score_calibration_ = {
            "mode": "train_distribution_fixed_minmax",
            "raw_anomaly_min": score_min,
            "raw_anomaly_max": score_max,
            "decision_rule": "confidence normalization only; labels use sklearn predict",
        }
        self.score_scale_ = score_max

        self.meta_ = {
            "algorithm": "Isolation Forest",
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "n_training_samples": len(X),
            "n_features": X.shape[1],
            "score_calibration": self.score_calibration_,
            "threshold_calibration": self.threshold_calibration_,
            "score_threshold": self.score_threshold_,
            "trained_at": datetime.utcnow().isoformat(),
        }
        return self

    def calibrate_threshold(
        self,
        X_benign_calibration: np.ndarray,
        target_fpr: float = 0.05,
    ) -> dict:
        """Calibrate the IF decision threshold from BENIGN rows only."""
        self._check_fitted()
        scores = self.raw_anomaly_scores(X_benign_calibration)
        if len(scores) == 0:
            raise ValueError("Cannot calibrate Isolation Forest without benign rows")

        threshold_info = conformal_threshold(scores, target_fpr)
        threshold = float(threshold_info["threshold"])
        observed_fpr = float(threshold_info["observed_fpr"])
        finite = scores[np.isfinite(scores)]
        high = float(np.quantile(finite, 0.999)) if len(finite) else threshold

        self.score_threshold_ = threshold
        self.score_scale_ = max(high, threshold * 1.5, threshold + 1e-9)
        self.threshold_calibration_ = {
            "mode": "unsupervised_benign_isolation_forest",
            "score_mode": "isolation_forest_raw_anomaly_score",
            "target_fpr": round(float(threshold_info["target_fpr"]), 6),
            "observed_fpr": round(observed_fpr, 6),
            "normal_pass_rate": round(float(threshold_info["normal_pass_rate"]), 6),
            "threshold": round(threshold, 6),
            "score_scale": round(float(self.score_scale_), 6),
            "n_calibration_samples": int(threshold_info["n_calibration_samples"]),
            "rank_index": int(threshold_info["rank_index"]),
            "rank_index_zero_based": int(threshold_info["rank_index_zero_based"]),
            "calibration_reliability": threshold_info["reliability"],
            "decision_rule": "raw_anomaly_score > threshold",
            "score_min": round(float(finite.min()), 6) if len(finite) else 0.0,
            "score_median": round(float(np.median(finite)), 6) if len(finite) else 0.0,
            "score_p95": round(float(np.quantile(finite, 0.95)), 6) if len(finite) else 0.0,
            "score_p99": round(float(np.quantile(finite, 0.99)), 6) if len(finite) else 0.0,
            "score_max": round(float(finite.max()), 6) if len(finite) else 0.0,
        }
        self.meta_["score_threshold"] = self.score_threshold_
        self.meta_["score_scale"] = self.score_scale_
        self.meta_["threshold_calibration"] = self.threshold_calibration_
        return self.threshold_calibration_

    # ------------------------------------------------------------------ #
    #  DETECTION                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _runtime_threshold_factor(alert_threshold: float | None) -> float:
        if alert_threshold is None:
            return 1.0
        try:
            return max(float(alert_threshold), 1e-9) / 0.50
        except (TypeError, ValueError):
            return 1.0

    def _runtime_threshold_and_scale(self, alert_threshold: float | None) -> tuple[float, float]:
        threshold = float(self.score_threshold_)
        factor = self._runtime_threshold_factor(alert_threshold)
        adjusted_threshold = threshold * factor
        scale = float(self.score_scale_ or threshold * 1.5) * factor
        return adjusted_threshold, max(scale, adjusted_threshold + 1e-9)

    def predict(self, X: np.ndarray, alert_threshold: float | None = None) -> np.ndarray:
        """
        Returns labels: 0 = normal, 1 = anomaly.
        (sklearn returns +1 for normal, -1 for anomaly — we invert this.)
        """
        self._check_fitted()
        if self.score_threshold_ is not None:
            threshold, _ = self._runtime_threshold_and_scale(alert_threshold)
            return (self.raw_anomaly_scores(X) > threshold).astype(int)
        raw = self._model.predict(X)          # +1 normal, -1 anomaly
        return np.where(raw == -1, 1, 0).astype(int)

    def predict_with_scores(
        self,
        X: np.ndarray,
        alert_threshold: float | None = None,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores).
        Score is in [0, 1], higher = more anomalous.
        """
        self._check_fitted()
        raw_anomaly = self.raw_anomaly_scores(X)
        labels = self.predict(X, alert_threshold=alert_threshold)

        # Use fixed calibration ranges so confidence does not change with batch
        # composition. If a benign threshold is available, confidence is scaled
        # around that threshold to match the IDS decision rule.
        if self.score_threshold_ is not None:
            threshold, scale = self._runtime_threshold_and_scale(alert_threshold)
            scores = np.clip(
                (raw_anomaly - threshold) / max(scale - threshold, 1e-9),
                0.0,
                1.0,
            )
            scores = np.where(labels == 1, scores, 0.0)
            return labels, scores.round(4)

        cal = getattr(self, "score_calibration_", {}) or {}
        lo = float(cal.get("raw_anomaly_min", np.min(raw_anomaly) if len(raw_anomaly) else 0.0))
        hi = float(cal.get("raw_anomaly_max", np.max(raw_anomaly) if len(raw_anomaly) else 1.0))
        if hi <= lo:
            hi = lo + 1e-9
        normalised = (raw_anomaly - lo) / (hi - lo)
        scores = np.clip(normalised, 0.0, 1.0).round(4)
        return labels, scores

    def raw_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Return monotonic IF anomaly scores; higher means more anomalous."""
        self._check_fitted()
        return (-self._model.decision_function(X)).astype(float)

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError("Model not fitted. Call fit() first.")
        if not hasattr(self, "score_calibration_"):
            self.score_calibration_ = {}
        if not hasattr(self, "score_threshold_"):
            self.score_threshold_ = None
        if not hasattr(self, "threshold_calibration_"):
            self.threshold_calibration_ = {}
        if not hasattr(self, "score_scale_"):
            self.score_scale_ = None

    # ------------------------------------------------------------------ #
    #  PERSISTENCE                                                         #
    # ------------------------------------------------------------------ #

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> "IsolationForestDetector":
        return joblib.load(path)

    def summary(self) -> dict:
        if not self.is_fitted_:
            return {"status": "not_fitted"}
        self._check_fitted()
        return {"status": "fitted", **self.meta_}

    def __repr__(self):
        status = "fitted" if self.is_fitted_ else "unfitted"
        return (
            f"IsolationForestDetector("
            f"contamination={self.contamination}, "
            f"n_estimators={self.n_estimators}, status={status})"
        )
