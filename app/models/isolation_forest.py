"""
Isolation Forest Baseline Model
================================
Wraps sklearn's IsolationForest to match the same interface as the NSA
detector, so both models can be swapped transparently in the pipeline.

Used as:
  - A performance BENCHMARK against the AIS/NSA model.
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


class IsolationForestDetector:
    """
    Isolation Forest anomaly detector with the same fit/predict interface
    as NegativeSelectionDetector.

    Parameters
    ----------
    contamination : float
        Expected fraction of anomalies in training data [0.0 – 0.5].
        Use a small value (e.g. 0.05) if you believe the training data is
        mostly clean but may have a small number of hidden attacks.
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

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        """
        Train on the provided data.  Unlike NSA, Isolation Forest can be
        trained on MIXED data (it estimates the contamination level).

        Parameters
        ----------
        X : ndarray (n_samples, n_features) — normalised features
        """
        self._model.fit(X)
        self.is_fitted_ = True

        self.meta_ = {
            "algorithm": "Isolation Forest",
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "n_training_samples": len(X),
            "n_features": X.shape[1],
            "trained_at": datetime.utcnow().isoformat(),
        }
        return self

    # ------------------------------------------------------------------ #
    #  DETECTION                                                           #
    # ------------------------------------------------------------------ #

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Returns labels: 0 = normal, 1 = anomaly.
        (sklearn returns +1 for normal, -1 for anomaly — we invert this.)
        """
        self._check_fitted()
        raw = self._model.predict(X)          # +1 normal, -1 anomaly
        return np.where(raw == -1, 1, 0).astype(int)

    def predict_with_scores(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores).
        Score is in [0, 1], higher = more anomalous.
        """
        self._check_fitted()
        labels = self.predict(X)

        # decision_function returns negative anomaly scores; more negative = more anomalous
        raw_scores = self._model.decision_function(X)   # typically in [-0.5, 0.5]
        # Normalise to [0, 1]: invert (lower raw_score → higher anomaly confidence)
        normalised = 1.0 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)
        scores = np.clip(normalised, 0.0, 1.0).round(4)
        return labels, scores

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError("Model not fitted. Call fit() first.")

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
        return {"status": "fitted", **self.meta_}

    def __repr__(self):
        status = "fitted" if self.is_fitted_ else "unfitted"
        return (
            f"IsolationForestDetector("
            f"contamination={self.contamination}, "
            f"n_estimators={self.n_estimators}, status={status})"
        )
