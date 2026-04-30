"""
Negative Selection Algorithm (NSA) — Artificial Immune System Core
====================================================================
Implements the AIS-based anomaly detector described in the FYP report.

Performance design
------------------
Naive per-sample Euclidean distance vs all self samples is O(n_test × n_self × n_features).
At CIC-IDS-2017 scale this becomes intractable.  We apply two optimisations:

1. SELF_REF_CAP — both training (negative selection) and inference use a
   random subsample of ≤ SELF_REF_CAP self rows.  The self space is dense
   enough in the normalised feature space that a 5 k subsample faithfully
   represents it.

2. Squared-distance decomposition — instead of the 3-D diff tensor
   (n_test, n_ref, n_features), we use:
       ||a - b||² = ||a||² + ||b||² - 2 · a·b
   The dot-product term is a 2-D matmul (n_test, n_features) @ (n_features, n_ref)
   which BLAS executes at near-peak FLOPS.  Memory is O(n_test × n_ref)
   instead of O(n_test × n_ref × n_features).
   Example: 5 000 test rows × 5 000 ref rows = 25 M float32 = 100 MB — fine.
"""

import numpy as np
import joblib
import os
from datetime import datetime

# Maximum self rows used for both negative selection (fit) and inference.
SELF_REF_CAP = 5_000

# Predict chunk size — limits (chunk, n_ref) working matrix to ~100 MB.
# 12 500 × 5 000 × float32 = 250 MB; keep lower for safety on shared systems.
PREDICT_CHUNK = 5_000


class NegativeSelectionDetector:
    """
    Mature Negative Selection Algorithm detector.

    Parameters
    ----------
    r : float
        Detector activation radius (affinity threshold).
    max_detectors : int
        Maximum number of mature detectors to generate.
    max_attempts : int
        Maximum random candidates to try before stopping.
    random_state : int
        Reproducibility seed.
    """

    def __init__(
        self,
        r: float = 0.5,
        max_detectors: int = 500,
        max_attempts: int = 10_000,
        random_state: int = 42,
    ):
        self.r = r
        self.max_detectors = max_detectors
        self.max_attempts = max_attempts
        self.random_state = random_state

        self.detectors_: np.ndarray | None = None
        self.self_samples_: np.ndarray | None = None    # full set (audit only)
        self.self_reference_: np.ndarray | None = None  # capped set for inference
        self._ref_sq_: np.ndarray | None = None         # precomputed ||ref||²
        self.n_features_: int | None = None
        self.is_fitted_: bool = False
        self.meta_: dict = {}

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def fit(self, X_self: np.ndarray) -> "NegativeSelectionDetector":
        rng = np.random.default_rng(self.random_state)
        n_self, n_features = X_self.shape
        self.n_features_ = n_features
        self.self_samples_ = X_self.astype(np.float32)

        # Build capped reference --- used for both negative selection & inference
        if n_self > SELF_REF_CAP:
            idx = rng.choice(n_self, size=SELF_REF_CAP, replace=False)
            ref = X_self[idx].astype(np.float32)
        else:
            ref = self.self_samples_

        self.self_reference_ = ref
        # Precompute squared row-norms for the distance decomposition trick
        self._ref_sq_ = (ref * ref).sum(axis=1)   # (n_ref,)
        n_ref = len(ref)

        # Squared-radius threshold in UN-normalised space:
        #   normalised_dist = sqrt(raw_sq_dist) / sqrt(n_features)
        #   normalised_dist < r  ⟺  raw_sq_dist < r² × n_features
        r_sq_thresh = (self.r ** 2) * n_features

        detectors = []
        attempts = 0
        rejected = 0

        while len(detectors) < self.max_detectors and attempts < self.max_attempts:
            attempts += 1
            candidate = rng.random(n_features).astype(np.float32)

            # Squared distance via decomposition — no 3-D tensor
            c_sq = float((candidate * candidate).sum())
            dot  = ref @ candidate                          # (n_ref,)
            sq_dists = self._ref_sq_ + c_sq - 2.0 * dot   # (n_ref,)

            if sq_dists.min() < r_sq_thresh:
                rejected += 1
            else:
                detectors.append(candidate)

        self.detectors_ = (
            np.array(detectors, dtype=np.float32)
            if detectors
            else np.empty((0, n_features), dtype=np.float32)
        )
        self.is_fitted_ = True

        self.meta_ = {
            "algorithm": "Negative Selection Algorithm (NSA)",
            "r": self.r,
            "max_detectors": self.max_detectors,
            "n_self_samples": n_self,
            "self_match_cap": n_ref,
            "n_features": n_features,
            "attempts": attempts,
            "candidates_rejected": rejected,
            "mature_detectors": len(detectors),
            "trained_at": datetime.utcnow().isoformat(),
        }
        return self

    # ------------------------------------------------------------------ #
    #  DETECTION — vectorised, chunked, BLAS-based                         #
    # ------------------------------------------------------------------ #

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Classify samples as normal (0) or anomalous (1)."""
        self._check_fitted()
        return (self._min_dist_batch(X) > self.r).astype(int)

    def predict_with_scores(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores ∈ [0,1]).
        Higher score = more anomalous.

        Score formula: (min_dist - r) / (1 - r)
        Dividing by (1 - r) rather than r stretches the score across the full
        non-self space so that a sample at the maximum possible distance
        (≈1.0) scores 1.0 instead of saturating near 0.2.
        """
        self._check_fitted()
        min_dists = self._min_dist_batch(X)
        labels = (min_dists > self.r).astype(int)
        scores = np.where(
            labels == 1,
            np.clip((min_dists - self.r) / max(1.0 - self.r, 1e-9), 0.0, 1.0),
            0.0,
        ).round(4)
        return labels, scores

    def predict_with_details(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores, min_dists).
        min_dists is the raw normalised distance to the nearest self sample,
        used downstream to tag zero-day candidates without re-running inference.
        """
        self._check_fitted()
        min_dists = self._min_dist_batch(X)
        labels = (min_dists > self.r).astype(int)
        scores = np.where(
            labels == 1,
            np.clip((min_dists - self.r) / max(1.0 - self.r, 1e-9), 0.0, 1.0),
            0.0,
        ).round(4)
        return labels, scores, min_dists

    def _min_dist_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Minimum normalised Euclidean distance from each row in X to the nearest
        self_reference_ row.

        Uses the squared-distance decomposition to avoid a 3-D tensor:
            sq_dist(x, r) = ||x||² + ||r||² - 2 · x·r

        Chunked over X so the (chunk, n_ref) working matrix stays ≤ ~100 MB.
        """
        ref    = self.self_reference_
        ref_sq = self._ref_sq_
        if ref is None or len(ref) == 0:
            return np.full(len(X), np.inf, dtype=np.float64)

        X      = np.asarray(X, dtype=np.float32)
        scale  = float(np.sqrt(self.n_features_))
        n      = len(X)
        result = np.empty(n, dtype=np.float64)

        for start in range(0, n, PREDICT_CHUNK):
            end   = min(start + PREDICT_CHUNK, n)
            batch = X[start:end]                            # (c, f)

            x_sq = (batch * batch).sum(axis=1, keepdims=True)  # (c, 1)
            dot  = batch @ ref.T                               # (c, n_ref)  BLAS
            sq   = x_sq + ref_sq[np.newaxis, :] - 2.0 * dot  # (c, n_ref)
            np.clip(sq, 0, None, out=sq)                       # numerical safety

            result[start:end] = np.sqrt(sq.min(axis=1)) / scale

        return result

    # ── Legacy single-sample helpers (kept for API compatibility) ──────

    def _is_anomaly(self, x: np.ndarray) -> bool:
        return bool(self._min_dist_batch(x[np.newaxis])[0] > self.r)

    def _dist_to_self(self, x: np.ndarray) -> tuple[float, bool]:
        d = float(self._min_dist_batch(x[np.newaxis])[0])
        return d, d > self.r

    def _matches_self(self, candidate: np.ndarray, X_self: np.ndarray) -> bool:
        """Legacy — used only by unit tests."""
        return bool(self._min_dist_batch(candidate[np.newaxis])[0] < self.r)

    def _min_detector_distance(self, x: np.ndarray) -> tuple[float, bool]:
        return self._dist_to_self(x)

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError("Detector not fitted. Call fit() first.")

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
        return {
            "status": "fitted",
            **self.meta_,
            "active_antibodies": int(len(self.detectors_)) if self.detectors_ is not None else 0,
        }

    def __repr__(self):
        status = "fitted" if self.is_fitted_ else "unfitted"
        return (
            f"NegativeSelectionDetector("
            f"r={self.r}, max_detectors={self.max_detectors}, status={status})"
        )
