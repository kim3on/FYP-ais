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

import numpy as np
import joblib
import os
from datetime import datetime, timezone

# Maximum self rows used for both negative selection (fit) and inference.
SELF_REF_CAP = 5_000

# Predict chunk size — limits (chunk, n_ref) working matrix to ~100 MB.
PREDICT_CHUNK = 5_000


class NegativeSelectionDetector:
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
        max_detectors: int = 1000,
        max_attempts: int = 30_000,
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

        # Detector aging — tracks staleness per detector
        self._det_match_counts_: np.ndarray | None = None   # lifetime match count
        self._det_idle_batches_: np.ndarray | None = None   # batches since last match

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def fit(self, X_self: np.ndarray) -> "NegativeSelectionDetector":
        rng = np.random.default_rng(self.random_state)
        n_self, n_features = X_self.shape
        self.n_features_ = n_features
        self.self_samples_ = X_self.astype(np.float32)
        scale = float(np.sqrt(n_features))

        # Build capped reference — used for negative selection & inference
        if n_self > SELF_REF_CAP:
            idx = rng.choice(n_self, size=SELF_REF_CAP, replace=False)
            ref = X_self[idx].astype(np.float32)
        else:
            ref = self.self_samples_

        self.self_reference_ = ref
        self._ref_sq_ = (ref * ref).sum(axis=1)          # (n_ref,)
        n_ref = len(ref)

        # ── Dynamic threshold computation ─────────────────────────────
        # Compute r and r_s from the actual benign data distribution in PCA space.
        # This avoids hard-coded [0,1] assumptions that break after RobustScaler+PCA.
        if self.auto_threshold:
            n_subset = min(n_ref, 2000)
            idx_subset = rng.choice(n_ref, size=n_subset, replace=False) if n_ref > 2000 else np.arange(n_ref)
            ref_subset = ref[idx_subset]
            ref_subset_sq = self._ref_sq_[idx_subset]

            dot_matrix = ref_subset @ ref.T
            sq_dists = ref_subset_sq[:, np.newaxis] + self._ref_sq_[np.newaxis, :] - 2.0 * dot_matrix
            np.clip(sq_dists, 0, None, out=sq_dists)
            dist_matrix = np.sqrt(sq_dists) / scale

            # Calculate nearest neighbor distances (ignore self-distance 0)
            sorted_dists = np.sort(dist_matrix, axis=1)
            nn_dists = sorted_dists[:, 1] if sorted_dists.shape[1] > 1 else sorted_dists[:, 0]

            # Dynamic r (Self-Gap Threshold): 99.9th percentile of all pairwise distances
            self.r = max(float(np.percentile(dist_matrix, 99.9)), 0.05)
            
            # Dynamic r_s (Self-Tolerance): 99.0th percentile of nearest-neighbor distances
            self.r_s = max(float(np.percentile(nn_dists, 99.0)), 0.01)

        # ── V-Detector generation ─────────────────────────────────────
        # r_s is in normalised distance space; convert to squared raw:
        #   norm_dist = sqrt(raw_sq) / sqrt(d)
        #   norm_dist < r_s  ⟺  raw_sq < r_s² × d
        r_s_sq_thresh = (self.r_s ** 2) * n_features

        # Pre-compute KMeans centroids for Smarter Phase 1 Generation
        from sklearn.cluster import KMeans
        n_clusters = min(50, n_ref)
        kmeans = KMeans(n_clusters=n_clusters, random_state=self.random_state, n_init='auto')
        kmeans.fit(ref)
        centroids = kmeans.cluster_centers_.astype(np.float32)

        detectors = []
        radii = []
        attempts = 0
        rejected = 0
        rejected_overlap = 0

        while len(detectors) < self.max_detectors and attempts < self.max_attempts:
            attempts += 1

            if len(detectors) < (self.max_detectors // 2):
                # Phase 1: Smart sampling via KMeans centroids + large noise
                # Mutation in actual data-space — no [0,1] clip (breaks after PCA)
                centroid = centroids[rng.integers(len(centroids))]
                mutation = rng.normal(0, self.r * 3.0, n_features).astype(np.float32)
                candidate = centroid + mutation
            else:
                # Phase 2: Boundary mutation — push self samples outward
                base = ref[rng.integers(n_ref)]
                mutation = rng.normal(0, self.r * 1.5, n_features).astype(np.float32)
                candidate = base + mutation

            # Distance to nearest self (squared, raw)
            c_sq = float((candidate * candidate).sum())
            dot = ref @ candidate                            # (n_ref,)
            sq_dists = self._ref_sq_ + c_sq - 2.0 * dot     # (n_ref,)
            min_sq = float(sq_dists.min())

            if min_sq < r_s_sq_thresh:
                # Candidate reacts to self → delete (negative selection)
                rejected += 1
            else:
                # Survived!  V-Detector radius = dist_to_nearest_self − r_s
                min_dist_norm = float(np.sqrt(max(min_sq, 0.0))) / scale
                det_radius = min_dist_norm - self.r_s
                
                if det_radius > 0:
                    # Enforce Inter-Detector Spacing to maximize coverage
                    if len(detectors) > 0:
                        det_array = np.array(detectors, dtype=np.float32)
                        dot_det = det_array @ candidate
                        det_sq = (det_array * det_array).sum(axis=1)
                        dist_sq_to_det = c_sq + det_sq - 2.0 * dot_det
                        
                        if dist_sq_to_det.min() < r_s_sq_thresh:
                            # Candidate is too close to an existing detector
                            rejected_overlap += 1
                            continue
                            
                    detectors.append(candidate)
                    radii.append(det_radius)

        self.detectors_ = (
            np.array(detectors, dtype=np.float32)
            if detectors
            else np.empty((0, n_features), dtype=np.float32)
        )
        self.det_radii_ = (
            np.array(radii, dtype=np.float64)
            if radii
            else np.empty(0, dtype=np.float64)
        )
        if len(self.detectors_) > 0:
            self._det_sq_ = (self.detectors_ * self.detectors_).sum(axis=1)

        # Initialise aging counters
        n_det = len(self.detectors_)
        self._det_match_counts_ = np.zeros(n_det, dtype=np.int64)
        self._det_idle_batches_ = np.zeros(n_det, dtype=np.int64)

        self.is_fitted_ = True
        self.meta_ = {
            "algorithm": "V-Detector Negative Selection Algorithm (NSA)",
            "r": self.r,
            "r_s": self.r_s,
            "max_detectors": self.max_detectors,
            "n_self_samples": n_self,
            "self_match_cap": n_ref,
            "n_features": n_features,
            "attempts": attempts,
            "candidates_rejected": rejected,
            "candidates_rejected_overlap": rejected_overlap,
            "mature_detectors": len(detectors),
            "det_radius_min": float(min(radii)) if radii else 0.0,
            "det_radius_max": float(max(radii)) if radii else 0.0,
            "det_radius_mean": float(np.mean(radii)) if radii else 0.0,
            "auto_threshold": self.auto_threshold,
            "r_fitted": round(self.r, 6),
            "r_s_fitted": round(self.r_s, 6),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        return self

    # ------------------------------------------------------------------ #
    #  DETECTION — True NSA: Detector-primary classification               #
    # ------------------------------------------------------------------ #

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Classify samples as normal (0) or anomalous (1).

        True Negative Selection — two complementary mechanisms:

        1. **Detector match (primary / adaptive immune):**
           A sample is anomalous if it falls within the variable activation
           radius of ANY mature V-detector.

        2. **Self-gap fallback (innate immune):**
           A sample is anomalous if its distance to the nearest self-reference
           exceeds ``self.r``, even when no detector covers that region.

        A sample is flagged if EITHER condition is true.
        """
        self._check_fitted()
        det_matched, _ = self._check_detector_match(X)
        dist_to_self = self._min_dist_to_self(X)
        self_gap = dist_to_self > self.r
        return (det_matched | self_gap).astype(int)

    def predict_with_scores(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores ∈ [0, 1]).

        Scoring hierarchy:
        - Detector match  → high confidence (0.5–1.0), indicates a known
          non-self pattern was recognised by a mature antibody.
        - Self-gap only   → variable confidence (0.0–1.0), indicates general
          novelty with no specific antibody match.
        - Both            → takes the maximum of the two signals.
        """
        self._check_fitted()
        det_matched, det_scores = self._check_detector_match(X)
        det_matched = det_matched & (det_scores >= getattr(self, "confidence_threshold", 0.0))
        dist_to_self = self._min_dist_to_self(X)
        self_gap = dist_to_self > self.r

        labels = (det_matched | self_gap).astype(int)

        # Self-gap score: ramps 0→1 as distance goes from r to 1.0
        gap_scores = np.clip(
            (dist_to_self - self.r) / max(1.0 - self.r, 1e-9), 0.0, 1.0
        )

        # Detector score: boost to 0.5–1.0 range (specific antibody match
        # always implies at least medium confidence)
        boosted_det = np.where(det_matched, 0.5 + 0.5 * det_scores, 0.0)

        final_scores = np.maximum(gap_scores, boosted_det)
        # Normal samples should have score 0
        final_scores = np.where(labels == 1, final_scores, 0.0)

        return labels, final_scores.round(4)

    def predict_with_details(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores, dist_to_self).
        """
        self._check_fitted()
        det_matched, det_scores = self._check_detector_match(X)
        det_matched = det_matched & (det_scores >= getattr(self, "confidence_threshold", 0.0))
        dist_to_self = self._min_dist_to_self(X)
        self_gap = dist_to_self > self.r

        labels = (det_matched | self_gap).astype(int)

        gap_scores = np.clip(
            (dist_to_self - self.r) / max(1.0 - self.r, 1e-9), 0.0, 1.0
        )
        boosted_det = np.where(det_matched, 0.5 + 0.5 * det_scores, 0.0)
        scores = np.maximum(gap_scores, boosted_det)
        scores = np.where(labels == 1, scores, 0.0)

        return labels, scores.round(4), dist_to_self

    # ------------------------------------------------------------------ #
    #  V-DETECTOR MATCHING                                                 #
    # ------------------------------------------------------------------ #

    def _check_detector_match(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Check each sample against all V-detectors (variable radius).

        Returns
        -------
        matched : bool array (n_samples,)
            True if the sample falls inside any detector's activation sphere.
        best_score : float array (n_samples,)
            Depth of the best match: 1.0 = at detector centre, 0.0 = on
            boundary.  Zero for unmatched samples.
        """
        X = np.asarray(X, dtype=np.float32)
        n = len(X)
        matched = np.zeros(n, dtype=bool)
        best_score = np.zeros(n, dtype=np.float64)

        if self.detectors_ is None or len(self.detectors_) == 0:
            return matched, best_score

        scale = float(np.sqrt(self.n_features_))
        n_det = len(self.detectors_)
        # Track which detectors fired (for aging)
        det_fired = np.zeros(n_det, dtype=bool)

        for start in range(0, n, PREDICT_CHUNK):
            end = min(start + PREDICT_CHUNK, n)
            batch = X[start:end]

            # (chunk, n_det) normalised distance matrix
            x_sq = (batch * batch).sum(axis=1, keepdims=True)
            dot = batch @ self.detectors_.T
            sq = x_sq + self._det_sq_[np.newaxis, :] - 2.0 * dot
            np.clip(sq, 0, None, out=sq)
            dists = np.sqrt(sq) / scale                    # (chunk, n_det)

            # Variable-radius comparison: dist < det_radii per detector
            match_matrix = dists < self.det_radii_[np.newaxis, :]  # (chunk, n_det)
            matched[start:end] = match_matrix.any(axis=1)

            # Record which detectors matched at least one sample
            det_fired |= match_matrix.any(axis=0)

            # Score = 1 − (dist / radius), clamped to [0, 1] for matched only
            with np.errstate(divide='ignore', invalid='ignore'):
                ratios = np.where(
                    match_matrix,
                    1.0 - (dists / self.det_radii_[np.newaxis, :]),
                    0.0,
                )
            best_score[start:end] = ratios.max(axis=1)

        # Update aging counters
        if self._det_match_counts_ is not None:
            self._det_match_counts_ += det_fired.astype(np.int64)
            self._det_idle_batches_ += 1
            self._det_idle_batches_[det_fired] = 0

        return matched, best_score

    # ------------------------------------------------------------------ #
    #  DISTANCE TO SELF                                                    #
    # ------------------------------------------------------------------ #

    def _min_dist_to_self(self, X: np.ndarray) -> np.ndarray:
        """Minimum normalised Euclidean distance from each row of X to self."""
        return self._batch_min_dist(X, self.self_reference_, self._ref_sq_)

    def _batch_min_dist(
        self, X: np.ndarray, ref: np.ndarray, ref_sq: np.ndarray
    ) -> np.ndarray:
        """
        Efficiently calculates min normalised Euclidean distance from X to ref.
        """
        X = np.asarray(X, dtype=np.float32)
        scale = float(np.sqrt(self.n_features_))
        n = len(X)
        result = np.empty(n, dtype=np.float64)

        for start in range(0, n, PREDICT_CHUNK):
            end = min(start + PREDICT_CHUNK, n)
            batch = X[start:end]
            x_sq = (batch * batch).sum(axis=1, keepdims=True)
            dot = batch @ ref.T
            sq = x_sq + ref_sq[np.newaxis, :] - 2.0 * dot
            np.clip(sq, 0, None, out=sq)
            result[start:end] = np.sqrt(sq.min(axis=1)) / scale

        return result

    # ------------------------------------------------------------------ #
    #  DETECTOR AGING & REFRESH                                            #
    # ------------------------------------------------------------------ #

    def get_detector_ages(self) -> dict:
        """Return aging statistics for the detector repertoire."""
        if self._det_idle_batches_ is None or len(self._det_idle_batches_) == 0:
            return {"total": 0, "stale": 0, "active": 0}
        idle = self._det_idle_batches_
        return {
            "total": int(len(idle)),
            "active": int((idle == 0).sum()),
            "stale_5": int((idle >= 5).sum()),
            "stale_10": int((idle >= 10).sum()),
            "max_idle": int(idle.max()),
            "mean_idle": round(float(idle.mean()), 1),
            "match_counts": {
                "min": int(self._det_match_counts_.min()),
                "max": int(self._det_match_counts_.max()),
                "mean": round(float(self._det_match_counts_.mean()), 1),
            },
        }

    def refresh(self, max_idle_batches: int = 10) -> int:
        """
        Replace detectors that have been idle for too long (T-cell death
        and replacement).  Generates new candidates via the same negative
        selection process.

        Returns the number of detectors replaced.
        """
        self._check_fitted()
        if self._det_idle_batches_ is None or len(self.detectors_) == 0:
            return 0

        stale_mask = self._det_idle_batches_ >= max_idle_batches
        n_stale = int(stale_mask.sum())
        if n_stale == 0:
            return 0

        rng = np.random.default_rng()
        scale = float(np.sqrt(self.n_features_))
        ref = self.self_reference_
        n_ref = len(ref)
        r_s_sq_thresh = (self.r_s ** 2) * self.n_features_

        stale_indices = np.where(stale_mask)[0]
        replaced = 0
        attempts = 0
        max_refresh_attempts = n_stale * 50

        while replaced < n_stale and attempts < max_refresh_attempts:
            attempts += 1
            # Boundary mutation for replacement detectors
            base = ref[rng.integers(n_ref)]
            mutation = rng.normal(0, self.r * 1.5, self.n_features_).astype(np.float32)
            candidate = np.clip(base + mutation, 0, 1)

            c_sq = float((candidate * candidate).sum())
            dot = ref @ candidate
            sq_dists = self._ref_sq_ + c_sq - 2.0 * dot
            min_sq = float(sq_dists.min())

            if min_sq >= r_s_sq_thresh:
                min_dist_norm = float(np.sqrt(max(min_sq, 0.0))) / scale
                det_radius = min_dist_norm - self.r_s
                if det_radius > 0:
                    idx = stale_indices[replaced]
                    self.detectors_[idx] = candidate
                    self.det_radii_[idx] = det_radius
                    self._det_sq_[idx] = c_sq
                    self._det_match_counts_[idx] = 0
                    self._det_idle_batches_[idx] = 0
                    replaced += 1

        return replaced

    # ── Legacy single-sample helpers (kept for API compatibility) ──────

    def _is_anomaly(self, x: np.ndarray) -> bool:
        return bool(self.predict(x[np.newaxis])[0] == 1)

    def _dist_to_self(self, x: np.ndarray) -> tuple[float, bool]:
        d = float(self._min_dist_to_self(x[np.newaxis])[0])
        return d, d > self.r

    def _matches_self(self, candidate: np.ndarray, X_self: np.ndarray) -> bool:
        """Legacy — used only by unit tests."""
        return bool(self._min_dist_to_self(candidate[np.newaxis])[0] < self.r_s)

    def _min_detector_distance(self, x: np.ndarray) -> tuple[float, bool]:
        """Distance from x to nearest V-detector centre (not self)."""
        if self.detectors_ is None or len(self.detectors_) == 0:
            return float('inf'), False
        dists = self._batch_min_dist(
            x[np.newaxis], self.detectors_, self._det_sq_
        )
        d = float(dists[0])
        # Check variable-radius match against nearest detector
        matched, _ = self._check_detector_match(x[np.newaxis])
        return d, bool(matched[0])

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
            f"r={self.r}, r_s={self.r_s}, "
            f"max_detectors={self.max_detectors}, status={status})"
        )
