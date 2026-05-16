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

from app.core.calibration import conformal_threshold

# Maximum self rows used for both negative selection (fit) and inference.
SELF_REF_CAP = 3_000

# Distance matrix budget for laptop-friendly memory use.
MAX_DISTANCE_MATRIX_ENTRIES = 4_000_000
PREDICT_CHUNK = 5_000

DEFAULT_FUSION_WEIGHTS = {
    "detector": 0.40,
    "distance": 0.25,
    "density": 0.20,
    "self_boundary": 0.15,
}

MIN_COMPONENT_SCALES = {
    "distance": 0.05,
    "density": 0.05,
    "detector": 1.0,
    "self_boundary": 0.10,
}


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
        self.target_fpr = 0.05

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

            # Calculate nearest neighbor distances without sorting every row.
            if dist_matrix.shape[1] > 1:
                nn_dists = np.partition(dist_matrix, 1, axis=1)[:, 1]
            else:
                nn_dists = dist_matrix[:, 0]

            # Dynamic r (Self-Gap Threshold): 99th percentile of nearest-neighbour
            # distances. Wide self-gap ensures anomalies far from all benign
            # references are detected. Final anomaly decision uses score_threshold_
            # calibrated on the benign holdout by TrainingPipeline.
            self.r = max(float(np.percentile(nn_dists, 99.0)), 0.05)

            # Dynamic r_s (Thymus Stringency): MUST be materially smaller than r.
            # V-Detector radius = dist_to_nearest_self − r_s.
            # When r_s ≈ r (both at p99), every detector gets radius ≈ 0 and matches
            # almost nothing — this was the root cause of 11.8% recall.
            # Using p30 keeps the thymus tight while leaving enough headroom for
            # detectors to have a meaningful activation radius in non-self space.
            self.r_s = max(float(np.percentile(nn_dists, 30.0)), 0.01)

        # ── V-Detector generation ─────────────────────────────────────
        # r_s is in normalised distance space; convert to squared raw:
        #   norm_dist = sqrt(raw_sq) / sqrt(d)
        #   norm_dist < r_s  ⟺  raw_sq < r_s² × d
        r_s_sq_thresh = (self.r_s ** 2) * n_features

        # Pre-compute benign PCA-space geometry for detector candidate generation.
        # PCA-whitened space is unbounded; the expanded quantile envelope targets
        # benign tails without falling back to invalid [0, 1] clipping.
        q_low = np.quantile(ref, 0.01, axis=0).astype(np.float32)
        q_high = np.quantile(ref, 0.99, axis=0).astype(np.float32)
        span = np.maximum(q_high - q_low, 1e-3).astype(np.float32)
        envelope_low = q_low - (0.35 * span)
        envelope_high = q_high + (0.35 * span)

        # Pre-compute lightweight centroids for boundary-aware mutation.
        from sklearn.cluster import MiniBatchKMeans
        n_clusters = min(50, n_ref)
        kmeans = MiniBatchKMeans(
            n_clusters=n_clusters,
            random_state=self.random_state,
            n_init=3,
            batch_size=min(1024, n_ref),
            max_iter=100,
        )
        kmeans.fit(ref)
        centroids = kmeans.cluster_centers_.astype(np.float32)

        detectors = np.empty((self.max_detectors, n_features), dtype=np.float32)
        detector_sq = np.empty(self.max_detectors, dtype=np.float32)
        radii = np.empty(self.max_detectors, dtype=np.float64)
        attempts = 0
        rejected = 0
        rejected_overlap = 0
        n_detectors = 0

        while n_detectors < self.max_detectors and attempts < self.max_attempts:
            attempts += 1

            if n_detectors < (self.max_detectors // 3):
                # Phase 1: Expanded benign-tail envelope sampling.
                candidate = rng.uniform(envelope_low, envelope_high).astype(np.float32)
            elif n_detectors < (self.max_detectors * 2 // 3):
                # Phase 2: Smart sampling via KMeans centroids + large noise
                # Mutation in actual data-space — no [0,1] clip (breaks after PCA).
                centroid = centroids[rng.integers(len(centroids))]
                mutation = rng.normal(0, self.r * 3.0, n_features).astype(np.float32)
                candidate = centroid + mutation
            else:
                # Phase 3: Boundary mutation — push self samples outward.
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
                    if n_detectors > 0:
                        det_view = detectors[:n_detectors]
                        dot_det = det_view @ candidate
                        det_sq = detector_sq[:n_detectors]
                        dist_sq_to_det = c_sq + det_sq - 2.0 * dot_det
                        
                        if dist_sq_to_det.min() < r_s_sq_thresh:
                            # Candidate is too close to an existing detector
                            rejected_overlap += 1
                            continue
                            
                    detectors[n_detectors] = candidate
                    detector_sq[n_detectors] = c_sq
                    radii[n_detectors] = det_radius
                    n_detectors += 1

        self.detectors_ = (
            detectors[:n_detectors].copy()
            if n_detectors
            else np.empty((0, n_features), dtype=np.float32)
        )
        self.det_radii_ = (
            radii[:n_detectors].copy()
            if n_detectors
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
            "candidate_strategy": "expanded_pca_tail_envelope_plus_centroid_and_boundary_mutation",
            "mature_detectors": n_detectors,
            "det_radius_min": float(self.det_radii_.min()) if n_detectors else 0.0,
            "det_radius_max": float(self.det_radii_.max()) if n_detectors else 0.0,
            "det_radius_mean": float(self.det_radii_.mean()) if n_detectors else 0.0,
            "performance_profile": "laptop",
            "self_ref_cap": SELF_REF_CAP,
            "distance_matrix_entry_budget": MAX_DISTANCE_MATRIX_ENTRIES,
            "auto_threshold": self.auto_threshold,
            "r_fitted": round(self.r, 6),
            "r_s_fitted": round(self.r_s, 6),
            "score_threshold": self.score_threshold_,
            "fusion_threshold": self.fusion_threshold_,
            "target_fpr": self.target_fpr,
            "calibration": self.calibration_,
            "fusion_calibration": self.fusion_calibration_,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        return self

    def calibrate_threshold(
        self,
        X_benign: np.ndarray,
        target_fpr: float = 0.01,
    ) -> dict:
        """
        Calibrate the final anomaly threshold from benign rows only.

        target_fpr=0.01 means the threshold is set at the 99th percentile of
        benign calibration scores, so roughly 1% of benign calibration rows are
        allowed to be flagged as anomalies.
        """
        self._check_fitted()
        if len(X_benign) == 0:
            raise ValueError("Cannot calibrate NSA threshold without benign calibration rows")

        target_fpr = float(np.clip(target_fpr, 0.0001, 0.5))
        scores = self.anomaly_scores(X_benign)
        threshold_info = conformal_threshold(
            scores,
            target_fpr,
            min_threshold=1e-9,
        )
        threshold = float(threshold_info["threshold"])
        observed_fpr = float(threshold_info["observed_fpr"])

        high = float(np.quantile(scores, 0.999))
        self.score_threshold_ = threshold
        self.score_scale_ = max(high, threshold * 1.5, threshold + 1e-9)
        self.target_fpr = target_fpr
        self.calibration_ = {
            "mode": "unsupervised_benign",
            "target_fpr": round(float(threshold_info["target_fpr"]), 6),
            "observed_fpr": round(observed_fpr, 6),
            "normal_pass_rate": round(float(threshold_info["normal_pass_rate"]), 6),
            "threshold": round(threshold, 6),
            "score_scale": round(self.score_scale_, 6),
            "n_calibration_samples": int(threshold_info["n_calibration_samples"]),
            "rank_index": int(threshold_info["rank_index"]),
            "rank_index_zero_based": int(threshold_info["rank_index_zero_based"]),
            "calibration_reliability": threshold_info["reliability"],
            "decision_rule": "score > threshold",
            "score_min": round(float(scores.min()), 6),
            "score_median": round(float(np.median(scores)), 6),
            "score_p95": round(float(np.quantile(scores, 0.95)), 6),
            "score_p99": round(float(np.quantile(scores, 0.99)), 6),
            "score_max": round(float(scores.max()), 6),
        }
        self.meta_["score_threshold"] = self.score_threshold_
        self.meta_["target_fpr"] = self.target_fpr
        self.meta_["calibration"] = self.calibration_
        return self.calibration_

    def calibrate_fusion(
        self,
        X_benign: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
        target_fpr: float = 0.05,
        weights: dict | None = None,
        density_k: int = 5,
    ) -> dict:
        """
        Calibrate fused anomaly scoring from BENIGN rows only.

        Fusion combines NSA self-distance, k-nearest-self density,
        V-detector depth, and optional self-boundary scores. Component scales,
        weights, and the final threshold are learned from benign calibration
        rows only; no attack labels are used.
        """
        self._check_fitted()
        if len(X_benign) == 0:
            raise ValueError("Cannot calibrate fused threshold without benign rows")

        target_fpr = float(np.clip(target_fpr, 0.0001, 0.5))
        weights = weights or DEFAULT_FUSION_WEIGHTS
        if self_boundary_scores is None:
            self_boundary_scores = np.zeros(len(X_benign), dtype=np.float64)

        components = self.score_components(X_benign, density_k=density_k)
        components["self_boundary"] = np.asarray(self_boundary_scores, dtype=np.float64)

        scales = {}
        for name, values in components.items():
            values = np.asarray(values, dtype=np.float64)
            finite = values[np.isfinite(values)]
            if len(finite) == 0:
                scale = 1.0
            else:
                q25, q75 = np.quantile(finite, [0.25, 0.75])
                iqr = max(float(q75 - q25), 0.0)
                candidates = [
                    float(np.quantile(finite, 0.95)),
                    float(np.quantile(finite, 0.99)),
                    float(q75 + 1.5 * iqr),
                    float(finite.max()) if finite.size else 1.0,
                ]
                scale = max(candidates)
                if scale <= 1e-12:
                    scale = 1.0
            scale = max(scale, MIN_COMPONENT_SCALES.get(name, 1e-6))
            scales[name] = scale

        fused = self.fused_scores(
            X_benign,
            self_boundary_scores=self_boundary_scores,
            weights=weights,
            component_scales=scales,
            density_k=density_k,
        )
        threshold_info = conformal_threshold(fused, target_fpr)
        threshold = float(threshold_info["threshold"])
        observed_fpr = float(threshold_info["observed_fpr"])
        high = float(np.quantile(fused, 0.999))

        self.fusion_threshold_ = threshold
        self.fusion_score_scale_ = max(high, threshold * 1.5, threshold + 1e-9)
        self.fusion_weights_ = {k: float(v) for k, v in weights.items()}
        self.fusion_component_scales_ = {k: round(float(v), 6) for k, v in scales.items()}
        self.target_fpr = target_fpr
        self.fusion_calibration_ = {
            "mode": "unsupervised_benign_score_fusion",
            "score_mode": "weighted_fusion",
            "target_fpr": round(float(threshold_info["target_fpr"]), 6),
            "observed_fpr": round(observed_fpr, 6),
            "normal_pass_rate": round(float(threshold_info["normal_pass_rate"]), 6),
            "threshold": round(threshold, 6),
            "score_scale": round(self.fusion_score_scale_, 6),
            "n_calibration_samples": int(threshold_info["n_calibration_samples"]),
            "rank_index": int(threshold_info["rank_index"]),
            "rank_index_zero_based": int(threshold_info["rank_index_zero_based"]),
            "calibration_reliability": threshold_info["reliability"],
            "decision_rule": "score > threshold",
            "density_k": int(density_k),
            "component_weights": self.fusion_weights_,
            "component_scales": self.fusion_component_scales_,
            "score_min": round(float(fused.min()), 6),
            "score_median": round(float(np.median(fused)), 6),
            "score_p95": round(float(np.quantile(fused, 0.95)), 6),
            "score_p99": round(float(np.quantile(fused, 0.99)), 6),
            "score_max": round(float(fused.max()), 6),
        }
        self.meta_["fusion_threshold"] = self.fusion_threshold_
        self.meta_["target_fpr"] = self.target_fpr
        self.meta_["fusion_calibration"] = self.fusion_calibration_
        return self.fusion_calibration_

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
        scores = self.anomaly_scores(X)
        threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        detector_matches, _ = self._check_detector_match(X, update_aging=False)
        return ((scores > threshold) | detector_matches).astype(int)

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
        raw_scores = self.anomaly_scores(X)
        threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        labels = ((raw_scores > threshold) | detector_matches).astype(int)
        scale = max(float(self.score_scale_ or threshold * 1.5), threshold + 1e-9)
        confidence = np.clip((raw_scores - threshold) / max(scale - threshold, 1e-9), 0.0, 1.0)
        confidence = np.maximum(confidence, detector_scores)
        confidence = np.where(labels == 1, confidence, 0.0)
        return labels, confidence.round(4)

    def predict_with_details(
        self, X: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores, dist_to_self).
        """
        self._check_fitted()
        labels, scores = self.predict_with_scores(X)
        dist_to_self = self._min_dist_to_self(X)
        return labels, scores, dist_to_self

    def predict_fused(
        self,
        X: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Return labels, normalized confidence, and fused raw scores."""
        self._check_fitted()
        raw_scores = self.fused_scores(X, self_boundary_scores=self_boundary_scores)
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        threshold = getattr(self, "fusion_threshold_", None)
        if threshold is None:
            threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        labels = ((raw_scores > threshold) | detector_matches).astype(int)
        scale = max(float(self.fusion_score_scale_ or threshold * 1.5), threshold + 1e-9)
        confidence = np.clip((raw_scores - threshold) / max(scale - threshold, 1e-9), 0.0, 1.0)
        confidence = np.maximum(confidence, detector_scores)
        confidence = np.where(labels == 1, confidence, 0.0)
        return labels, confidence.round(4), raw_scores.astype(np.float64)

    def decision_components(
        self,
        X: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
    ) -> dict[str, np.ndarray]:
        """
        Return source-level decision components without changing predictions.

        D = mature V-detector match
        G = self-gap fallback, based on distance to self-reference > r
        N = NSA-only calibrated score match
        F = fused calibrated score match
        """
        self._check_fitted()
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        distances = self._min_dist_to_self(X)
        nsa_scores = distances + np.where(
            detector_scores >= getattr(self, "confidence_threshold", 0.0),
            detector_scores,
            0.0,
        )
        nsa_threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        fused_scores = self.fused_scores(X, self_boundary_scores=self_boundary_scores)
        fusion_threshold = getattr(self, "fusion_threshold_", None)
        if fusion_threshold is None:
            fusion_threshold = nsa_threshold

        return {
            "v_detector_match": detector_matches.astype(bool),
            "self_gap_match": (distances > self.r).astype(bool),
            "nsa_score_match": (nsa_scores > nsa_threshold).astype(bool),
            "fusion_score_match": (fused_scores > fusion_threshold).astype(bool),
            "distance": distances.astype(np.float64),
            "detector_score": detector_scores.astype(np.float64),
            "nsa_score": nsa_scores.astype(np.float64),
            "fused_score": fused_scores.astype(np.float64),
        }

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Continuous unsupervised anomaly evidence used for calibration."""
        self._check_fitted()
        _, det_scores = self._check_detector_match(X, update_aging=False)
        det_scores = np.where(
            det_scores >= getattr(self, "confidence_threshold", 0.0),
            det_scores,
            0.0,
        )
        dist_to_self = self._min_dist_to_self(X)
        return dist_to_self + det_scores

    def score_components(self, X: np.ndarray, density_k: int = 5) -> dict[str, np.ndarray]:
        """Return raw NSA component scores before benign calibration scaling."""
        self._check_fitted()
        _, det_scores = self._check_detector_match(X, update_aging=False)
        det_scores = np.where(
            det_scores >= getattr(self, "confidence_threshold", 0.0),
            det_scores,
            0.0,
        )
        return {
            "distance": self._min_dist_to_self(X),
            "density": self._kth_dist_to_self(X, k=density_k),
            "detector": det_scores.astype(np.float64),
        }

    def fused_scores(
        self,
        X: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
        weights: dict | None = None,
        component_scales: dict | None = None,
        density_k: int | None = None,
    ) -> np.ndarray:
        """Return calibrated weighted fusion scores."""
        self._check_fitted()
        weights = weights or getattr(self, "fusion_weights_", {}) or DEFAULT_FUSION_WEIGHTS
        component_scales = component_scales or getattr(self, "fusion_component_scales_", {}) or {}
        if density_k is None:
            fusion_calibration = getattr(self, "fusion_calibration_", {})
            density_k = int(fusion_calibration.get("density_k", 5)) if fusion_calibration else 5

        components = self.score_components(X, density_k=density_k)
        if self_boundary_scores is None:
            self_boundary_scores = np.zeros(len(X), dtype=np.float64)
        components["self_boundary"] = np.asarray(self_boundary_scores, dtype=np.float64)

        fused = np.zeros(len(X), dtype=np.float64)
        for name, values in components.items():
            weight = float(weights.get(name, 0.0))
            if weight == 0.0:
                continue
            scale = float(component_scales.get(name, 1.0) or 1.0)
            scale = max(scale, MIN_COMPONENT_SCALES.get(name, 1e-9))
            normalized = np.clip(np.asarray(values, dtype=np.float64) / max(scale, 1e-9), 0.0, 2.0)
            fused += weight * normalized
        return fused

    # ------------------------------------------------------------------ #
    #  V-DETECTOR MATCHING                                                 #
    # ------------------------------------------------------------------ #

    def _check_detector_match(
        self, X: np.ndarray, update_aging: bool = True
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

        chunk_size = self._chunk_size(n_det)
        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
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
        if update_aging and self._det_match_counts_ is not None:
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

    def _kth_dist_to_self(self, X: np.ndarray, k: int = 5) -> np.ndarray:
        """k-nearest-self distance used as a local benign-density score."""
        X = np.asarray(X, dtype=np.float32)
        scale = float(np.sqrt(self.n_features_))
        n = len(X)
        result = np.empty(n, dtype=np.float64)
        kth = max(int(k), 1) - 1
        kth = min(kth, len(self.self_reference_) - 1)

        chunk_size = self._chunk_size(len(self.self_reference_))
        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            batch = X[start:end]
            x_sq = (batch * batch).sum(axis=1, keepdims=True)
            dot = batch @ self.self_reference_.T
            sq = x_sq + self._ref_sq_[np.newaxis, :] - 2.0 * dot
            np.clip(sq, 0, None, out=sq)
            kth_sq = np.partition(sq, kth, axis=1)[:, kth]
            result[start:end] = np.sqrt(kth_sq) / scale

        return result

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

        chunk_size = self._chunk_size(len(ref))
        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
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
            # PCA-whitened feature space is not bounded to [0, 1].
            candidate = base + mutation

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
