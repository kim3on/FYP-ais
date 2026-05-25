"""Runtime scoring logic for the NSA/V-Detector model."""

import numpy as np

from app.models.nsa_config import DEFAULT_FUSION_WEIGHTS, MIN_COMPONENT_SCALES


class NSAScoringMixin:
    """Prediction, scoring, detector matching, and refresh helpers."""

    @staticmethod
    def _runtime_threshold_factor(alert_threshold: float | None) -> float:
        if alert_threshold is None:
            return 1.0
        try:
            return max(float(alert_threshold), 1e-9) / 0.50
        except (TypeError, ValueError):
            return 1.0

    def _scaled_threshold(self, threshold: float, alert_threshold: float | None) -> float:
        return float(threshold) * self._runtime_threshold_factor(alert_threshold)

    def _scaled_threshold_and_scale(
        self,
        threshold: float,
        scale: float | None,
        alert_threshold: float | None,
    ) -> tuple[float, float]:
        factor = self._runtime_threshold_factor(alert_threshold)
        base_threshold = float(threshold)
        adjusted_threshold = base_threshold * factor
        base_scale = max(float(scale or base_threshold * 1.5), base_threshold + 1e-9)
        adjusted_scale = base_scale * factor
        return adjusted_threshold, max(adjusted_scale, adjusted_threshold + 1e-9)

    def _runtime_detector_matches(
        self,
        detector_matches: np.ndarray,
        detector_scores: np.ndarray,
        alert_threshold: float | None,
    ) -> np.ndarray:
        if alert_threshold is None:
            return detector_matches.astype(bool)
        return detector_matches.astype(bool) & (detector_scores >= float(alert_threshold))

    def predict(self, X: np.ndarray, alert_threshold: float | None = None) -> np.ndarray:
        """
        Classify samples as normal (0) or anomalous (1).

        True Negative Selection — two complementary mechanisms:

        1. **Detector match (primary / adaptive immune):**
           A sample is anomalous if it falls within the variable activation
           radius of ANY mature V-detector.

        2. **Self-gap fallback (innate immune):**
           A sample is anomalous if its distance to the nearest self-reference
           exceeds the calibrated self-gap threshold, even when no detector
           covers that region.

        A sample is flagged if EITHER condition is true.
        """
        self._check_fitted()
        scores = self.anomaly_scores(X)
        threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        threshold = self._scaled_threshold(threshold, alert_threshold)
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        detector_matches = self._runtime_detector_matches(detector_matches, detector_scores, alert_threshold)
        return ((scores > threshold) | detector_matches).astype(int)

    def predict_with_scores(
        self,
        X: np.ndarray,
        alert_threshold: float | None = None,
    ) -> tuple[np.ndarray, np.ndarray]:
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
        threshold, scale = self._scaled_threshold_and_scale(
            threshold,
            self.score_scale_,
            alert_threshold,
        )
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        detector_matches = self._runtime_detector_matches(detector_matches, detector_scores, alert_threshold)
        labels = ((raw_scores > threshold) | detector_matches).astype(int)
        confidence = np.clip((raw_scores - threshold) / max(scale - threshold, 1e-9), 0.0, 1.0)
        detector_scores = np.where(detector_matches, detector_scores, 0.0)
        confidence = np.maximum(confidence, detector_scores)
        confidence = np.where(labels == 1, confidence, 0.0)
        return labels, confidence.round(4)

    def predict_with_details(
        self, X: np.ndarray, alert_threshold: float | None = None
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns (labels, confidence_scores, dist_to_self).
        """
        self._check_fitted()
        labels, scores = self.predict_with_scores(X, alert_threshold=alert_threshold)
        dist_to_self = self._min_dist_to_self(X)
        return labels, scores, dist_to_self

    def predict_fused(
        self,
        X: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
        alert_threshold: float | None = None,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Compatibility wrapper; active NSA no longer uses weighted fusion."""
        self._check_fitted()
        labels, confidence = self.predict_with_scores(X, alert_threshold=alert_threshold)
        return labels, confidence, self.anomaly_scores(X).astype(np.float64)

    def decision_components(
        self,
        X: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
        alert_threshold: float | None = None,
    ) -> dict[str, np.ndarray]:
        """
        Return source-level decision components without changing predictions.

        D = mature V-detector match
        G = calibrated self-gap fallback
        N = pure NSA score match, identical to G for the active rule
        F = legacy fused-score slot, disabled for new pure-NSA artifacts
        """
        self._check_fitted()
        detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
        detector_matches = self._runtime_detector_matches(detector_matches, detector_scores, alert_threshold)
        distances = self._min_dist_to_self(X)
        nsa_threshold = self.score_threshold_ if self.score_threshold_ is not None else self.r
        nsa_threshold = self._scaled_threshold(nsa_threshold, alert_threshold)
        self_gap_match = (distances > nsa_threshold).astype(bool)
        disabled = np.zeros(len(distances), dtype=bool)
        disabled_scores = np.zeros(len(distances), dtype=np.float64)

        return {
            "v_detector_match": detector_matches.astype(bool),
            "self_gap_match": self_gap_match,
            "nsa_score_match": self_gap_match,
            "fusion_score_match": disabled,
            "distance": distances.astype(np.float64),
            "detector_score": detector_scores.astype(np.float64),
            "nsa_score": distances.astype(np.float64),
            "fused_score": disabled_scores,
        }

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Continuous pure-NSA self-gap evidence used for calibration."""
        self._check_fitted()
        return self._min_dist_to_self(X)

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
