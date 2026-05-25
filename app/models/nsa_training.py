"""Training logic for the NSA/V-Detector model."""

from datetime import datetime, timezone

import numpy as np

from app.models.nsa_config import MAX_DISTANCE_MATRIX_ENTRIES, SELF_REF_CAP


class NSATrainingMixin:
    """Fit-time V-detector generation."""

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
