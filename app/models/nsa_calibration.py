"""Benign-only calibration logic for the NSA/V-Detector model."""

import numpy as np

from app.core.calibration import calibration_reliability, conformal_threshold
from app.models.nsa_config import (
    DEFAULT_FUSION_WEIGHTS,
    DISABLED_FUSION_CALIBRATION,
    MIN_COMPONENT_SCALES,
)


class NSACalibrationMixin:
    """Threshold and legacy fusion calibration helpers."""

    def calibrate_threshold(
        self,
        X_benign: np.ndarray,
        target_fpr: float = 0.10,
    ) -> dict:
        """
        Calibrate the pure NSA self-gap threshold from benign rows only.

        The final decision rule is:
            v_detector_match OR self_distance > threshold

        Detector matches and self-gap are reported together, but the self-gap
        cutoff is still calibrated from benign distance quantiles even when the
        detector path already exceeds the target false-positive budget.
        """
        self._check_fitted()
        if len(X_benign) == 0:
            raise ValueError("Cannot calibrate NSA threshold without benign calibration rows")

        target_fpr = float(np.clip(target_fpr, 0.0001, 0.5))
        scores = self.anomaly_scores(X_benign)
        detector_matches, detector_scores = self._check_detector_match(X_benign, update_aging=False)
        detector_matches = detector_matches.astype(bool)
        finite_mask = np.isfinite(scores)
        scores = scores[finite_mask]
        detector_matches = detector_matches[finite_mask]
        sorted_scores = np.sort(scores)
        if len(sorted_scores) == 0:
            raise ValueError("Cannot calibrate NSA threshold without finite benign scores")

        detector_only_fpr = float(detector_matches.mean())
        residual_fpr_budget = max(target_fpr - detector_only_fpr, 0.0)
        fallback_self_gap_budget = min(target_fpr * 0.5, 0.05)
        self_gap_target_fpr = residual_fpr_budget if residual_fpr_budget > 0.0 else fallback_self_gap_budget
        self_gap_scores = scores[~detector_matches]
        if len(self_gap_scores) == 0:
            self_gap_scores = scores

        threshold_info = conformal_threshold(self_gap_scores, self_gap_target_fpr)
        threshold = float(threshold_info["threshold"])
        observed_fpr = float((detector_matches | (scores > threshold)).mean())
        target_achieved = observed_fpr <= target_fpr + 1e-12
        if target_achieved:
            reason = (
                "Selected a benign-only conformal self-gap threshold whose full "
                "pure-NSA benign FPR stays within target."
            )
        elif detector_only_fpr > target_fpr:
            reason = (
                "V-detector benign match rate exceeds target FPR; self-gap remains "
                "conformal-calibrated instead of being disabled by a max-distance outlier."
            )
        else:
            reason = (
                "Self-gap was conformal-calibrated from benign distances, but overlap "
                "with detector matches still exceeded the requested FPR target."
            )

        high = float(np.quantile(scores, 0.999))
        self.score_threshold_ = threshold
        self.score_scale_ = max(high, threshold * 1.5, threshold + 1e-9)
        self.target_fpr = target_fpr
        rank = int(threshold_info["rank_index"])
        self_gap_only_fpr = float(((~detector_matches) & (scores > threshold)).mean())
        self.calibration_ = {
            "mode": "unsupervised_benign_pure_nsa",
            "score_mode": "self_gap_distance",
            "target_fpr": round(float(target_fpr), 6),
            "self_gap_target_fpr": round(float(self_gap_target_fpr), 6),
            "observed_fpr": round(observed_fpr, 6),
            "normal_pass_rate": round(1.0 - observed_fpr, 6),
            "threshold": round(threshold, 6),
            "score_scale": round(self.score_scale_, 6),
            "n_calibration_samples": int(len(sorted_scores)),
            "self_gap_calibration_samples": int(len(self_gap_scores)),
            "rank_index": rank,
            "rank_index_zero_based": rank - 1,
            "calibration_reliability": calibration_reliability(len(sorted_scores)),
            "decision_rule": "v_detector_match OR self_distance > threshold",
            "target_achieved": bool(target_achieved and observed_fpr <= target_fpr + 1e-12),
            "target_achievement_reason": reason,
            "detector_match_fpr": round(detector_only_fpr, 6),
            "self_gap_only_fpr": round(self_gap_only_fpr, 6),
            "detector_match_count": int(detector_matches.sum()),
            "score_min": round(float(scores.min()), 6),
            "score_median": round(float(np.median(scores)), 6),
            "score_p95": round(float(np.quantile(scores, 0.95)), 6),
            "score_p99": round(float(np.quantile(scores, 0.99)), 6),
            "score_max": round(float(scores.max()), 6),
        }
        self.fusion_threshold_ = None
        self.fusion_score_scale_ = None
        self.fusion_weights_ = {}
        self.fusion_component_scales_ = {}
        self.fusion_calibration_ = dict(DISABLED_FUSION_CALIBRATION)
        self.meta_["score_threshold"] = self.score_threshold_
        self.meta_["fusion_threshold"] = self.fusion_threshold_
        self.meta_["target_fpr"] = self.target_fpr
        self.meta_["calibration"] = self.calibration_
        self.meta_["fusion_calibration"] = self.fusion_calibration_
        return self.calibration_

    def calibrate_fusion(
        self,
        X_benign: np.ndarray,
        self_boundary_scores: np.ndarray | None = None,
        target_fpr: float = 0.10,
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
