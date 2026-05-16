"""
Self-Boundary Detector — AIS Feature-Space Immune Boundary
=============================================================
Learns the statistical profile of BENIGN (Self) traffic in the
*original* feature space (pre-PCA) and flags samples whose individual
features deviate significantly from the learned Self distribution.

Biological analogy
-------------------
While the NSA V-Detector operates in compressed PCA space (adaptive
immune system), this module models the innate immune boundary — a
fast, feature-level check that catches attacks which PCA might
compress into the normal region.

Implementation
--------------
- Fits a Gaussian profile (mean, std) per feature from BENIGN
  training data.
- At inference, computes a z-score per feature per sample.
- A feature is "violated" when |z| > threshold.
- Rare BENIGN violations receive higher weight, producing a continuous
  weighted self-boundary score for benign-calibrated fusion.
- Returns a violation ratio, continuous anomaly score, and
  human-readable evidence strings.

The detector never uses attack labels for fitting or scoring.
"""

import numpy as np
import pandas as pd
import joblib
import os
from typing import Optional

from app.core.calibration import conformal_threshold


class SelfBoundaryDetector:
    """
    Per-feature quantile-fence anomaly detector for BENIGN traffic.

    Parameters
    ----------
    z_threshold : float
        Z-score magnitude above which a feature is considered violated.
        Default 3.0 (≈0.3% of a normal distribution per tail).
    min_violations_ratio : float
        Minimum fraction of features that must be violated to flag
        a sample as anomalous via the self-boundary path alone.
        Default 0.15 (15% of features).
    """

    def __init__(
        self,
        z_threshold: float = 2.5,
        min_violations_ratio: float = 0.08,
        lower_quantile: float = 0.005,
        upper_quantile: float = 0.995,
    ):
        self.z_threshold = z_threshold
        self.min_violations_ratio = min_violations_ratio
        self.lower_quantile = lower_quantile
        self.upper_quantile = upper_quantile

        # Fitted state
        self.feature_names_: list[str] | None = None
        self.boundary_mode_: str = "quantile_fence"
        self.lower_bounds_: np.ndarray | None = None
        self.upper_bounds_: np.ndarray | None = None
        self.centers_: np.ndarray | None = None
        self.robust_scales_: np.ndarray | None = None
        self.boundary_eps_: np.ndarray | None = None
        self.means_: np.ndarray | None = None
        self.stds_: np.ndarray | None = None
        self.feature_weights_: np.ndarray | None = None
        self.benign_violation_rates_: np.ndarray | None = None
        self.weighted_threshold_: float | None = None
        self.weighted_calibration_: dict = {}
        self.is_fitted_: bool = False
        self.n_features_: int = 0
        self.meta_: dict = {}

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def fit(
        self,
        df_benign: pd.DataFrame,
        feature_columns: list[str],
    ) -> "SelfBoundaryDetector":
        """
        Learn per-feature empirical quantile fences from BENIGN training rows.

        Parameters
        ----------
        df_benign : pd.DataFrame
            Raw BENIGN training data (pre-PCA, pre-scaling).
        feature_columns : list[str]
            Column names of the numeric features to model.
        """
        available = [c for c in feature_columns if c in df_benign.columns]
        if not available:
            raise ValueError(
                "No matching feature columns found in benign DataFrame. "
                f"Expected some of: {feature_columns[:10]}"
            )

        self.feature_names_ = available
        self.n_features_ = len(available)

        X = df_benign[available].values.astype(np.float64)

        # Replace inf with NaN, then compute stats ignoring NaN
        X = np.where(np.isfinite(X), X, np.nan)

        self.boundary_mode_ = "quantile_fence"
        self.lower_bounds_ = np.nanquantile(X, self.lower_quantile, axis=0)
        self.upper_bounds_ = np.nanquantile(X, self.upper_quantile, axis=0)
        self.centers_ = np.nanmedian(X, axis=0)
        q25 = np.nanquantile(X, 0.25, axis=0)
        q75 = np.nanquantile(X, 0.75, axis=0)
        mad = np.nanmedian(np.abs(X - self.centers_), axis=0)
        iqr_scale = (q75 - q25) / 1.349
        mad_scale = 1.4826 * mad
        fence_width = self.upper_bounds_ - self.lower_bounds_
        self.robust_scales_ = np.maximum.reduce([
            np.abs(iqr_scale),
            np.abs(mad_scale),
            np.abs(fence_width),
            np.ones_like(fence_width, dtype=np.float64),
        ])
        self.boundary_eps_ = np.maximum(np.abs(fence_width) * 1e-9, 1e-9)

        constant_mask = np.abs(fence_width) < 1e-12
        violations = self._quantile_violations(X)
        violation_counts = np.nansum(violations, axis=0)
        smooth_rates = (violation_counts + 1.0) / (len(X) + 2.0)
        violation_rates = np.asarray(violation_counts / max(len(X), 1), dtype=np.float64)

        # Rare benign violations are more informative. Constant features are not
        # useful for boundary scoring, so give them zero weight.
        raw_weights = -np.log(np.clip(smooth_rates, 1e-12, 1.0))
        raw_weights[constant_mask] = 0.0
        if float(raw_weights.sum()) <= 0.0:
            raw_weights = np.ones_like(raw_weights, dtype=np.float64)
            raw_weights[constant_mask] = 0.0
        if float(raw_weights.sum()) <= 0.0:
            raw_weights = np.ones_like(raw_weights, dtype=np.float64)

        self.benign_violation_rates_ = violation_rates.astype(np.float64)
        self.feature_weights_ = (raw_weights / raw_weights.sum()).astype(np.float64)

        n_constant = int(constant_mask.sum())
        self.is_fitted_ = True
        self.meta_ = {
            "algorithm": "Quantile Fence Self-Boundary (AIS Innate Immune)",
            "boundary_mode": self.boundary_mode_,
            "lower_quantile": self.lower_quantile,
            "upper_quantile": self.upper_quantile,
            "z_threshold": self.z_threshold,
            "min_violations_ratio": self.min_violations_ratio,
            "score_mode": "weighted_feature_violation",
            "n_features_modelled": self.n_features_,
            "n_constant_features": n_constant,
            "n_training_samples": len(X),
            "weighted_threshold": self.weighted_threshold_,
            "weighted_calibration": self.weighted_calibration_,
        }
        return self

    # ------------------------------------------------------------------ #
    #  SCORING                                                             #
    # ------------------------------------------------------------------ #

    def score(
        self,
        df: pd.DataFrame,
    ) -> tuple[np.ndarray, np.ndarray, list[list[str]]]:
        """
        Score samples against the learned BENIGN self-boundary.

        Parameters
        ----------
        df : pd.DataFrame
            Raw feature data (same column schema as training).

        Returns
        -------
        violation_ratios : ndarray of float, shape (n_samples,)
            Fraction of features violated per sample (0.0 to 1.0).
        anomaly_flags : ndarray of bool, shape (n_samples,)
            True if violation_ratio > min_violations_ratio.
        evidence : list of list of str
            Per-sample human-readable evidence strings.
        """
        self._check_fitted()
        n = len(df)

        X = self._aligned_array(df)

        details = self._score_details(X)
        violations = details["violations"]

        # Per-sample unweighted and weighted violation scores.
        violation_counts = violations.sum(axis=1)
        violation_ratios = violation_counts / self.n_features_
        weighted_scores = details["weighted_scores"]

        # Anomaly flag
        if self.weighted_threshold_ is not None:
            anomaly_flags = weighted_scores > self.weighted_threshold_
        else:
            anomaly_flags = violation_ratios > self.min_violations_ratio

        # Build evidence strings (top violations per sample)
        evidence = []
        for row_idx in range(n):
            row_evidence = []
            if not anomaly_flags[row_idx]:
                evidence.append(row_evidence)
                continue

            # Get violated feature indices, sorted by violation magnitude
            violated_indices = np.where(violations[row_idx])[0]
            sorted_by_z = violated_indices[
                np.argsort(details["excess"][row_idx, violated_indices])[::-1]
            ]

            # Top 5 most extreme violations
            for feat_idx in sorted_by_z[:5]:
                feat_name = self.feature_names_[feat_idx]
                if self.boundary_mode_ == "gaussian_zscore_legacy":
                    z_val = details["signed"][row_idx, feat_idx]
                    direction = "above" if z_val > 0 else "below"
                    row_evidence.append(
                        f"{feat_name} {direction} BENIGN self boundary "
                        f"(z={z_val:+.1f})"
                    )
                else:
                    val = X[row_idx, feat_idx]
                    direction = "above" if val > self.upper_bounds_[feat_idx] else "below"
                    bound = self.upper_bounds_[feat_idx] if direction == "above" else self.lower_bounds_[feat_idx]
                    row_evidence.append(
                        f"{feat_name} {direction} BENIGN quantile fence "
                        f"(value={val:.3g}, bound={bound:.3g})"
                    )

            evidence.append(row_evidence)

        return violation_ratios, anomaly_flags, evidence

    def weighted_score(self, df: pd.DataFrame) -> np.ndarray:
        """Return continuous self-boundary anomaly scores for fusion."""
        self._check_fitted()
        X = self._aligned_array(df)
        return self._score_details(X)["weighted_scores"].astype(np.float64)

    def calibrate_weighted_threshold(
        self,
        df_benign: pd.DataFrame,
        target_fpr: float = 0.05,
    ) -> dict:
        """Calibrate weighted self-boundary threshold from BENIGN rows only."""
        self._check_fitted()
        scores = self.weighted_score(df_benign)
        if len(scores) == 0:
            raise ValueError("Cannot calibrate self-boundary without benign rows")

        target_fpr = float(np.clip(target_fpr, 0.0001, 0.5))
        threshold_info = conformal_threshold(scores, target_fpr)
        threshold = float(threshold_info["threshold"])
        observed_fpr = float(threshold_info["observed_fpr"])
        self.weighted_threshold_ = threshold
        self.weighted_calibration_ = {
            "mode": "unsupervised_benign_weighted_self_boundary",
            "target_fpr": round(float(threshold_info["target_fpr"]), 6),
            "observed_fpr": round(observed_fpr, 6),
            "normal_pass_rate": round(float(threshold_info["normal_pass_rate"]), 6),
            "threshold": round(threshold, 6),
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
        self.meta_["weighted_threshold"] = self.weighted_threshold_
        self.meta_["weighted_calibration"] = self.weighted_calibration_
        return self.weighted_calibration_

    def score_array(
        self,
        X_raw: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Score from a raw numpy array (columns must match feature_names_ order).

        Returns (violation_ratios, anomaly_flags) without evidence strings
        for performance in bulk scoring.
        """
        self._check_fitted()
        X = np.asarray(X_raw, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Truncate or pad to match fitted features
        n_cols = X.shape[1]
        if n_cols > self.n_features_:
            X = X[:, : self.n_features_]
        elif n_cols < self.n_features_:
            pad = np.zeros((X.shape[0], self.n_features_ - n_cols))
            X = np.hstack([X, pad])

        details = self._score_details(X)
        violations = details["violations"]
        violation_ratios = violations.sum(axis=1) / self.n_features_
        weighted_scores = details["weighted_scores"]
        if self.weighted_threshold_ is not None:
            anomaly_flags = weighted_scores > self.weighted_threshold_
        else:
            anomaly_flags = violation_ratios > self.min_violations_ratio

        return violation_ratios.astype(np.float64), anomaly_flags

    # ------------------------------------------------------------------ #
    #  HELPERS                                                             #
    # ------------------------------------------------------------------ #

    def _check_fitted(self):
        if not self.is_fitted_:
            raise RuntimeError(
                "SelfBoundaryDetector not fitted. Call fit() first."
            )
        self._ensure_compat()

    def _ensure_compat(self):
        """Populate fields missing from older persisted artifacts."""
        if not hasattr(self, "boundary_mode_"):
            self.boundary_mode_ = "quantile_fence"
        if not hasattr(self, "lower_quantile"):
            self.lower_quantile = 0.005
        if not hasattr(self, "upper_quantile"):
            self.upper_quantile = 0.995
        if not hasattr(self, "lower_bounds_"):
            self.lower_bounds_ = None
        if not hasattr(self, "upper_bounds_"):
            self.upper_bounds_ = None
        if not hasattr(self, "centers_"):
            self.centers_ = None
        if not hasattr(self, "robust_scales_"):
            self.robust_scales_ = None
        if not hasattr(self, "boundary_eps_"):
            self.boundary_eps_ = None
        if self.lower_bounds_ is None or self.upper_bounds_ is None:
            self.boundary_mode_ = "gaussian_zscore_legacy"
        if not hasattr(self, "feature_weights_") or self.feature_weights_ is None:
            n = max(int(getattr(self, "n_features_", 0) or 0), 1)
            self.feature_weights_ = np.ones(n, dtype=np.float64) / n
        if not hasattr(self, "benign_violation_rates_"):
            self.benign_violation_rates_ = np.zeros_like(self.feature_weights_, dtype=np.float64)
        if not hasattr(self, "weighted_threshold_"):
            self.weighted_threshold_ = None
        if not hasattr(self, "weighted_calibration_"):
            self.weighted_calibration_ = {}

    def _aligned_array(self, df: pd.DataFrame) -> np.ndarray:
        """Align input DataFrame to fitted feature order, filling missing with 0."""
        n = len(df)
        X = np.zeros((n, self.n_features_), dtype=np.float64)
        for i, col in enumerate(self.feature_names_):
            if col in df.columns:
                vals = pd.to_numeric(df[col], errors="coerce").fillna(0).values
                X[:, i] = vals
        return X

    def _quantile_violations(self, X: np.ndarray) -> np.ndarray:
        low = self.lower_bounds_[np.newaxis, :] - self.boundary_eps_[np.newaxis, :]
        high = self.upper_bounds_[np.newaxis, :] + self.boundary_eps_[np.newaxis, :]
        return (X < low) | (X > high)

    def _score_details(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """Return violation details for either current or legacy boundary mode."""
        X = np.asarray(X, dtype=np.float64)
        if self.boundary_mode_ == "gaussian_zscore_legacy":
            z_scores = (X - self.means_) / self.stds_
            z_abs = np.abs(z_scores)
            violations = z_abs > self.z_threshold
            return {
                "violations": violations,
                "weighted_scores": self._weighted_from_z_abs(z_abs),
                "excess": z_abs,
                "signed": z_scores,
            }

        violations = self._quantile_violations(X)
        low_excess = np.maximum((self.lower_bounds_[np.newaxis, :] - X), 0.0)
        high_excess = np.maximum((X - self.upper_bounds_[np.newaxis, :]), 0.0)
        excess = np.maximum(low_excess, high_excess) / np.maximum(
            self.robust_scales_[np.newaxis, :],
            1e-9,
        )
        weights = self.feature_weights_
        if weights is None:
            weights = np.ones(self.n_features_, dtype=np.float64) / max(self.n_features_, 1)
        weighted_binary = violations @ weights
        weighted_excess = np.clip(excess, 0.0, 3.0) @ weights
        return {
            "violations": violations,
            "weighted_scores": weighted_binary + weighted_excess,
            "excess": excess,
            "signed": X - self.centers_[np.newaxis, :],
        }

    def _weighted_from_z_abs(self, z_abs: np.ndarray) -> np.ndarray:
        """Weighted continuous violation score from absolute z-scores."""
        excess = np.maximum((z_abs / max(self.z_threshold, 1e-9)) - 1.0, 0.0)
        violation_mask = z_abs > self.z_threshold
        weights = self.feature_weights_
        if weights is None:
            weights = np.ones(self.n_features_, dtype=np.float64) / max(self.n_features_, 1)
        weighted_binary = violation_mask @ weights
        weighted_excess = np.clip(excess, 0.0, 3.0) @ weights
        return weighted_binary + weighted_excess

    def summary(self) -> dict:
        if not self.is_fitted_:
            return {"status": "not_fitted"}
        self._ensure_compat()
        summary = {"status": "fitted", **self.meta_}
        summary["boundary_mode"] = self.boundary_mode_
        summary["lower_quantile"] = getattr(self, "lower_quantile", None)
        summary["upper_quantile"] = getattr(self, "upper_quantile", None)
        summary["weighted_threshold"] = self.weighted_threshold_
        summary["weighted_calibration"] = self.weighted_calibration_
        return summary

    # ------------------------------------------------------------------ #
    #  PERSISTENCE                                                         #
    # ------------------------------------------------------------------ #

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> "SelfBoundaryDetector":
        return joblib.load(path)

    def __repr__(self):
        status = "fitted" if self.is_fitted_ else "unfitted"
        return (
            f"SelfBoundaryDetector("
            f"z_threshold={self.z_threshold}, "
            f"min_violations_ratio={self.min_violations_ratio}, "
            f"status={status})"
        )
