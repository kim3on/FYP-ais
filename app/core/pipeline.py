"""
Training Pipeline
==================
Orchestrates the full training workflow:
  1. Load and preprocess the CIC-IDS-2017 dataset
  2. Train the NSA (AIS) model on NORMAL samples only
  3. Train the Self-Boundary detector on NORMAL raw features
  4. Train the Isolation Forest baseline on all samples
  5. Evaluate both models on the test portion
  6. Save trained artefacts and return a structured result

This module is called by the FastAPI /train endpoint.
"""

import os
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split

from app.core.preprocessor import CICIDSPreprocessor
from app.core.evaluator import (
    METRIC_EXPLANATIONS,
    assess_metric,
    compare_models,
    compute_silhouette_metric,
    evaluate_model,
    source_decomposition_metrics,
    threshold_analysis,
)
from app.models.nsa import NegativeSelectionDetector
from app.models.isolation_forest import IsolationForestDetector
from app.models.self_boundary import SelfBoundaryDetector

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(__file__))
ARTEFACT_DIR    = os.path.join(BASE_DIR, "artefacts")
NSA_PATH        = os.path.join(ARTEFACT_DIR, "nsa_model.pkl")
ISO_PATH        = os.path.join(ARTEFACT_DIR, "iso_model.pkl")
PREP_PATH       = os.path.join(ARTEFACT_DIR, "preprocessor.pkl")
SB_PATH         = os.path.join(ARTEFACT_DIR, "self_boundary.pkl")
RESULTS_PATH    = os.path.join(ARTEFACT_DIR, "last_train_result.json")

MIN_BENIGN_ROWS_HARD = 100
MIN_BENIGN_ROWS_RECOMMENDED = 1_000
MIN_CALIBRATION_ROWS_RECOMMENDED = 200
MAX_LABELLED_EVAL_ATTACK_ROWS = 50_000
MIN_TRAINING_DETECTORS = 10
MAX_TRAINING_DETECTORS = 10_000
MAX_TRAINING_ATTEMPTS = 200_000
MAX_BENIGN_ROW_LIMIT = 100_000


class TrainingPipeline:
    """
    Full end-to-end training pipeline.

    Parameters
    ----------
    r : float
        NSA detector radius.
    max_detectors : int
        Maximum number of mature NSA antibodies.
    max_attempts : int
        Maximum NSA candidate generation attempts.
    contamination : float
        Isolation Forest expected contamination fraction.
    test_size : float
        Fraction of data held out for evaluation.
    random_state : int
        Global reproducibility seed.
    target_fpr : float
        Target false positive rate for NSA threshold calibration.
    """

    def __init__(
        self,
        r: float = 0.3,
        r_s: float | None = None,
        max_detectors: int = 1500,
        max_attempts: int = 40_000,
        contamination: float = 0.05,
        test_size: float = 0.2,
        random_state: int = 42,
        n_pca_components: float | int | None = 0.95,
        target_fpr: float = 0.05,
        benign_row_limit: int | None = 20_000,
    ):
        self.r = float(np.clip(r, 0.01, 5.0))
        self.r_s = float(np.clip(r_s, 0.01, 5.0)) if r_s is not None else None
        self.max_detectors = int(np.clip(max_detectors, MIN_TRAINING_DETECTORS, MAX_TRAINING_DETECTORS))
        self.max_attempts = int(np.clip(max_attempts, self.max_detectors, MAX_TRAINING_ATTEMPTS))
        self.contamination = float(np.clip(contamination, 0.001, 0.20))
        self.test_size = float(np.clip(test_size, 0.10, 0.40))
        self.random_state = random_state
        self.n_pca_components = n_pca_components
        self.target_fpr = float(np.clip(target_fpr, 0.01, 0.20))
        self.benign_row_limit = (
            int(np.clip(benign_row_limit, MIN_BENIGN_ROWS_HARD, MAX_BENIGN_ROW_LIMIT))
            if benign_row_limit and benign_row_limit > 0
            else None
        )

        os.makedirs(ARTEFACT_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  MAIN ENTRY POINT                                                    #
    # ------------------------------------------------------------------ #

    def run(
        self,
        dataset_source,          # file path, bytes, or file-like
        log_callback=None,       # callable(str) — streams logs to caller
        filename: str = '',      # original upload filename for format detection
    ) -> dict:
        t0 = datetime.now()

        def log(msg: str):
            ts = datetime.now().strftime("%H:%M:%S")
            full = f"[{ts}] {msg}"
            # Use sys.stdout with replace errors to avoid cp1252 crashes on Windows
            import sys
            sys.stdout.buffer.write((full + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()
            if log_callback:
                log_callback(full)

        # ── 1. INITIAL LOAD ──────────────────────────────────────────
        log("[SYSTEM] Initiating training sequence...")
        preprocessor = CICIDSPreprocessor(n_pca_components=self.n_pca_components)

        log(f"[INFO] Loading and parsing dataset{' (' + filename + ')' if filename else ''}...")
        df_raw = preprocessor._load(dataset_source, filename=filename)
        df_raw, label_col = preprocessor._find_label_col(df_raw)
        
        # Clean numeric artefacts in RAW before split
        num_cols = df_raw.select_dtypes(include=[np.number]).columns
        df_raw[num_cols] = df_raw[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Encode binary labels for splitting
        df_raw, y_all = preprocessor._encode_labels(df_raw, label_col)

        # ── 2. UNSUPERVISED BENIGN SPLITS ──────────────────────────────
        # Labels are used only to select BENIGN rows for self training.
        # Attack labels never influence scaler/PCA, NSA fitting, or threshold tuning.
        val_stats = preprocessor.validation_stats(y_all, df_raw)
        benign_mask = y_all == 0
        df_benign = df_raw.loc[benign_mask].reset_index(drop=True)
        df_attack_raw = df_raw.loc[~benign_mask].reset_index(drop=True)
        training_warnings = []
        if len(df_benign) < MIN_BENIGN_ROWS_HARD:
            raise ValueError(
                f"Training requires at least {MIN_BENIGN_ROWS_HARD} BENIGN rows "
                "for unsupervised NSA calibration"
            )
        if len(df_benign) < MIN_BENIGN_ROWS_RECOMMENDED:
            training_warnings.append(
                f"Only {len(df_benign):,} BENIGN rows found; use at least "
                f"{MIN_BENIGN_ROWS_RECOMMENDED:,} for more stable unsupervised calibration."
            )
        benign_rows_available = len(df_benign)
        if self.benign_row_limit is not None and benign_rows_available > self.benign_row_limit:
            df_benign = (
                df_benign
                .sample(n=int(self.benign_row_limit), random_state=self.random_state)
                .reset_index(drop=True)
            )
            log(
                f"[INFO] BENIGN self-profile rows capped by user input: "
                f"{len(df_benign):,} of {benign_rows_available:,} available."
            )

        log("[INFO] Creating BENIGN-only train/calibration/test splits...")
        holdout_size = min(max(self.test_size * 2, 0.2), 0.5)
        df_train_raw, df_holdout_raw = train_test_split(
            df_benign,
            test_size=holdout_size,
            random_state=self.random_state,
            shuffle=True,
        )
        df_cal_raw, df_test_raw = train_test_split(
            df_holdout_raw,
            test_size=0.5,
            random_state=self.random_state,
            shuffle=True,
        )

        # ── 3. FIT PREPROCESSOR ON TRAINING DATA ONLY ──────────────────
        log("[INFO] Fitting feature scaler on BENIGN training rows only...")
        preprocessor.fit(df_train_raw)
        val_stats["n_features"] = len(preprocessor.feature_columns_ or [])
        
        # Transform benign-only portions
        X_train, _ = preprocessor.transform_df(df_train_raw)
        X_cal, _ = preprocessor.transform_df(df_cal_raw)
        X_test, df_test_meta = preprocessor.transform_df(df_test_raw)

        log(f"[OK] Dataset validated: {val_stats['total_records']:,} records.")
        log(
            f"[OK] BENIGN split: {len(X_train):,} train / "
            f"{len(X_cal):,} calibration / {len(X_test):,} test."
        )
        if len(X_cal) < MIN_CALIBRATION_ROWS_RECOMMENDED or len(X_test) < MIN_CALIBRATION_ROWS_RECOMMENDED:
            training_warnings.append(
                f"Calibration/test splits are small ({len(X_cal):,}/{len(X_test):,}); "
                f"{MIN_CALIBRATION_ROWS_RECOMMENDED:,}+ rows each is recommended."
            )
        for warning in training_warnings:
            log(f"[WARN] {warning}")

        # ── 4. TRAIN SELF-BOUNDARY DETECTOR ─────────────────────────────
        log("[SB] Training Self-Boundary detector on BENIGN raw features...")
        sb = SelfBoundaryDetector(
            z_threshold=2.0,
            min_violations_ratio=0.15,
        )
        sb.fit(df_train_raw, preprocessor.feature_columns_)
        log(
            f"[OK] Self-Boundary fitted: {sb.n_features_} features modelled "
            f"(z-threshold={sb.z_threshold}, min-violations={sb.min_violations_ratio:.0%})."
        )

        # ── 5. TRAIN NSA ───────────────────────────────────────────────
        log("[NSA] Beginning Negative Selection Algorithm...")
        nsa = NegativeSelectionDetector(
            r=self.r,
            r_s=self.r_s,
            max_detectors=self.max_detectors,
            max_attempts=self.max_attempts,
            random_state=self.random_state,
        )
        nsa.fit(X_train)

        log(f"[OK] {nsa.meta_['mature_detectors']:,} V-detectors generated "
            f"(radius range: {nsa.meta_['det_radius_min']:.3f}-{nsa.meta_['det_radius_max']:.3f}).")

        log(f"[INFO] Calibrating NSA-only threshold on BENIGN calibration rows (target FPR={self.target_fpr*100:.1f}%)...")
        nsa_calibration = nsa.calibrate_threshold(X_cal, target_fpr=self.target_fpr)
        if nsa_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "NSA calibration reliability is experimental because fewer than "
                f"{MIN_CALIBRATION_ROWS_RECOMMENDED:,} benign calibration rows were available."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] NSA-only threshold: {nsa_calibration['threshold']:.6f} "
            f"(target FPR {nsa_calibration['target_fpr'] * 100:.2f}%, "
            f"observed {nsa_calibration['observed_fpr'] * 100:.2f}%)."
        )

        log("[INFO] Calibrating weighted self-boundary on BENIGN calibration rows...")
        sb_cal_scores = sb.weighted_score(df_cal_raw[preprocessor.feature_columns_])
        sb_calibration = sb.calibrate_weighted_threshold(
            df_cal_raw[preprocessor.feature_columns_],
            target_fpr=self.target_fpr,
        )
        if sb_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "Self-boundary calibration reliability is experimental because the "
                "benign calibration sample is small."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] Self-boundary weighted threshold: {sb_calibration['threshold']:.6f} "
            f"(observed FPR {sb_calibration['observed_fpr'] * 100:.2f}%)."
        )

        log("[INFO] Calibrating fused AIS score on BENIGN calibration rows only...")
        fusion_calibration = nsa.calibrate_fusion(
            X_cal,
            self_boundary_scores=sb_cal_scores,
            target_fpr=self.target_fpr,
        )
        if fusion_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "Fused AIS calibration reliability is experimental because the "
                "benign calibration sample is small."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] Fused AIS threshold: {fusion_calibration['threshold']:.6f} "
            f"(target FPR {fusion_calibration['target_fpr'] * 100:.2f}%, "
            f"observed {fusion_calibration['observed_fpr'] * 100:.2f}%)."
        )

        # ── 6. TRAIN ISOLATION FOREST ──────────────────────────────────
        log("[INFO] Training Isolation Forest baseline on BENIGN rows only...")
        iso = IsolationForestDetector(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        iso.fit(X_train)
        log("[OK] Isolation Forest training complete.")

        # ── 7. EVALUATE ───────────────────────────────────────────────
        log("[INFO] Evaluating benign holdout false-positive behaviour...")
        nsa_labels, _ = nsa.predict_with_scores(X_test)
        iso_labels, _ = iso.predict_with_scores(X_test)

        # Evaluate fused AIS score on benign test rows.
        sb_test_scores = sb.weighted_score(df_test_raw[preprocessor.feature_columns_])
        fused_labels, _, _ = nsa.predict_fused(
            X_test,
            self_boundary_scores=sb_test_scores,
        )
        test_components = nsa.decision_components(
            X_test,
            self_boundary_scores=sb_test_scores,
        )

        y_test = np.zeros(len(X_test), dtype=int)
        nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
        fused_result = evaluate_model(y_test, fused_labels, "AIS (Fused NSA + Self-Boundary)", df_test_meta)
        iso_result = evaluate_model(y_test, iso_labels, "Isolation Forest", df_test_meta)
        nsa_silhouette = compute_silhouette_metric(X_test, fused_labels, random_state=self.random_state)
        iso_silhouette = compute_silhouette_metric(X_test, iso_labels, random_state=self.random_state)
        self_intrusion_rate = fused_result.false_positive_rate
        benign_source_decomposition = source_decomposition_metrics(
            y_test,
            test_components,
        )

        log(
            f"[OK] NSA-only benign FPR: {nsa_result.false_positive_rate:.4f} | "
            f"Fused AIS benign FPR: {fused_result.false_positive_rate:.4f} | "
            f"ISO benign FPR: {iso_result.false_positive_rate:.4f}"
        )
        log(
            f"[OK] AIS Self Intrusion Rate (combined): {self_intrusion_rate * 100:.2f}% "
            "(benign validation flagged as anomaly)."
        )
        sir_assessment = assess_metric("self_intrusion_rate", self_intrusion_rate)
        log(f"[OK] Self Intrusion assessment: {sir_assessment['grade']}")

        labelled_verification = {
            "available": False,
            "reason": "No labelled attack rows were available for post-run verification.",
            "verification_mode": "post_run_labelled_verification",
            "verification_only": True,
        }
        if len(df_attack_raw) > 0:
            log("[INFO] Running report-only labelled verification after unsupervised training...")
            attack_eval = df_attack_raw
            attack_eval_sampled = False
            if len(attack_eval) > MAX_LABELLED_EVAL_ATTACK_ROWS:
                attack_eval = attack_eval.sample(
                    n=MAX_LABELLED_EVAL_ATTACK_ROWS,
                    random_state=self.random_state,
                )
                attack_eval_sampled = True

            df_label_eval_raw = pd.concat(
                [df_test_raw, attack_eval],
                ignore_index=True,
            )
            X_label_eval, df_label_meta = preprocessor.transform_df(df_label_eval_raw)
            sb_label_features = preprocessor._clean(df_label_eval_raw.copy(), inference=True)
            sb_label_scores = sb.weighted_score(sb_label_features[preprocessor.feature_columns_])
            label_pred, _, label_raw_scores = nsa.predict_fused(
                X_label_eval,
                self_boundary_scores=sb_label_scores,
            )
            label_components = nsa.decision_components(
                X_label_eval,
                self_boundary_scores=sb_label_scores,
            )
            y_label_true = (
                df_label_meta["attack_category"]
                .fillna("Unknown")
                .astype(str)
                .str.lower()
                .ne("normal")
                .astype(int)
                .to_numpy()
            )
            labelled_metrics = evaluate_model(
                y_label_true,
                label_pred.astype(int),
                "AIS (Fused NSA + Self-Boundary) labelled verification",
                df_label_meta,
            ).to_dict()
            labelled_metrics["available"] = True
            labelled_metrics["verification_mode"] = "post_run_labelled_verification"
            labelled_metrics["verification_only"] = True
            labelled_metrics["sampled_attack_rows"] = bool(attack_eval_sampled)
            labelled_metrics["n_eval_attacks_available"] = int(len(df_attack_raw))
            labelled_metrics["n_eval_attacks_used"] = int(len(attack_eval))
            labelled_metrics["n_eval_benign_used"] = int(len(df_test_raw))
            labelled_metrics["threshold_analysis"] = threshold_analysis(
                y_label_true,
                label_raw_scores,
                model_name="AIS labelled threshold analysis",
            )
            labelled_metrics["source_decomposition"] = source_decomposition_metrics(
                y_label_true,
                label_components,
            )
            labelled_metrics["verification_note"] = (
                "Attack labels are used only after unsupervised prediction to report "
                "recall, FNR, FPR, precision, and threshold tradeoffs. They do not "
                "modify saved model artifacts or thresholds."
            )
            labelled_verification = labelled_metrics
            log(
                "[OK] Labelled verification: "
                f"Recall={labelled_metrics.get('recall')} | "
                f"FNR={labelled_metrics.get('false_negative_rate')} | "
                f"FPR={labelled_metrics.get('false_positive_rate')}"
            )

        comparison = compare_models([fused_result, iso_result])

        # ── 8. SAVE ARTEFACTS ──────────────────────────────────────────
        log("[INFO] Saving trained models to disk...")
        nsa.save(NSA_PATH)
        iso.save(ISO_PATH)
        sb.save(SB_PATH)
        preprocessor.save(PREP_PATH)
        log("[OK] Models saved successfully (NSA, ISO, Self-Boundary, Preprocessor).")

        # ── 9. COMPILE RESULT ──────────────────────────────────────────
        duration = (datetime.now() - t0).total_seconds()
        log(f"[METRICS] Total pipeline duration: {duration:.2f} seconds")
        log("[SYSTEM] Status: LEARNING -> ACTIVE")

        nsa_only_eval = nsa_result.to_dict()
        nsa_eval = fused_result.to_dict()
        nsa_eval["labelled_attack_metrics_applicable"] = False
        nsa_eval["training_metric_note"] = (
            "Benign-only training validation has no attack class; precision, recall, F1, "
            "TPR, and FNR are intentionally not reported here."
        )
        for attack_metric in ("precision", "recall", "f1", "false_negative_rate", "detection_rate", "true_positive_rate"):
            nsa_eval[attack_metric] = None
        nsa_eval["self_intrusion_rate"] = round(self_intrusion_rate, 4)
        nsa_eval["self_intrusion_assessment"] = sir_assessment
        nsa_eval["silhouette_score"] = nsa_silhouette["value"]
        nsa_eval["silhouette"] = nsa_silhouette

        iso_eval = iso_result.to_dict()
        iso_eval["labelled_attack_metrics_applicable"] = False
        iso_eval["training_metric_note"] = (
            "Benign-only training validation has no attack class; precision, recall, F1, "
            "TPR, and FNR are intentionally not reported here."
        )
        for attack_metric in ("precision", "recall", "f1", "false_negative_rate", "detection_rate", "true_positive_rate"):
            iso_eval[attack_metric] = None
        iso_eval["silhouette_score"] = iso_silhouette["value"]
        iso_eval["silhouette"] = iso_silhouette

        result = {
            "nsa_summary":      nsa.summary(),
            "iso_summary":      iso.summary(),
            "sb_summary":       sb.summary(),
            "nsa_eval":         nsa_eval,
            "nsa_only_eval":    nsa_only_eval,
            "iso_eval":         iso_eval,
            "comparison":       comparison,
            "validation_stats": val_stats,
            "validation_mode":   "strict_unsupervised_benign_fusion_calibrated",
            "benign_row_limit": self.benign_row_limit,
            "benign_rows_available": benign_rows_available,
            "benign_rows_used": int(len(df_benign)),
            "training_warnings": training_warnings,
            "calibration_summary": fusion_calibration,
            "nsa_calibration_summary": nsa_calibration,
            "self_boundary_calibration_summary": sb_calibration,
            "post_run_labelled_verification": labelled_verification,
            "ais_metrics": {
                "self_intrusion_rate": round(self_intrusion_rate, 4),
                "self_intrusion_rate_pct": round(self_intrusion_rate * 100, 2),
                "self_intrusion_assessment": sir_assessment,
                "explanation": METRIC_EXPLANATIONS["self_intrusion_rate"],
            },
            "unsupervised_validation": {
                "silhouette": nsa_silhouette,
                "silhouette_score": nsa_silhouette["value"],
                "source_decomposition": benign_source_decomposition,
                "silhouette_assessment": assess_metric(
                    "silhouette_score",
                    nsa_silhouette["value"],
                ),
                "explanation": METRIC_EXPLANATIONS["silhouette_score"],
            },
            "metric_explanations": METRIC_EXPLANATIONS,
            "detection_architecture": "two_layer_ais_score_fusion",
            "unsupervised_note": (
                "Labels are used only to select BENIGN self rows and for reporting. "
                "No attack labels are used to fit PCA/scaler, train detectors, "
                "train self-boundary, calibrate fusion weights/scales, or tune thresholds."
            ),
            "duration_seconds": round(duration, 2),
            "trained_at":       t0.isoformat(),
        }

        # Persist result to disk for the dashboard to read on reload
        import json
        with open(RESULTS_PATH, "w") as f:
            json.dump(result, f, indent=2)

        return result


# ── Convenience functions ────────────────────────────────────────────────

def load_nsa() -> NegativeSelectionDetector | None:
    """Load the trained NSA model if it exists."""
    if os.path.exists(NSA_PATH):
        return NegativeSelectionDetector.load(NSA_PATH)
    return None


def load_iso() -> IsolationForestDetector | None:
    """Load the trained Isolation Forest model if it exists."""
    if os.path.exists(ISO_PATH):
        return IsolationForestDetector.load(ISO_PATH)
    return None


def load_preprocessor() -> CICIDSPreprocessor | None:
    """Load the fitted preprocessor if it exists."""
    if os.path.exists(PREP_PATH):
        return CICIDSPreprocessor.load(PREP_PATH)
    return None


def load_self_boundary() -> SelfBoundaryDetector | None:
    """Load the trained Self-Boundary detector if it exists."""
    if os.path.exists(SB_PATH):
        return SelfBoundaryDetector.load(SB_PATH)
    return None


def models_ready() -> bool:
    """Returns True if trained artefacts exist on disk."""
    return all(os.path.exists(p) for p in [NSA_PATH, ISO_PATH, PREP_PATH, SB_PATH])
