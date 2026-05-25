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
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split

from app.core.datasets import (
    DATASET_CICIDS2017,
    DATASET_NSL_KDD,
    artifact_paths,
    dataset_display_name,
    legacy_cicids_paths,
    normalize_dataset_type,
)
from app.core.nsl_kdd_preprocessor import NSLKDDPreprocessor
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
_DEFAULT_PATHS  = artifact_paths(DATASET_CICIDS2017)
NSA_PATH        = _DEFAULT_PATHS.nsa
ISO_PATH        = _DEFAULT_PATHS.iso
PREP_PATH       = _DEFAULT_PATHS.preprocessor
SB_PATH         = _DEFAULT_PATHS.self_boundary
PCA_SB_PATH     = _DEFAULT_PATHS.pca_self_boundary
RESULTS_PATH    = _DEFAULT_PATHS.results

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
        max_detectors: int = 3000,
        max_attempts: int = 100_000,
        contamination: float = 0.05,
        test_size: float = 0.2,
        random_state: int = 42,
        n_pca_components: float | int | None = 0.95,
        target_fpr: float = 0.10,
        benign_row_limit: int | None = 20_000,
        dataset_type: str = DATASET_CICIDS2017,
    ):
        self.dataset_type = normalize_dataset_type(dataset_type)
        self.paths = artifact_paths(self.dataset_type)
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

        os.makedirs(self.paths.root, exist_ok=True)

    def _make_preprocessor(self):
        if self.dataset_type == DATASET_NSL_KDD:
            return NSLKDDPreprocessor(n_pca_components=self.n_pca_components)
        return CICIDSPreprocessor(n_pca_components=self.n_pca_components)

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
            if log_callback:
                log_callback(full)
            # Console output is best-effort only. Windows detached/reload
            # processes can expose invalid stdout handles; logging must never
            # abort training.
            try:
                import sys
                if hasattr(sys.stdout, "buffer"):
                    sys.stdout.buffer.write((full + "\n").encode("utf-8", errors="replace"))
                else:
                    sys.stdout.write(full + "\n")
                sys.stdout.flush()
            except (OSError, ValueError):
                pass

        # ── 1. INITIAL LOAD ──────────────────────────────────────────
        log("[SYSTEM] Initiating training sequence...")
        log(f"[INFO] Dataset profile: {dataset_display_name(self.dataset_type)}")
        preprocessor = self._make_preprocessor()

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

        # ── 4. TRAIN SELF-BOUNDARY DETECTORS ───────────────────────────
        log("[SB] Training raw Self-Boundary detector on BENIGN raw features for evidence...")
        df_train_features = preprocessor.clean_feature_frame(df_train_raw)
        df_cal_features = preprocessor.clean_feature_frame(df_cal_raw)
        df_test_features = preprocessor.clean_feature_frame(df_test_raw)
        raw_sb = SelfBoundaryDetector(
            z_threshold=2.0,
            min_violations_ratio=0.15,
        )
        raw_sb.fit(df_train_features, preprocessor.feature_columns_)
        log(
            f"[OK] Raw Self-Boundary fitted: {raw_sb.n_features_} features modelled "
            f"(z-threshold={raw_sb.z_threshold}, min-violations={raw_sb.min_violations_ratio:.0%})."
        )

        log("[SB] Training PCA-space Self-Boundary detector for supporting evidence...")
        X_train_pca_df = preprocessor.pca_dataframe(X_train)
        X_cal_pca_df = preprocessor.pca_dataframe(X_cal)
        X_test_pca_df = preprocessor.pca_dataframe(X_test)
        pca_feature_columns = preprocessor.pca_feature_names(X_train.shape[1])
        pca_sb = SelfBoundaryDetector(
            z_threshold=2.0,
            min_violations_ratio=0.15,
        )
        pca_sb.fit(X_train_pca_df, pca_feature_columns)
        log(
            f"[OK] PCA Self-Boundary fitted: {pca_sb.n_features_} PCA components modelled "
            "(used for supporting evidence)."
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

        log("[INFO] Calibrating raw self-boundary on BENIGN calibration rows for evidence...")
        raw_sb_calibration = raw_sb.calibrate_weighted_threshold(
            df_cal_features[preprocessor.feature_columns_],
            target_fpr=self.target_fpr,
        )
        if raw_sb_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "Raw self-boundary calibration reliability is experimental because the "
                "benign calibration sample is small."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] Raw self-boundary weighted threshold: {raw_sb_calibration['threshold']:.6f} "
            f"(observed FPR {raw_sb_calibration['observed_fpr'] * 100:.2f}%)."
        )

        log("[INFO] Calibrating PCA self-boundary on BENIGN calibration rows...")
        pca_sb_calibration = pca_sb.calibrate_weighted_threshold(
            X_cal_pca_df,
            target_fpr=self.target_fpr,
        )
        if pca_sb_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "PCA self-boundary calibration reliability is experimental because the "
                "benign calibration sample is small."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] PCA self-boundary weighted threshold: {pca_sb_calibration['threshold']:.6f} "
            f"(observed FPR {pca_sb_calibration['observed_fpr'] * 100:.2f}%)."
        )

        calibration_summary = nsa_calibration
        log("[INFO] Weighted fusion disabled: final AIS decision is V-detector OR calibrated self-gap.")

        # ── 6. TRAIN ISOLATION FOREST ──────────────────────────────────
        log("[INFO] Training Isolation Forest baseline on BENIGN rows only...")
        iso = IsolationForestDetector(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        iso.fit(X_train)
        iso_calibration = iso.calibrate_threshold(
            X_cal,
            target_fpr=self.target_fpr,
        )
        if iso_calibration.get("calibration_reliability") == "experimental":
            warning = (
                "Isolation Forest calibration reliability is experimental because "
                "the benign calibration sample is small."
            )
            training_warnings.append(warning)
            log(f"[WARN] {warning}")
        log(
            f"[OK] Isolation Forest calibrated threshold: {iso_calibration['threshold']:.6f} "
            f"(target FPR {iso_calibration['target_fpr'] * 100:.2f}%, "
            f"observed {iso_calibration['observed_fpr'] * 100:.2f}%)."
        )
        log("[OK] Isolation Forest training complete.")

        # ── 7. EVALUATE ───────────────────────────────────────────────
        log("[INFO] Evaluating benign holdout false-positive behaviour...")
        nsa_labels, _ = nsa.predict_with_scores(X_test)
        iso_labels, _ = iso.predict_with_scores(X_test)

        # Evaluate pure NSA on benign test rows. Self-Boundary is evidence only.
        test_components = nsa.decision_components(
            X_test,
        )
        _, pca_sb_test_flags, _ = pca_sb.score(X_test_pca_df)
        _, raw_sb_test_flags, _ = raw_sb.score(df_test_features[preprocessor.feature_columns_])
        test_components["pca_self_boundary_match"] = np.asarray(pca_sb_test_flags, dtype=bool)
        test_components["raw_self_boundary_evidence_match"] = np.asarray(raw_sb_test_flags, dtype=bool)

        y_test = np.zeros(len(X_test), dtype=int)
        nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
        iso_result = evaluate_model(y_test, iso_labels, "Isolation Forest", df_test_meta)
        nsa_silhouette = compute_silhouette_metric(X_test, nsa_labels, random_state=self.random_state)
        iso_silhouette = compute_silhouette_metric(X_test, iso_labels, random_state=self.random_state)
        self_intrusion_rate = nsa_result.false_positive_rate
        benign_source_decomposition = source_decomposition_metrics(
            y_test,
            test_components,
        )

        log(
            f"[OK] Pure NSA benign FPR: {nsa_result.false_positive_rate:.4f} | "
            f"ISO benign FPR: {iso_result.false_positive_rate:.4f}"
        )
        log(
            f"[OK] AIS Self Intrusion Rate (pure NSA): {self_intrusion_rate * 100:.2f}% "
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
        iso_labelled_verification = {
            "available": False,
            "reason": "No labelled attack rows were available for Isolation Forest post-run verification.",
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
            X_label_pca_df = preprocessor.pca_dataframe(X_label_eval)
            label_pred, _, label_raw_scores = nsa.predict_with_details(X_label_eval)
            label_components = nsa.decision_components(
                X_label_eval,
            )
            _, pca_sb_label_flags, _ = pca_sb.score(X_label_pca_df)
            raw_label_features = preprocessor.clean_feature_frame(df_label_eval_raw)
            _, raw_sb_label_flags, _ = raw_sb.score(raw_label_features[preprocessor.feature_columns_])
            label_components["pca_self_boundary_match"] = np.asarray(pca_sb_label_flags, dtype=bool)
            label_components["raw_self_boundary_evidence_match"] = np.asarray(raw_sb_label_flags, dtype=bool)
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
                "AIS (Pure NSA) labelled verification",
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
                target_fpr=(0.0, self.target_fpr),
                forced_positive_mask=label_components.get("v_detector_match"),
            )
            labelled_metrics["source_decomposition"] = source_decomposition_metrics(
                y_label_true,
                label_components,
            )
            labelled_metrics["source_verification"] = labelled_metrics["source_decomposition"]
            labelled_metrics["verification_note"] = (
                "Attack labels are used only after unsupervised prediction to report "
                "recall, FNR, FPR, precision, and threshold tradeoffs. They do not "
                "modify saved model artifacts or thresholds."
            )
            labelled_verification = labelled_metrics
            iso_label_pred, _ = iso.predict_with_scores(X_label_eval)
            iso_label_raw_scores = iso.raw_anomaly_scores(X_label_eval)
            iso_labelled_metrics = evaluate_model(
                y_label_true,
                iso_label_pred.astype(int),
                "Isolation Forest baseline labelled verification",
                df_label_meta,
            ).to_dict()
            iso_labelled_metrics["available"] = True
            iso_labelled_metrics["verification_mode"] = "post_run_labelled_verification"
            iso_labelled_metrics["verification_only"] = True
            iso_labelled_metrics["baseline_only"] = True
            iso_labelled_metrics["sampled_attack_rows"] = bool(attack_eval_sampled)
            iso_labelled_metrics["n_eval_attacks_available"] = int(len(df_attack_raw))
            iso_labelled_metrics["n_eval_attacks_used"] = int(len(attack_eval))
            iso_labelled_metrics["n_eval_benign_used"] = int(len(df_test_raw))
            iso_labelled_metrics["threshold_analysis"] = threshold_analysis(
                y_label_true,
                iso_label_raw_scores,
                model_name="Isolation Forest baseline threshold analysis",
                target_fpr=(0.0, self.target_fpr),
            )
            iso_labelled_metrics["verification_note"] = (
                "Isolation Forest is an unsupervised BENIGN-only baseline. Labels "
                "are used only after prediction to verify baseline performance."
            )
            iso_labelled_verification = iso_labelled_metrics
            log(
                "[OK] Labelled verification: "
                f"Recall={labelled_metrics.get('recall')} | "
                f"FNR={labelled_metrics.get('false_negative_rate')} | "
                f"FPR={labelled_metrics.get('false_positive_rate')}"
            )

        comparison = compare_models([nsa_result, iso_result])

        # ── 8. SAVE ARTEFACTS ──────────────────────────────────────────
        log("[INFO] Saving trained models to disk...")
        nsa.save(self.paths.nsa)
        iso.save(self.paths.iso)
        raw_sb.save(self.paths.self_boundary)
        pca_sb.save(self.paths.pca_self_boundary)
        preprocessor.save(self.paths.preprocessor)
        log("[OK] Models saved successfully (NSA, ISO, raw SB, PCA SB, Preprocessor).")

        # ── 9. COMPILE RESULT ──────────────────────────────────────────
        duration = (datetime.now() - t0).total_seconds()
        log(f"[METRICS] Total pipeline duration: {duration:.2f} seconds")
        log("[SYSTEM] Status: LEARNING -> ACTIVE")

        nsa_only_eval = nsa_result.to_dict()
        nsa_eval = nsa_result.to_dict()
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
            "dataset_type":     self.dataset_type,
            "dataset_display":  dataset_display_name(self.dataset_type),
            "batch_only":       self.dataset_type == DATASET_NSL_KDD,
            "nsa_summary":      nsa.summary(),
            "iso_summary":      iso.summary(),
            "sb_summary":       raw_sb.summary(),
            "raw_self_boundary_summary": raw_sb.summary(),
            "pca_self_boundary_summary": pca_sb.summary(),
            "nsa_eval":         nsa_eval,
            "nsa_only_eval":    nsa_only_eval,
            "iso_eval":         iso_eval,
            "comparison":       comparison,
            "validation_stats": val_stats,
            "validation_mode":   "strict_unsupervised_benign_pure_nsa_calibrated",
            "benign_row_limit": self.benign_row_limit,
            "benign_rows_available": benign_rows_available,
            "benign_rows_used": int(len(df_benign)),
            "training_warnings": training_warnings,
            "calibration_summary": calibration_summary,
            "calibration_reliability": calibration_summary.get("calibration_reliability"),
            "nsa_calibration_summary": nsa_calibration,
            "iso_calibration_summary": iso_calibration,
            "self_boundary_mode": "evidence_only_pca_raw",
            "self_boundary_calibration_summary": pca_sb_calibration,
            "pca_self_boundary_calibration_summary": pca_sb_calibration,
            "raw_self_boundary_calibration_summary": raw_sb_calibration,
            "post_run_labelled_verification": labelled_verification,
            "iso_post_run_labelled_verification": iso_labelled_verification,
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
            "source_decomposition": benign_source_decomposition,
            "metric_explanations": METRIC_EXPLANATIONS,
            "detection_architecture": "pure_nsa_v_detector_self_gap",
            "unsupervised_note": (
                "Labels are used only to select BENIGN self rows and for reporting. "
                "No attack labels are used to fit PCA/scaler, train detectors, "
                "train self-boundary, or tune thresholds. The final AIS decision is "
                "a pure NSA rule: mature V-detector match OR calibrated self-gap. "
                "Self-boundary models are retained only for alert evidence."
            ),
            "duration_seconds": round(duration, 2),
            "trained_at":       t0.isoformat(),
        }
        result["nsa_summary"]["dataset_type"] = self.dataset_type
        result["nsa_summary"]["dataset_name"] = dataset_display_name(self.dataset_type)
        result["iso_summary"]["dataset_type"] = self.dataset_type
        result["iso_summary"]["dataset_name"] = dataset_display_name(self.dataset_type)

        # Persist result to disk for the dashboard to read on reload
        import json
        with open(self.paths.results, "w") as f:
            json.dump(result, f, indent=2)

        return result


# ── Convenience functions ────────────────────────────────────────────────

def _paths_with_legacy_fallback(dataset_type: str | None):
    dataset = normalize_dataset_type(dataset_type)
    paths = artifact_paths(dataset)
    fallbacks = [paths]
    if dataset == DATASET_CICIDS2017:
        fallbacks.append(legacy_cicids_paths())
    return fallbacks


def _first_existing_path(dataset_type: str | None, attr: str) -> str | None:
    for paths in _paths_with_legacy_fallback(dataset_type):
        path = getattr(paths, attr)
        if os.path.exists(path):
            return path
    return None


def load_nsa(dataset_type: str | None = DATASET_CICIDS2017) -> NegativeSelectionDetector | None:
    """Load the trained NSA model if it exists."""
    path = _first_existing_path(dataset_type, "nsa")
    if path:
        return NegativeSelectionDetector.load(path)
    return None


def load_iso(dataset_type: str | None = DATASET_CICIDS2017) -> IsolationForestDetector | None:
    """Load the trained Isolation Forest model if it exists."""
    path = _first_existing_path(dataset_type, "iso")
    if path:
        return IsolationForestDetector.load(path)
    return None


def load_preprocessor(dataset_type: str | None = DATASET_CICIDS2017):
    """Load the fitted preprocessor if it exists."""
    path = _first_existing_path(dataset_type, "preprocessor")
    if path:
        return joblib.load(path)
    return None


def load_self_boundary(dataset_type: str | None = DATASET_CICIDS2017) -> SelfBoundaryDetector | None:
    """Load the trained raw-feature Self-Boundary detector if it exists."""
    path = _first_existing_path(dataset_type, "self_boundary")
    if path:
        return SelfBoundaryDetector.load(path)
    return None


def load_pca_self_boundary(dataset_type: str | None = DATASET_CICIDS2017) -> SelfBoundaryDetector | None:
    """Load the trained PCA-space Self-Boundary detector if it exists."""
    path = _first_existing_path(dataset_type, "pca_self_boundary")
    if path:
        return SelfBoundaryDetector.load(path)
    return None


def result_path(dataset_type: str | None = DATASET_CICIDS2017) -> str:
    path = _first_existing_path(dataset_type, "results")
    return path or artifact_paths(dataset_type).results


def models_ready(dataset_type: str | None = DATASET_CICIDS2017) -> bool:
    """Returns True if trained artefacts exist on disk for the dataset profile."""
    required = ["nsa", "iso", "preprocessor", "self_boundary"]
    return all(_first_existing_path(dataset_type, attr) for attr in required)
