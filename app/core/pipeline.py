"""
Training Pipeline
==================
Orchestrates the full training workflow:
  1. Load and preprocess the CIC-IDS-2017 dataset
  2. Train the NSA (AIS) model on NORMAL samples only
  3. Train the Isolation Forest baseline on all samples
  4. Evaluate both models on the test portion
  5. Save trained artefacts and return a structured result

This module is called by the FastAPI /train endpoint.
"""

import os
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split

from app.core.preprocessor import CICIDSPreprocessor
from app.core.evaluator import (
    METRIC_EXPLANATIONS,
    compare_models,
    compute_silhouette_metric,
    evaluate_model,
)
from app.models.nsa import NegativeSelectionDetector
from app.models.isolation_forest import IsolationForestDetector

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(__file__))
ARTEFACT_DIR    = os.path.join(BASE_DIR, "artefacts")
NSA_PATH        = os.path.join(ARTEFACT_DIR, "nsa_model.pkl")
ISO_PATH        = os.path.join(ARTEFACT_DIR, "iso_model.pkl")
PREP_PATH       = os.path.join(ARTEFACT_DIR, "preprocessor.pkl")
RESULTS_PATH    = os.path.join(ARTEFACT_DIR, "last_train_result.json")


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
    """

    def __init__(
        self,
        r: float = 0.3,
        r_s: float | None = None,
        max_detectors: int = 500,
        max_attempts: int = 10_000,
        contamination: float = 0.05,
        test_size: float = 0.2,
        random_state: int = 42,
        n_pca_components: float | int | None = 0.95,
    ):
        self.r = r
        self.r_s = r_s
        self.max_detectors = max_detectors
        self.max_attempts = max_attempts
        self.contamination = contamination
        self.test_size = test_size
        self.random_state = random_state
        self.n_pca_components = n_pca_components

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
        if len(df_benign) < 10:
            raise ValueError("Training requires at least 10 BENIGN rows for unsupervised calibration")

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
        X_cal, df_cal_meta = preprocessor.transform_df(df_cal_raw)
        X_test, df_test_meta = preprocessor.transform_df(df_test_raw)

        log(f"[OK] Dataset validated: {val_stats['total_records']:,} records.")
        log(
            f"[OK] BENIGN split: {len(X_train):,} train / "
            f"{len(X_cal):,} calibration / {len(X_test):,} test."
        )
        
        # ── 4. TRAIN NSA ───────────────────────────────────────────────
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

        log("[INFO] Calibrating anomaly threshold on BENIGN calibration rows only...")
        calibration = nsa.calibrate_threshold(X_cal, target_fpr=0.01)
        log(
            f"[OK] Unsupervised threshold: {calibration['threshold']:.6f} "
            f"(target FPR {calibration['target_fpr'] * 100:.2f}%, "
            f"observed {calibration['observed_fpr'] * 100:.2f}%)."
        )

        # ── 5. TRAIN ISOLATION FOREST ──────────────────────────────────
        log("[INFO] Training Isolation Forest baseline on BENIGN rows only...")
        iso = IsolationForestDetector(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        iso.fit(X_train)
        log("[OK] Isolation Forest training complete.")

        # ── 6. EVALUATE ───────────────────────────────────────────────
        log("[INFO] Evaluating benign holdout false-positive behaviour...")
        nsa_labels, nsa_scores = nsa.predict_with_scores(X_test)
        iso_labels, iso_scores = iso.predict_with_scores(X_test)

        y_test = np.zeros(len(X_test), dtype=int)
        nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
        iso_result = evaluate_model(y_test, iso_labels, "Isolation Forest", df_test_meta)
        nsa_silhouette = compute_silhouette_metric(X_test, nsa_labels, random_state=self.random_state)
        iso_silhouette = compute_silhouette_metric(X_test, iso_labels, random_state=self.random_state)
        self_intrusion_rate = nsa_result.false_positive_rate

        log(
            f"[OK] NSA benign FPR: {nsa_result.false_positive_rate:.4f} | "
            f"ISO benign FPR: {iso_result.false_positive_rate:.4f}"
        )
        log(
            f"[OK] AIS Self Intrusion Rate: {self_intrusion_rate * 100:.2f}% "
            "(benign validation flagged as anomaly)."
        )

        comparison = compare_models([nsa_result, iso_result])

        # ── 6. SAVE ARTEFACTS ──────────────────────────────────────────
        log("[INFO] Saving trained models to disk...")
        nsa.save(NSA_PATH)
        iso.save(ISO_PATH)
        preprocessor.save(PREP_PATH)
        log("[OK] Models saved successfully.")

        # ── 7. COMPILE RESULT ──────────────────────────────────────────
        duration = (datetime.now() - t0).total_seconds()
        log(f"[METRICS] Total pipeline duration: {duration:.2f} seconds")
        log("[SYSTEM] Status: LEARNING -> ACTIVE")

        nsa_eval = nsa_result.to_dict()
        nsa_eval["labelled_attack_metrics_applicable"] = False
        nsa_eval["training_metric_note"] = (
            "Benign-only training validation has no attack class; precision, recall, F1, "
            "TPR, and FNR are intentionally not reported here."
        )
        for attack_metric in ("precision", "recall", "f1", "false_negative_rate", "detection_rate", "true_positive_rate"):
            nsa_eval[attack_metric] = None
        nsa_eval["self_intrusion_rate"] = round(self_intrusion_rate, 4)
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
            "nsa_eval":         nsa_eval,
            "iso_eval":         iso_eval,
            "comparison":       comparison,
            "validation_stats": val_stats,
            "validation_mode":   "unsupervised_benign_calibrated",
            "calibration_summary": calibration,
            "ais_metrics": {
                "self_intrusion_rate": round(self_intrusion_rate, 4),
                "self_intrusion_rate_pct": round(self_intrusion_rate * 100, 2),
                "explanation": METRIC_EXPLANATIONS["self_intrusion_rate"],
            },
            "unsupervised_validation": {
                "silhouette": nsa_silhouette,
                "silhouette_score": nsa_silhouette["value"],
                "explanation": METRIC_EXPLANATIONS["silhouette_score"],
            },
            "metric_explanations": METRIC_EXPLANATIONS,
            "unsupervised_note": (
                "Labels are used only to select BENIGN self rows and for reporting. "
                "No attack labels are used to fit PCA/scaler, train detectors, or tune thresholds."
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


def models_ready() -> bool:
    """Returns True if trained artefacts exist on disk."""
    return all(os.path.exists(p) for p in [NSA_PATH, ISO_PATH, PREP_PATH])
