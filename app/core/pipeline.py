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
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split

from app.core.preprocessor import CICIDSPreprocessor
from app.core.evaluator import evaluate_model, compare_models, EvaluationResult
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
    ):
        self.r = r
        self.r_s = r_s
        self.max_detectors = max_detectors
        self.max_attempts = max_attempts
        self.contamination = contamination
        self.test_size = test_size
        self.random_state = random_state

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
            print(full)
            if log_callback:
                log_callback(full)

        # ── 1. INITIAL LOAD ──────────────────────────────────────────
        log("[SYSTEM] Initiating training sequence...")
        preprocessor = CICIDSPreprocessor()

        log(f"[INFO] Loading and parsing dataset{' (' + filename + ')' if filename else ''}...")
        df_raw = preprocessor._load(dataset_source, filename=filename)
        df_raw, label_col = preprocessor._find_label_col(df_raw)
        
        # Clean numeric artefacts in RAW before split
        num_cols = df_raw.select_dtypes(include=[np.number]).columns
        df_raw[num_cols] = df_raw[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Encode binary labels for splitting
        df_raw, y_all = preprocessor._encode_labels(df_raw, label_col)

        # ── 2. TRAIN/TEST SPLIT ────────────────────────────────────────
        # SPLIT RAW DATA FIRST to ensure no leakage from test set to training scaler
        log("[INFO] Creating train/test split (raw data) to prevent leakage...")
        
        df_train_raw, df_test_raw, y_train, y_test = train_test_split(
            df_raw, y_all,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y_all,
        )

        # ── 3. FIT PREPROCESSOR ON TRAINING DATA ONLY ──────────────────
        log("[INFO] Fitting feature scaler on training portion only...")
        preprocessor.fit(df_train_raw)
        
        # Transform both portions
        X_train, _ = preprocessor.transform_df(df_train_raw)
        X_test, df_test_meta = preprocessor.transform_df(df_test_raw)

        val_stats = preprocessor.validation_stats(y_all, df_raw)
        log(f"[OK] Dataset validated: {val_stats['total_records']:,} records.")
        log(f"[OK] Preprocessor fitted on {len(X_train):,} training samples.")
        
        # ── 4. TRAIN NSA ───────────────────────────────────────────────
        log("[NSA] Beginning Negative Selection Algorithm...")
        # NSA only trains on NORMAL samples
        X_train_normal = X_train[y_train == 0]
        
        nsa = NegativeSelectionDetector(
            r=self.r,
            r_s=self.r_s,
            max_detectors=self.max_detectors,
            max_attempts=self.max_attempts,
            random_state=self.random_state,
        )
        nsa.fit(X_train_normal)

        log(f"[OK] {nsa.meta_['mature_detectors']:,} V-detectors generated "
            f"(radius range: {nsa.meta_['det_radius_min']:.3f}–{nsa.meta_['det_radius_max']:.3f}).")

        # ── 5. TRAIN ISOLATION FOREST ──────────────────────────────────
        log("[INFO] Training Isolation Forest baseline...")
        iso = IsolationForestDetector(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        # Isolation Forest is semi-supervised (trains on mixed data)
        iso.fit(X_train)
        log("[OK] Isolation Forest training complete.")

        # ── 6. EVALUATE ───────────────────────────────────────────────
        log("[INFO] Evaluating models on held-out test set...")
        nsa_labels, nsa_scores = nsa.predict_with_scores(X_test)
        iso_labels, iso_scores = iso.predict_with_scores(X_test)

        nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
        iso_result = evaluate_model(y_test, iso_labels, "Isolation Forest", df_test_meta)

        log(f"[OK] NSA F1: {nsa_result.f1:.4f} | ISO F1: {iso_result.f1:.4f}")

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
        log("[SYSTEM] Status: LEARNING → ACTIVE")

        result = {
            "nsa_summary":      nsa.summary(),
            "iso_summary":      iso.summary(),
            "nsa_eval":         nsa_result.to_dict(),
            "iso_eval":         iso_result.to_dict(),
            "comparison":       comparison,
            "validation_stats": val_stats,
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
