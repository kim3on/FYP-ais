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
        r: float = 0.5,
        max_detectors: int = 500,
        max_attempts: int = 10_000,
        contamination: float = 0.05,
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        self.r = r
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
        """
        Execute the full training pipeline.

        Returns a JSON-serialisable result dict containing:
          - nsa_summary      : NSA model metadata
          - iso_summary      : IsolationForest metadata
          - nsa_eval         : NSA evaluation metrics
          - iso_eval         : IsolationForest evaluation metrics
          - comparison       : side-by-side model comparison
          - validation_stats : dataset statistics
          - duration_seconds : total training time
        """
        t0 = datetime.utcnow()

        def log(msg: str):
            ts = datetime.utcnow().strftime("%H:%M:%S")
            full = f"[{ts}] {msg}"
            print(full)
            if log_callback:
                log_callback(full)

        # ── 1. PRE-PROCESSING ──────────────────────────────────────────
        log("[SYSTEM] Initiating training sequence...")
        preprocessor = CICIDSPreprocessor()

        log(f"[INFO] Loading and parsing dataset{' (' + filename + ')' if filename else ''}...")
        X_normal, y, df = preprocessor.fit_transform(dataset_source, filename=filename)

        val_stats = preprocessor.validation_stats(y, df)
        log(f"[OK] Dataset validated: {val_stats['total_records']:,} records.")
        log(f"[OK] Feature normalization complete — {val_stats['n_features']} features after encoding.")
        log(f"[OK] Self baseline (normal traffic): {val_stats['normal_records']:,} samples.")
        log(f"[INFO] Attack traffic in dataset: {val_stats['attack_records']:,} samples.")

        # ── 2. TRAIN/TEST SPLIT ────────────────────────────────────────
        # CIC-IDS-2017 is all-numeric — preprocessor already returned a
        # clean feature matrix. We re-scale all rows for evaluation.
        log("[INFO] Creating train/test split for model evaluation...")

        # Re-apply the fitted scaler to get X_all_scaled from the full cleaned df
        df_feat = df.drop(columns=[c for c in ['attack_category', 'Label', ' Label', 'label'] if c in df.columns], errors='ignore')
        # Select only the feature columns the preprocessor registered
        for col in preprocessor.feature_columns_:
            if col not in df_feat.columns:
                df_feat[col] = 0.0
        df_feat = df_feat[preprocessor.feature_columns_]
        df_feat = df_feat.select_dtypes(include=[np.number]).fillna(0).replace([np.inf, -np.inf], 0).clip(-1e12, 1e12)
        X_all_scaled = preprocessor.scaler_.transform(df_feat.values.astype(np.float32))

        X_train_all, X_test, y_train_all, y_test = train_test_split(
            X_all_scaled, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )

        # NSA only sees NORMAL samples during training
        X_train_normal = X_train_all[y_train_all == 0]
        log(f"[OK] Train/test split: {len(X_train_all):,} train · {len(X_test):,} test.")

        # ── 3. TRAIN NSA ───────────────────────────────────────────────
        log("[NSA] Beginning Negative Selection Algorithm...")
        log(f"[NSA] Parameters: r={self.r}, max_detectors={self.max_detectors}, "
            f"max_attempts={self.max_attempts:,}")

        nsa = NegativeSelectionDetector(
            r=self.r,
            max_detectors=self.max_detectors,
            max_attempts=self.max_attempts,
            random_state=self.random_state,
        )
        nsa.fit(X_train_normal)

        log(f"[WARN] {nsa.meta_['candidates_rejected']:,} candidates rejected (self-match).")
        log(f"[OK] {nsa.meta_['mature_detectors']:,} valid antibodies generated and stored.")
        cap = nsa.meta_.get('self_match_cap', nsa.meta_.get('n_self_samples', '?'))
        n_self_total = nsa.meta_.get('n_self_samples', '?')
        if cap != n_self_total:
            log(f"[INFO] Self-match used {cap:,}-row subsample of {n_self_total:,} normal rows (speed optimisation).")

        # ── 4. TRAIN ISOLATION FOREST ──────────────────────────────────
        log("[INFO] Training Isolation Forest baseline...")
        iso = IsolationForestDetector(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        iso.fit(X_train_all)
        log("[OK] Isolation Forest training complete.")

        # ── 5. EVALUATE BOTH MODELS ────────────────────────────────────
        log("[INFO] Evaluating NSA model on test set...")
        nsa_labels, nsa_scores = nsa.predict_with_scores(X_test)

        log("[INFO] Evaluating Isolation Forest on test set...")
        iso_labels, iso_scores = iso.predict_with_scores(X_test)

        # Build df_meta slice for per-category stats
        all_indices = list(range(len(y)))
        _, idx_test = train_test_split(
            all_indices,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )
        df_test_meta = df.iloc[idx_test].reset_index(drop=True)

        nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
        iso_result = evaluate_model(y_test, iso_labels, "Isolation Forest", df_test_meta)

        log(f"[OK] NSA  — Accuracy: {nsa_result.accuracy:.1%}, "
            f"Recall: {nsa_result.recall:.1%}, F1: {nsa_result.f1:.4f}")
        log(f"[OK] ISO  — Accuracy: {iso_result.accuracy:.1%}, "
            f"Recall: {iso_result.recall:.1%}, F1: {iso_result.f1:.4f}")

        comparison = compare_models([nsa_result, iso_result])

        # ── 6. SAVE ARTEFACTS ──────────────────────────────────────────
        log("[INFO] Saving trained models to disk...")
        nsa.save(NSA_PATH)
        iso.save(ISO_PATH)
        preprocessor.save(PREP_PATH)
        log("[OK] Models saved successfully.")

        # ── 7. COMPILE RESULT ──────────────────────────────────────────
        duration = (datetime.utcnow() - t0).total_seconds()
        log(f"[COMPLETE] Training pipeline finished in {duration:.1f}s.")
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
