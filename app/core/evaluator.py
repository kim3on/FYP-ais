"""
Model Evaluator
================
Computes classification metrics for both the NSA and Isolation Forest models,
enabling the comparative analysis described in the FYP report (Stage 5).

Metrics computed:
  - Accuracy, Precision, Recall, F1-Score (binary)
  - Confusion matrix
  - Detection rate per attack category
  - False positive rate
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from dataclasses import dataclass, field, asdict
from typing import Optional
import pandas as pd


@dataclass
class EvaluationResult:
    """Holds all metrics for one model evaluation run."""
    model_name: str
    accuracy:   float
    precision:  float
    recall:     float
    f1:         float
    tp: int  # true positives  (correctly flagged attacks)
    tn: int  # true negatives  (correctly passed normal)
    fp: int  # false positives (normal flagged as attack)
    fn: int  # false negatives (attacks missed)
    false_positive_rate: float
    detection_rate:      float
    per_category: dict = field(default_factory=dict)
    n_samples:   int = 0
    n_attacks:   int = 0
    n_normal:    int = 0
    evaluated_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # Round floats for JSON neatness
        for k in ("accuracy", "precision", "recall", "f1",
                  "false_positive_rate", "detection_rate"):
            d[k] = round(d[k], 4)
        return d


def evaluate_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    model_name: str,
    df_meta: Optional[pd.DataFrame] = None,
) -> EvaluationResult:
    """
    Evaluate a binary classifier (0=normal, 1=attack).

    Parameters
    ----------
    y_true     : ground-truth binary labels
    y_pred     : predicted binary labels
    model_name : display name for the result
    df_meta    : optional DataFrame with 'attack_category' for per-category stats
    """
    from datetime import datetime

    acc  = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec  = float(recall_score(y_true, y_pred, zero_division=0))
    f1   = float(f1_score(y_true, y_pred, zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    n_attacks = int(y_true.sum())
    n_normal  = int(len(y_true) - n_attacks)

    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    dr  = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0

    # Per-category detection rates
    per_category = {}
    if df_meta is not None and "attack_category" in df_meta.columns:
        categories = df_meta["attack_category"].unique()
        for cat in categories:
            mask = df_meta["attack_category"] == cat
            cat_true = y_true[mask]
            cat_pred = y_pred[mask]
            if cat == "normal":
                # For normal traffic, measure: how many are correctly passed (not FP)
                correct = int((cat_pred == 0).sum())
                total   = len(cat_true)
            else:
                correct = int(((cat_true == 1) & (cat_pred == 1)).sum())
                total   = int((cat_true == 1).sum())
            per_category[cat] = {
                "correct": correct,
                "total":   total,
                "rate":    round(correct / total, 4) if total > 0 else 0.0,
            }

    return EvaluationResult(
        model_name=model_name,
        accuracy=acc,
        precision=prec,
        recall=rec,
        f1=f1,
        tp=tp, tn=tn, fp=fp, fn=fn,
        false_positive_rate=fpr,
        detection_rate=dr,
        per_category=per_category,
        n_samples=len(y_true),
        n_attacks=n_attacks,
        n_normal=n_normal,
        evaluated_at=datetime.utcnow().isoformat(),
    )


def compare_models(
    results: list[EvaluationResult],
) -> dict:
    """
    Build a side-by-side comparison dictionary for the dashboard.
    """
    comparison = {
        "models": [r.model_name for r in results],
        "metrics": {},
    }
    for metric in ("accuracy", "precision", "recall", "f1",
                   "false_positive_rate", "detection_rate"):
        comparison["metrics"][metric] = {
            r.model_name: getattr(r, metric) for r in results
        }

    # Determine which model wins on each metric
    winners = {}
    for metric, values in comparison["metrics"].items():
        # For FPR, lower is better; everything else higher is better
        if metric == "false_positive_rate":
            winners[metric] = min(values, key=values.get)
        else:
            winners[metric] = max(values, key=values.get)
    comparison["winners"] = winners

    return comparison


def severity_from_score(score: float) -> str:
    """Map a [0,1] anomaly confidence score to a severity label."""
    if score >= 0.90:
        return "critical"
    elif score >= 0.75:
        return "high"
    elif score >= 0.50:
        return "medium"
    else:
        return "low"
