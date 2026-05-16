"""
Model Evaluator
================
Computes classification metrics for both the NSA and Isolation Forest models,
enabling the comparative analysis described in the FYP report (Stage 5).

Metrics computed:
  - Accuracy, Precision, Recall, F1-Score (binary)
  - Confusion matrix
  - Detection rate / TPR, FNR, FPR
  - Threshold trade-off analysis for labelled post-run verification
  - Silhouette score for predicted normal/anomaly groups
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    silhouette_score,
)
from dataclasses import dataclass, field, asdict
from typing import Optional
import pandas as pd

METRIC_EXPLANATIONS = {
    "tp": "True Positives: attack flows correctly flagged as anomalies.",
    "tn": "True Negatives: benign flows correctly passed as normal.",
    "fp": "False Positives: benign flows incorrectly flagged as anomalies.",
    "fn": "False Negatives: attack flows missed as normal.",
    "recall": "Recall / Detection Rate / TPR: percentage of real attacks caught. Main IDS metric.",
    "false_negative_rate": "FNR: percentage of real attacks missed. Lower is better.",
    "false_positive_rate": "FPR: percentage of benign flows incorrectly alerted. Lower is better.",
    "precision": "Precision: percentage of alerts that are true attacks.",
    "f1": "F1-score: harmonic mean of precision and recall.",
    "accuracy": "Accuracy: overall correctness, reported as secondary because IDS datasets are imbalanced.",
    "silhouette_score": (
        "Silhouette Score: unsupervised separation of predicted normal/anomaly groups in PCA space. "
        "It does not prove attack-detection correctness."
    ),
    "self_intrusion_rate": (
        "Self Intrusion Rate: benign validation samples incorrectly flagged by NSA. "
        "AIS autoimmunity check; lower is better."
    ),
}

# ── Target ranges for metric assessment grading ──────────────────────────
# These encode the desired and prototype-acceptable performance bands.
METRIC_TARGETS = {
    "recall": {
        "desired": (0.92, 0.97),
        "acceptable": (0.85, 0.92),
        "higher_is_better": True,
    },
    "false_negative_rate": {
        "desired": (0.03, 0.08),
        "acceptable": (0.08, 0.15),
        "higher_is_better": False,
    },
    "false_positive_rate": {
        "desired": (0.03, 0.06),
        "acceptable": (0.06, 0.10),
        "higher_is_better": False,
    },
    "precision": {
        "desired": (0.80, 0.92),
        "acceptable": (0.70, 0.80),
        "higher_is_better": True,
    },
    "f1": {
        "desired": (0.85, 0.94),
        "acceptable": (0.75, 0.85),
        "higher_is_better": True,
    },
    "silhouette_score": {
        "desired": (0.35, 0.65),
        "acceptable": (0.20, 0.35),
        "higher_is_better": True,
    },
    "self_intrusion_rate": {
        "desired": (0.0, 0.05),
        "acceptable": (0.05, 0.10),
        "higher_is_better": False,
    },
}


def assess_metric(
    metric_name: str,
    value: float | None,
) -> dict:
    """
    Grade a metric value against the project target ranges.

    Returns
    -------
    {
        "grade": "target_met" | "prototype_acceptable" | "needs_improvement" | "not_applicable",
        "desired_range": [lo, hi] | null,
        "acceptable_range": [lo, hi] | null,
        "value": float | null
    }
    """
    if value is None or metric_name not in METRIC_TARGETS:
        return {
            "grade": "not_applicable",
            "desired_range": None,
            "acceptable_range": None,
            "value": value,
        }

    target = METRIC_TARGETS[metric_name]
    d_lo, d_hi = target["desired"]
    a_lo, a_hi = target["acceptable"]

    if target["higher_is_better"]:
        if value >= d_lo:
            grade = "target_met"
        elif value >= a_lo:
            grade = "prototype_acceptable"
        else:
            grade = "needs_improvement"
    elif value <= d_hi:
        grade = "target_met"
    elif value <= a_hi:
        grade = "prototype_acceptable"
    else:
        grade = "needs_improvement"

    return {
        "grade": grade,
        "desired_range": [d_lo, d_hi],
        "acceptable_range": [a_lo, a_hi],
        "value": round(value, 4) if value is not None else None,
    }


@dataclass
class EvaluationResult:
    """Holds all metrics for one model evaluation run."""
    model_name: str
    accuracy:   float
    precision:  float | None
    recall:     float | None
    f1:         float | None
    tp: int  # true positives  (correctly flagged attacks)
    tn: int  # true negatives  (correctly passed normal)
    fp: int  # false positives (normal flagged as attack)
    fn: int  # false negatives (attacks missed)
    false_positive_rate: float | None
    false_negative_rate: float | None
    detection_rate:      float | None
    true_positive_rate:  float | None
    per_category: dict = field(default_factory=dict)
    n_samples:   int = 0
    n_attacks:   int = 0
    n_normal:    int = 0
    evaluated_at: str = ""
    metric_assessment: dict = field(default_factory=dict)
    metric_explanations: dict = field(default_factory=lambda: METRIC_EXPLANATIONS)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Round floats for JSON neatness
        for k in ("accuracy", "precision", "recall", "f1",
                  "false_positive_rate", "false_negative_rate",
                  "detection_rate", "true_positive_rate"):
            if d[k] is not None:
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

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else None
    fnr = float(fn / (tp + fn)) if (tp + fn) > 0 else None
    dr  = float(tp / (tp + fn)) if (tp + fn) > 0 else None

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

    # Determine if metrics are applicable (N/A when no attacks present)
    has_attacks = n_attacks > 0

    # Build metric assessment grading
    assessment = {}
    if has_attacks:
        assessment["recall"] = assess_metric("recall", rec)
        assessment["false_negative_rate"] = assess_metric("false_negative_rate", fnr)
        assessment["false_positive_rate"] = assess_metric("false_positive_rate", fpr)
        assessment["precision"] = assess_metric("precision", prec)
        assessment["f1"] = assess_metric("f1", f1)
    else:
        for m in ("recall", "false_negative_rate", "precision", "f1"):
            assessment[m] = assess_metric(m, None)
        assessment["false_positive_rate"] = assess_metric("false_positive_rate", fpr)

    return EvaluationResult(
        model_name=model_name,
        accuracy=acc,
        precision=prec if has_attacks else None,
        recall=rec if has_attacks else None,
        f1=f1 if has_attacks else None,
        tp=tp, tn=tn, fp=fp, fn=fn,
        false_positive_rate=fpr,
        false_negative_rate=fnr if has_attacks else None,
        detection_rate=dr if has_attacks else None,
        true_positive_rate=dr if has_attacks else None,
        per_category=per_category,
        n_samples=len(y_true),
        n_attacks=n_attacks,
        n_normal=n_normal,
        metric_assessment=assessment,
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
                   "false_positive_rate", "false_negative_rate",
                   "detection_rate", "true_positive_rate"):
        comparison["metrics"][metric] = {
            r.model_name: getattr(r, metric) for r in results
        }

    # Determine which model wins on each metric
    winners = {}
    for metric, values in comparison["metrics"].items():
        valid_values = {
            name: value for name, value in values.items()
            if value is not None
        }
        if not valid_values:
            winners[metric] = None
            continue
        # For FPR, lower is better; everything else higher is better
        if metric in ("false_positive_rate", "false_negative_rate"):
            winners[metric] = min(valid_values, key=valid_values.get)
        else:
            winners[metric] = max(valid_values, key=valid_values.get)
    comparison["winners"] = winners

    return comparison


def source_decomposition_metrics(
    y_true: np.ndarray,
    components: dict,
) -> dict:
    """
    Report labelled source-level recall/FPR for AIS decision regions.

    D = mature V-detector match, G = self-gap, F = fused-score threshold,
    P = PCA-space self-boundary, R = raw-feature self-boundary evidence.
    Labels are expected to be used only after prediction for verification.
    """
    y_true = np.asarray(y_true).astype(int)
    n = len(y_true)
    if n == 0:
        return {"available": False, "reason": "No aligned rows for source decomposition."}

    source_defs = {
        "v_detector": np.asarray(components.get("v_detector_match", np.zeros(n)), dtype=bool),
        "self_gap": np.asarray(components.get("self_gap_match", np.zeros(n)), dtype=bool),
        "nsa_score": np.asarray(components.get("nsa_score_match", np.zeros(n)), dtype=bool),
        "score_fusion": np.asarray(components.get("fusion_score_match", np.zeros(n)), dtype=bool),
        "pca_self_boundary": np.asarray(components.get("pca_self_boundary_match", np.zeros(n)), dtype=bool),
        "raw_self_boundary_evidence": np.asarray(
            components.get("raw_self_boundary_evidence_match", np.zeros(n)),
            dtype=bool,
        ),
    }
    source_defs["fusion_only"] = (
        source_defs["score_fusion"]
        & ~source_defs["v_detector"]
        & ~source_defs["self_gap"]
        & ~source_defs["pca_self_boundary"]
    )

    attack_mask = y_true == 1
    benign_mask = y_true == 0
    n_attack = int(attack_mask.sum())
    n_benign = int(benign_mask.sum())

    sources = {}
    for name, mask in source_defs.items():
        if len(mask) != n:
            return {
                "available": False,
                "reason": f"Source '{name}' has {len(mask)} rows; expected {n}.",
            }
        tp = int((mask & attack_mask).sum())
        fp = int((mask & benign_mask).sum())
        sources[name] = {
            "count": int(mask.sum()),
            "tp": tp,
            "fp": fp,
            "recall": round(tp / n_attack, 4) if n_attack else None,
            "false_positive_rate": round(fp / n_benign, 4) if n_benign else None,
        }

    d = source_defs["v_detector"]
    g = source_defs["self_gap"]
    f = source_defs["score_fusion"]
    p = source_defs["pca_self_boundary"]
    r = source_defs["raw_self_boundary_evidence"]
    overlaps = {
        "D": int(d.sum()),
        "G": int(g.sum()),
        "F": int(f.sum()),
        "P": int(p.sum()),
        "R": int(r.sum()),
        "D_and_G": int((d & g).sum()),
        "D_and_F": int((d & f).sum()),
        "G_and_F": int((g & f).sum()),
        "P_and_F": int((p & f).sum()),
        "P_and_D": int((p & d).sum()),
        "P_and_G": int((p & g).sum()),
        "R_and_F": int((r & f).sum()),
        "D_and_G_and_F": int((d & g & f).sum()),
        "F_only": int((f & ~d & ~g & ~p).sum()),
        "P_only": int((p & ~d & ~g & ~f).sum()),
        "R_only": int((r & ~d & ~g & ~f & ~p).sum()),
    }

    return {
        "available": True,
        "verification_only": True,
        "n_samples": int(n),
        "n_attacks": n_attack,
        "n_benign": n_benign,
        "sources": sources,
        "overlaps": overlaps,
        "legend": {
            "D": "mature V-detector match",
            "G": "self-gap fallback",
            "F": "fused-score threshold",
            "P": "PCA-space self-boundary threshold",
            "R": "raw-feature self-boundary evidence",
        },
    }


def compute_silhouette_metric(
    X: np.ndarray,
    labels: np.ndarray,
    *,
    max_samples: int = 2_000,
    random_state: int = 42,
) -> dict:
    """
    Compute Silhouette Score for predicted normal/anomaly groups in PCA space.

    This is an unsupervised separation indicator only; it does not use labels and
    does not prove attack-detection correctness.
    """
    labels = np.asarray(labels).astype(int)
    X = np.asarray(X)

    if len(X) != len(labels) or len(labels) < 3:
        return {
            "value": None,
            "applicable": False,
            "reason": "Not enough aligned samples for Silhouette Score.",
            "n_samples": int(len(labels)),
            "groups": {},
            "explanation": METRIC_EXPLANATIONS["silhouette_score"],
        }

    unique = np.unique(labels)
    if len(unique) < 2:
        return {
            "value": None,
            "applicable": False,
            "reason": "Only one predicted class; Silhouette Score is not applicable.",
            "n_samples": int(len(labels)),
            "groups": {str(int(k)): int((labels == k).sum()) for k in unique},
            "explanation": METRIC_EXPLANATIONS["silhouette_score"],
        }

    if len(labels) > max_samples:
        rng = np.random.default_rng(random_state)
        idx = rng.choice(len(labels), size=max_samples, replace=False)
        X_eval = X[idx]
        labels_eval = labels[idx]
        if len(np.unique(labels_eval)) < 2:
            return {
                "value": None,
                "applicable": False,
                "reason": "Sample cap selected only one predicted class.",
                "n_samples": int(len(labels_eval)),
                "groups": {str(int(k)): int((labels_eval == k).sum()) for k in np.unique(labels_eval)},
                "explanation": METRIC_EXPLANATIONS["silhouette_score"],
            }
    else:
        X_eval = X
        labels_eval = labels

    try:
        value = float(silhouette_score(X_eval, labels_eval))
    except ValueError as exc:
        return {
            "value": None,
            "applicable": False,
            "reason": str(exc),
            "n_samples": int(len(labels_eval)),
            "groups": {str(int(k)): int((labels_eval == k).sum()) for k in np.unique(labels_eval)},
            "explanation": METRIC_EXPLANATIONS["silhouette_score"],
        }

    return {
        "value": round(value, 4),
        "applicable": True,
        "reason": (
            "Computed from PCA-space features and predicted normal/anomaly groups; "
            "interpret as separation only, not labelled correctness."
        ),
        "n_samples": int(len(labels_eval)),
        "groups": {str(int(k)): int((labels_eval == k).sum()) for k in np.unique(labels_eval)},
        "explanation": METRIC_EXPLANATIONS["silhouette_score"],
    }


def threshold_analysis(
    y_true: np.ndarray,
    anomaly_scores: np.ndarray,
    *,
    model_name: str = "model",
    max_rows: int = 41,
    target_recall: tuple[float, float] = (0.92, 0.97),
    target_fpr: tuple[float, float] = (0.03, 0.06),
) -> dict:
    """
    Evaluate how score thresholds affect labelled post-run verification metrics.

    Labels are used only here, after unsupervised scoring, to explain tradeoffs.
    The recommended threshold is report-only and must not update trained artifacts.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(anomaly_scores, dtype=float)
    if len(y_true) != len(scores) or len(scores) == 0:
        return {
            "available": False,
            "reason": "Threshold analysis requires aligned labels and anomaly scores.",
            "table": [],
            "recommended": None,
        }

    finite_mask = np.isfinite(scores)
    y_true = y_true[finite_mask]
    scores = scores[finite_mask]
    if len(scores) == 0:
        return {
            "available": False,
            "reason": "No finite anomaly scores available.",
            "table": [],
            "recommended": None,
        }
    if int(y_true.sum()) == 0:
        return {
            "available": False,
            "reason": "Threshold analysis needs labelled attack rows; this slice contains only benign traffic.",
            "table": [],
            "recommended": None,
            "verification_only": True,
        }
    if int((y_true == 0).sum()) == 0:
        return {
            "available": False,
            "reason": "Threshold analysis needs benign rows to estimate FPR; this slice contains only attack traffic.",
            "table": [],
            "recommended": None,
            "verification_only": True,
        }

    quantiles = np.linspace(0.0, 1.0, max_rows)
    thresholds = np.unique(np.quantile(scores, quantiles))
    rows = []
    for threshold in thresholds:
        y_pred = (scores > threshold).astype(int)
        metrics = evaluate_model(y_true, y_pred, model_name).to_dict()
        rows.append({
            "threshold": round(float(threshold), 6),
            "tp": metrics["tp"],
            "tn": metrics["tn"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "recall": metrics["recall"],
            "true_positive_rate": metrics["true_positive_rate"],
            "false_negative_rate": metrics["false_negative_rate"],
            "false_positive_rate": metrics["false_positive_rate"],
            "precision": metrics["precision"],
            "f1": metrics["f1"],
            "accuracy": metrics["accuracy"],
        })

    recall_low, recall_high = target_recall
    fpr_low, fpr_high = target_fpr

    ideal = [
        row for row in rows
        if row["recall"] >= recall_low
        and fpr_low <= row["false_positive_rate"] <= fpr_high
    ]
    fpr_band = [
        row for row in rows
        if fpr_low <= row["false_positive_rate"] <= fpr_high
    ]
    fpr_capped = [
        row for row in rows
        if row["false_positive_rate"] <= fpr_high
    ]

    if ideal:
        recommended = max(ideal, key=lambda r: (r["recall"], r["f1"], -r["false_positive_rate"]))
        target_achieved = True
        reason = "Meets the requested Recall and FPR target bands."
    elif fpr_band:
        recommended = max(fpr_band, key=lambda r: (r["recall"], r["f1"], -r["false_negative_rate"]))
        target_achieved = False
        reason = "FPR is inside the target band, but Recall is outside the requested range."
    elif fpr_capped:
        recommended = max(fpr_capped, key=lambda r: (r["recall"], r["f1"], -r["false_positive_rate"]))
        target_achieved = False
        reason = "No threshold hits the full target; selected highest Recall with FPR <= 6%."
    else:
        def band_distance(row):
            recall = row["recall"]
            fpr = row["false_positive_rate"]
            recall_gap = 0.0 if recall >= recall_low else abs(recall - recall_low)
            fpr_gap = 0.0 if fpr_low <= fpr <= fpr_high else min(abs(fpr - fpr_low), abs(fpr - fpr_high))
            return recall_gap + fpr_gap

        recommended = min(rows, key=lambda r: (band_distance(r), r["false_negative_rate"], r["false_positive_rate"]))
        target_achieved = False
        reason = "No threshold meets the acceptable FPR cap; selected closest observed tradeoff."

    return {
        "available": True,
        "verification_only": True,
        "score_space": "raw_anomaly_score",
        "target_recall_range": [recall_low, recall_high],
        "target_fpr_range": [fpr_low, fpr_high],
        "target_achieved": target_achieved,
        "recommendation_reason": reason,
        "recommended": recommended,
        "table": rows,
        "note": (
            "Report-only threshold analysis. Labels are used after detection to evaluate tradeoffs; "
            "the trained unsupervised model threshold is not changed."
        ),
    }


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
