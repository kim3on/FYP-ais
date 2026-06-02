"""
Detection Engine — Two-Layer AIS IDS
========================================
Layer 1: Binary unsupervised anomaly detection (NSA + Self-Boundary).
Layer 2: Post-alert attack attribution using flow-feature heuristics.
Layer 3: Post-run labelled verification (uses labels only after detection).

The detection engine NEVER uses ground-truth labels (attack_category, Label)
during detection.  Labels are consumed only by _labelled_metrics() after
all predictions are complete.
"""

import logging

import numpy as np
import pandas as pd
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
import uuid

from app.core.datasets import DATASET_NSL_KDD, dataset_display_name, normalize_dataset_type
from app.core.preprocessor import CICIDSPreprocessor
from app.core.attack_attribution import attribute_attack
from app.core.endpoint_roles import infer_endpoint_roles
from app.core.evaluator import (
    METRIC_EXPLANATIONS,
    compute_silhouette_metric,
    evaluate_model,
    severity_from_score,
    source_decomposition_metrics,
    threshold_analysis,
)

logger = logging.getLogger(__name__)
DEFAULT_RUNTIME_THRESHOLD = 0.50
DEFAULT_ZERO_DAY_THRESHOLD = 0.65


@dataclass
class AlertRecord:
    """A single anomaly alert — maps to one row in the dashboard table.

    Two-layer output:
      - Layer 1 fields: is_anomaly, anomaly_score, anomaly_sources
      - Layer 2 fields: likely_attack_family, attribution_confidence, evidence
      - Legacy: attack_type aliases likely_attack_family for backward compat
    """
    alert_id:        str
    timestamp:       str
    src_ip:          str
    dst_ip:          str
    dst_port:        str
    protocol:        str
    traffic_direction: str
    flow_initiator_ip: str
    flow_responder_ip: str
    local_ip: str
    remote_ip: str
    suspected_attacker_ip: str
    suspected_victim_ip: str
    suspected_compromised_host: str
    containment_target_ip: str
    endpoint_role_confidence: str
    endpoint_role_reason: str
    # Layer 1 — binary anomaly detection
    is_anomaly:      bool
    anomaly_score:   float        # [0, 1]
    anomaly_sources: list         # e.g. ["nsa_pca", "self_boundary"]
    # Layer 2 — attack attribution (heuristic only, never uses labels)
    likely_attack_family: str     # e.g. "DDoS — SYN Flood"
    attribution_confidence: str   # "high", "medium", "low"
    evidence:        list         # human-readable explanation strings
    # Display helpers
    attack_type:     str          # alias of likely_attack_family (backward compat)
    severity:        str          # critical / high / medium / low
    confidence:      float        # [0, 1]
    confidence_pct:  str          # "94%"
    is_false_positive: bool       # analyst can mark this
    is_zero_day:     bool         # True when no known signature matched + high novelty

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionEngine:
    """
    Two-layer AIS detection engine.

    Layer 1a — NSA V-Detector (saved representation space): detector match + self-gap.
    Layer 1b — Self-Boundary (original feature space): Gaussian z-score fences.
    Layer 2  — Attack Attribution: flow-feature heuristics (never uses labels).

    Parameters
    ----------
    model         : fitted NSA or IsolationForest detector
    preprocessor  : fitted CICIDSPreprocessor
    active_model  : "nsa" or "isolation_forest"
    self_boundary : fitted raw-feature SelfBoundaryDetector (optional)
    pca_self_boundary : fitted representation-space SelfBoundaryDetector (optional)
    """

    def __init__(
        self,
        model,
        preprocessor: CICIDSPreprocessor,
        active_model: str = "nsa",
        self_boundary=None,
        pca_self_boundary=None,
        threshold: float = DEFAULT_RUNTIME_THRESHOLD,
        zero_day_threshold: float = DEFAULT_ZERO_DAY_THRESHOLD,
    ):
        self.model = model
        self.preprocessor = preprocessor
        self.active_model = active_model
        self.self_boundary = self_boundary
        self.pca_self_boundary = pca_self_boundary
        self.threshold = float(threshold)
        self.zero_day_threshold = float(zero_day_threshold)
        self.dataset_type = normalize_dataset_type(
            getattr(preprocessor, "dataset_type", None)
        )
        self.representation_metadata = self._preprocessor_representation_summary()
        self.trained_target_fpr = self._trained_target_fpr()

    # ------------------------------------------------------------------ #
    #  BATCH DETECTION (CSV upload)                                        #
    # ------------------------------------------------------------------ #

    def detect_from_csv(
        self,
        source,                     # file path, bytes, or file-like
        limit: Optional[int] = None,
        offset: int = 0,
        filename: str = "",
    ) -> dict:
        """
        Run detection on an uploaded CSV or Parquet log file.

        Returns
        -------
        {
          "total_checked": int,
          "anomalies_found": int,
          "normal_count": int,
          "zero_day_candidates": int,
          "alerts": [AlertRecord.to_dict(), ...],
          "summary": {...}
        }
        """
        # Use transform_with_raw when either self-boundary layer is available.
        if self.self_boundary is not None or self.pca_self_boundary is not None:
            X_pca, df, df_raw = self.preprocessor.transform_with_raw(
                source, filename=filename
            )
        else:
            X_pca, df = self.preprocessor.transform(source, filename=filename)
            df_raw = None

        offset = max(int(offset or 0), 0)
        if limit:
            end = offset + int(limit)
            X_pca = X_pca[offset:end]
            df = df.iloc[offset:end].reset_index(drop=True)
            if df_raw is not None:
                df_raw = df_raw.iloc[offset:end].reset_index(drop=True)
        elif offset:
            X_pca = X_pca[offset:]
            df = df.iloc[offset:].reset_index(drop=True)
            if df_raw is not None:
                df_raw = df_raw.iloc[offset:].reset_index(drop=True)
        df.attrs["row_offset"] = offset

        sb_ratios = None
        sb_flags = None
        sb_evidence = None
        pca_sb_flags = None
        pca_sb_scores = None
        nsa_flags = None
        decision_components = None

        if self._is_isolation_forest():
            labels, scores = self.model.predict_with_scores(X_pca, alert_threshold=self.threshold)
            min_dists = None
            raw_scores = self._raw_anomaly_scores(X_pca, scores)
        else:
            if self.self_boundary is not None:
                sb_ratios, sb_flags, sb_evidence = self.self_boundary.score(df_raw)
            if self._scoring_self_boundary() is not None and df_raw is not None:
                pca_sb_scores, pca_sb_flags = self._score_scoring_self_boundary(X_pca, df_raw)
            labels, scores, min_dists = self.model.predict_with_details(X_pca, alert_threshold=self.threshold)
            raw_scores = np.asarray(min_dists, dtype=float)
            decision_components = self.model.decision_components(
                X_pca,
                alert_threshold=self.threshold,
            ) if hasattr(self.model, "decision_components") else None
            if decision_components is not None:
                if pca_sb_flags is not None:
                    decision_components["pca_self_boundary_match"] = np.asarray(pca_sb_flags, dtype=bool)
                if sb_flags is not None:
                    decision_components["raw_self_boundary_evidence_match"] = np.asarray(sb_flags, dtype=bool)
            nsa_flags = labels.astype(int)

        return self._build_result(
            labels,
            scores,
            df,
            min_dists=min_dists,
            raw_scores=raw_scores,
            features=X_pca,
            nsa_flags=nsa_flags,
            sb_ratios=sb_ratios,
            sb_flags=sb_flags,
            sb_evidence=sb_evidence,
            pca_sb_flags=pca_sb_flags,
            decision_components=decision_components,
        )

    # ------------------------------------------------------------------ #
    #  REAL-TIME DETECTION (single sample or small batch)                  #
    # ------------------------------------------------------------------ #

    def detect_sample(self, feature_dict: dict) -> dict:
        """
        Detect anomaly in a single network flow given as a dict of features.
        Returns a single AlertRecord if anomalous, else None.
        """
        df_single = pd.DataFrame([feature_dict])
        X_pca = self.preprocessor.transform_dataframe(df_single)
        sb_ratios = None
        sb_flags = None
        sb_evidence = None
        pca_sb_flags = None
        pca_sb_scores = None
        nsa_flags = None
        decision_components = None
        df_raw_single = self.preprocessor.clean_feature_frame(df_single)
        if self._is_isolation_forest():
            labels, scores = self.model.predict_with_scores(X_pca, alert_threshold=self.threshold)
            min_dists = None
            raw_scores = self._raw_anomaly_scores(X_pca, scores)
        else:
            if self.self_boundary is not None:
                sb_ratios, sb_flags, sb_evidence = self.self_boundary.score(df_raw_single)
            if self._scoring_self_boundary() is not None:
                pca_sb_scores, pca_sb_flags = self._score_scoring_self_boundary(X_pca, df_raw_single)
            labels, scores, min_dists = self.model.predict_with_details(X_pca, alert_threshold=self.threshold)
            raw_scores = np.asarray(min_dists, dtype=float)
            decision_components = self.model.decision_components(
                X_pca,
                alert_threshold=self.threshold,
            ) if hasattr(self.model, "decision_components") else None
            if decision_components is not None:
                if pca_sb_flags is not None:
                    decision_components["pca_self_boundary_match"] = np.asarray(pca_sb_flags, dtype=bool)
                if sb_flags is not None:
                    decision_components["raw_self_boundary_evidence_match"] = np.asarray(sb_flags, dtype=bool)
            nsa_flags = labels.astype(int)

        return self._build_result(
            labels,
            scores,
            df_single,
            min_dists=min_dists,
            raw_scores=raw_scores,
            features=X_pca,
            nsa_flags=nsa_flags,
            sb_ratios=sb_ratios,
            sb_flags=sb_flags,
            sb_evidence=sb_evidence,
            pca_sb_flags=pca_sb_flags,
            decision_components=decision_components,
        )

    # ------------------------------------------------------------------ #
    #  INTERNAL                                                            #
    # ------------------------------------------------------------------ #

    def _build_result(
        self,
        labels: np.ndarray,
        scores: np.ndarray,
        df: pd.DataFrame,
        min_dists: Optional[np.ndarray] = None,
        raw_scores: Optional[np.ndarray] = None,
        features: Optional[np.ndarray] = None,
        nsa_flags: Optional[np.ndarray] = None,
        sb_ratios: Optional[np.ndarray] = None,
        sb_flags: Optional[np.ndarray] = None,
        sb_evidence: Optional[list] = None,
        pca_sb_flags: Optional[np.ndarray] = None,
        decision_components: Optional[dict] = None,
    ) -> dict:
        """Convert raw predictions to structured result with alert objects."""
        alerts = []
        anomaly_indices = np.where(labels == 1)[0]
        representation_name = self.representation_metadata.get("name") or "pca"
        representation_label = self.representation_metadata.get("display_name") or "PCA"

        for i in anomaly_indices:
            row = df.iloc[i] if i < len(df) else {}
            score = float(scores[i])
            severity = severity_from_score(score)

            # Try to read real metadata from the dataframe row.
            # CIC-IDS-2017 Parquet/CSV files are pre-extracted flow statistics
            # and do not contain IP addresses or port numbers.  When absent, we
            # record 'N/A' — never fabricate values.
            src_ip   = str(self._get(row, ['Source IP',       'src_ip',   'srcip'],   'N/A'))
            dst_ip   = str(self._get(row, ['Destination IP',  'dst_ip',   'dstip'],   'N/A'))
            dst_port = str(self._get(row, ['Destination Port','dst_port', 'dstport'], 'N/A'))
            protocol = str(self._get(row, ['Protocol', 'protocol_type', 'protocol'], 'N/A'))

            # Map numeric protocol codes (CIC-IDS-2017: 0=HOPOPT, 6=TCP, 17=UDP)
            _proto_map = {'6': 'TCP', '17': 'UDP', '0': 'OTHER', '58': 'ICMPv6'}
            protocol = _proto_map.get(str(protocol), str(protocol)).upper()

            # ── Layer 1: Determine anomaly sources ──────────────────────
            anomaly_sources = []
            nsa_flagged = False
            sb_flagged = False

            if self._is_isolation_forest():
                anomaly_sources.append("isolation_forest")
                v_detector_flagged = False
                self_gap_flagged = False
            else:
                # Check which pure-NSA sub-mechanisms fired.
                v_detector_flagged = False
                self_gap_flagged = False
                if decision_components is not None:
                    v_detector_flagged = bool(decision_components.get("v_detector_match", [False])[i])
                    self_gap_flagged = bool(decision_components.get("self_gap_match", [False])[i])
                    nsa_flagged = bool(v_detector_flagged or self_gap_flagged or decision_components.get("nsa_score_match", [False])[i])
                elif nsa_flags is not None and i < len(nsa_flags):
                    nsa_flagged = bool(nsa_flags[i] == 1)
                elif hasattr(self.model, 'predict_with_details'):
                    nsa_labels_only, _, _ = self.model.predict_with_details(
                        features[i:i+1] if features is not None else np.zeros((1, 1)),
                        alert_threshold=self.threshold,
                    )
                    nsa_flagged = bool(nsa_labels_only[0] == 1)
                elif hasattr(self.model, 'predict_with_scores'):
                    nsa_labels_only, _ = self.model.predict_with_scores(
                        features[i:i+1] if features is not None else np.zeros((1, 1)),
                        alert_threshold=self.threshold,
                    )
                    nsa_flagged = bool(nsa_labels_only[0] == 1)

                if v_detector_flagged:
                    anomaly_sources.append("v_detector")
                if self_gap_flagged:
                    anomaly_sources.append("self_gap")
                if not decision_components and nsa_flagged:
                    anomaly_sources.append("self_gap")

                if pca_sb_flags is not None and i < len(pca_sb_flags) and pca_sb_flags[i]:
                    sb_flagged = True

                raw_sb_evidence_flagged = bool(sb_flags is not None and i < len(sb_flags) and sb_flags[i])
                sb_flagged = bool(sb_flagged or raw_sb_evidence_flagged)

                if not anomaly_sources:
                    anomaly_sources.append("self_gap")

            # ── Layer 2: Attack Attribution (NEVER uses labels) ─────────
            # The attack_category column is intentionally NOT passed here.
            attack_family = (
                "Unknown Anomaly"
                if self.dataset_type == DATASET_NSL_KDD
                else self._attribute_attack(row, novelty_score=score, zero_day_threshold=self.zero_day_threshold)
            )
            is_zero_day = (attack_family == 'Zero-Day Candidate')
            endpoint_roles = infer_endpoint_roles(src_ip, dst_ip, attack_family).to_dict()

            # Attribution confidence based on how many sources agree
            # and the strength of the anomaly score
            if len(anomaly_sources) >= 2 and score >= 0.5:
                attr_confidence = "high"
            elif score >= 0.3 or len(anomaly_sources) >= 2:
                attr_confidence = "medium"
            else:
                attr_confidence = "low"

            # Build evidence list
            evidence = []
            if not self._is_isolation_forest() and sb_evidence is not None and i < len(sb_evidence):
                evidence.extend(sb_evidence[i])
            if self._is_isolation_forest():
                evidence.append("Isolation Forest benign-calibrated anomaly score exceeded")
            if not self._is_isolation_forest() and pca_sb_flags is not None and i < len(pca_sb_flags) and pca_sb_flags[i]:
                evidence.append(f"{representation_label} self-boundary exceeded benign calibration")
            if v_detector_flagged:
                evidence.append("Mature V-detector matched the flow")
            if self_gap_flagged:
                evidence.append(f"{representation_label} NSA self-gap exceeded")
            if not self._is_isolation_forest() and not nsa_flagged and not sb_flagged:
                evidence.append("Benign-calibrated NSA self-gap threshold exceeded")

            alert = AlertRecord(
                alert_id=str(uuid.uuid4())[:8].upper(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                **endpoint_roles,
                # Layer 1
                is_anomaly=True,
                anomaly_score=round(score, 4),
                anomaly_sources=anomaly_sources,
                # Layer 2
                likely_attack_family=attack_family,
                attribution_confidence=attr_confidence,
                evidence=evidence,
                # Backward compat
                attack_type=attack_family,
                severity=severity,
                confidence=round(score, 4),
                confidence_pct=f"{round(score * 100)}%",
                is_false_positive=False,
                is_zero_day=is_zero_day,
            )
            alerts.append(alert.to_dict())

        total = len(labels)
        n_anomalies = int(labels.sum())
        n_zero_day  = sum(1 for a in alerts if a.get('is_zero_day'))
        silhouette = compute_silhouette_metric(features, labels) if features is not None else None

        if self._is_isolation_forest():
            detection_architecture = "isolation_forest_baseline"
            layer1_sources = ["isolation_forest"]
            score_mode = (
                "isolation_forest_benign_calibrated_score"
                if getattr(self.model, "score_threshold_", None) is not None
                else "isolation_forest_sklearn_contamination"
            )
            self_boundary_mode = "not_applicable"
        else:
            detection_architecture = "pure_nsa_v_detector_self_gap"
            layer1_sources = ["v_detector", "self_gap"]
            score_mode = "self_gap_distance"
            self_boundary_mode = (
                (
                    "evidence_only_pca_raw"
                    if representation_name == "pca"
                    else "evidence_only_representation_raw"
                )
                if self.pca_self_boundary is not None
                else ("legacy_raw_scoring" if self.self_boundary is not None else "none")
            )

        representation_components = (
            int(features.shape[1])
            if features is not None and len(getattr(features, "shape", ())) > 1
            else self.representation_metadata.get("component_count")
        )
        result = {
            "total_checked":      total,
            "row_offset":         int(df.attrs.get("row_offset", 0)) if hasattr(df, "attrs") else 0,
            "anomalies_found":    n_anomalies,
            "normal_count":       total - n_anomalies,
            "zero_day_candidates": n_zero_day,
            "detection_rate_pct": round(n_anomalies / total * 100, 2) if total else 0,
            "alerts":             alerts,
            "severity_counts":    self._count_severities(alerts),
            "model_used":         self.active_model,
            "dataset_type":       self.dataset_type,
            "dataset_display":    dataset_display_name(self.dataset_type),
            "batch_only":         self.dataset_type == DATASET_NSL_KDD,
            "representation":      {
                **self.representation_metadata,
                "component_count": representation_components,
            },
            "representation_name": representation_name,
            "representation_display": representation_label,
            "representation_components": representation_components,
            "analysed_at":        datetime.now(timezone.utc).isoformat(),
            "metric_explanations": METRIC_EXPLANATIONS,
            "detection_architecture": detection_architecture,
            "layer1_sources": layer1_sources,
            "score_mode": score_mode,
            "self_boundary_mode": self_boundary_mode,
            "trained_target_fpr": round(float(self.trained_target_fpr), 6),
        }
        result["anomaly_sources_summary"] = self._count_sources(alerts)
        if silhouette is not None:
            result["unsupervised_validation"] = {
                "silhouette": silhouette,
                "silhouette_score": silhouette["value"],
                "explanation": METRIC_EXPLANATIONS["silhouette_score"],
            }
            result["silhouette_score"] = silhouette["value"]

        result.update(self._labelled_metrics(
            labels,
            df,
            raw_scores=raw_scores,
            decision_components=decision_components,
        ))
        return result

    def _labelled_metrics(
        self,
        labels: np.ndarray,
        df: pd.DataFrame,
        raw_scores: Optional[np.ndarray] = None,
        decision_components: Optional[dict] = None,
    ) -> dict:
        """
        Return classification metrics when uploaded detection data has labels.

        LAYER 3 — Post-run verification only.
        Labels are NEVER used during detection (Layers 1 & 2).
        """
        if "attack_category" not in df.columns or len(df) != len(labels):
            return {}

        categories = df["attack_category"].fillna("Unknown").astype(str)
        if categories.str.lower().eq("unknown").all():
            return {}

        y_true = categories.str.lower().ne("normal").astype(int).to_numpy()

        # Check if there are any attacks — if not, metrics like recall are N/A
        n_attacks = int(y_true.sum())

        metrics = evaluate_model(
            y_true,
            labels.astype(int),
            f"{self.active_model} detection",
            df,
        ).to_dict()
        metrics["verification_mode"] = "post_run_labelled_verification"
        metrics["verification_note"] = (
            "Labels were used only after unsupervised detection to score predictions. "
            "No labels were used during Layer 1 anomaly detection or Layer 2 attribution."
        )

        # If no attacks in file slice, mark attack-dependent metrics as N/A
        if n_attacks == 0:
            for m in ("recall", "false_negative_rate", "precision", "f1",
                      "detection_rate", "true_positive_rate"):
                metrics[m] = None
            metrics["verification_note"] += (
                " This file slice contains no labelled attacks; "
                "recall, FNR, precision, and F1 are not applicable."
            )

        if raw_scores is not None and len(raw_scores) == len(labels):
            forced_positive_mask = None
            if not self._is_isolation_forest() and decision_components is not None:
                forced_positive_mask = decision_components.get("v_detector_match")
            metrics["threshold_analysis"] = threshold_analysis(
                y_true,
                raw_scores,
                model_name=f"{self.active_model} threshold analysis",
                target_fpr=(0.0, self.trained_target_fpr),
                forced_positive_mask=forced_positive_mask,
            )
        if decision_components is not None:
            source_metrics = source_decomposition_metrics(
                y_true,
                decision_components,
            )
            metrics["source_decomposition"] = source_metrics
            metrics["source_verification"] = source_metrics
        return metrics

    def _trained_target_fpr(self) -> float:
        """Return the benign calibration target saved in the active model."""
        candidates = [
            getattr(self.model, "target_fpr", None),
            (getattr(self.model, "fusion_calibration_", None) or {}).get("target_fpr"),
            (getattr(self.model, "threshold_calibration_", None) or {}).get("target_fpr"),
            (getattr(self.model, "meta_", None) or {}).get("target_fpr"),
            ((getattr(self.model, "meta_", None) or {}).get("threshold_calibration") or {}).get("target_fpr"),
        ]
        for value in candidates:
            try:
                if value is not None:
                    return float(np.clip(float(value), 0.01, 0.20))
            except (TypeError, ValueError):
                continue
        return 0.10

    def _raw_anomaly_scores(self, X_scaled: np.ndarray, confidence_scores: np.ndarray) -> np.ndarray:
        """
        Return raw monotonic anomaly scores for threshold analysis when available.

        For NSA this uses the model's existing anomaly_scores method. For models
        without raw scoring, the normalized confidence score is still monotonic:
        higher means more anomalous.
        """
        if hasattr(self.model, "raw_anomaly_scores"):
            try:
                return np.asarray(self.model.raw_anomaly_scores(X_scaled), dtype=float)
            except Exception as exc:
                logger.warning(
                    "Falling back to confidence scores for threshold analysis; "
                    "raw anomaly scoring failed for %s: %s",
                    type(self.model).__name__,
                    exc,
                )
        if hasattr(self.model, "anomaly_scores"):
            try:
                return np.asarray(self.model.anomaly_scores(X_scaled), dtype=float)
            except Exception as exc:
                logger.warning(
                    "Falling back to confidence scores for threshold analysis; "
                    "raw anomaly scoring failed for %s: %s",
                    type(self.model).__name__,
                    exc,
                )
        return np.asarray(confidence_scores, dtype=float)

    # ================================================================== #
    #  LAYER 2 — Attack Attribution (flow-feature heuristics ONLY)         #
    #                                                                      #
    #  NEVER receives or uses attack_category / Label columns.             #
    #  Uses only raw CIC-IDS-2017 flow statistics to guess the attack      #
    #  family.  A wrong guess does NOT count as a false negative.           #
    # ================================================================== #

    def _attribute_attack(
        self,
        row,
        novelty_score: float = 0.0,
        zero_day_threshold: float | None = None,
    ) -> str:
        """
        Post-detection attack family attribution using flow features only.

        This is Layer 2: it runs ONLY on samples already flagged as anomalous.
        It NEVER uses ground-truth labels.  Replaces the old _infer_attack_type
        which had a Stage 1 that read attack_category (label leakage).

        Rule order matters: more specific signatures (brute force on known ports)
        MUST be checked BEFORE generic volumetric rules.
        """
        threshold = self.zero_day_threshold if zero_day_threshold is None else zero_day_threshold
        return attribute_attack(
            row,
            novelty_score=novelty_score,
            zero_day_threshold=threshold,
        )


    @staticmethod
    def _get(row, keys: list, default):
        """Try multiple column name variants with a fallback default."""
        if isinstance(row, pd.Series):
            for k in keys:
                if k in row.index and pd.notna(row[k]):
                    return row[k]
        elif isinstance(row, dict):
            for k in keys:
                if k in row:
                    return row[k]
        return default

    @staticmethod
    def _count_severities(alerts: list) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            sev = a.get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _count_sources(alerts: list) -> dict:
        counts = {}
        for alert in alerts:
            for source in alert.get("anomaly_sources", []) or []:
                counts[source] = counts.get(source, 0) + 1
        return counts

    def _scoring_self_boundary(self):
        """Return the SB model used for supporting evidence."""
        return self.pca_self_boundary or self.self_boundary

    def _preprocessor_representation_summary(self) -> dict:
        if hasattr(self.preprocessor, "representation_summary"):
            try:
                summary = self.preprocessor.representation_summary()
                if isinstance(summary, dict):
                    return summary
            except Exception:
                pass
        pca = getattr(self.preprocessor, "pca_", None)
        n_components = None
        if pca is not None:
            n_components = int(getattr(pca, "n_components_", 0) or 0)
        elif getattr(self.preprocessor, "feature_columns_", None):
            n_components = len(self.preprocessor.feature_columns_)
        return {
            "name": "pca",
            "display_name": "PCA",
            "component_count": int(n_components or 0),
            "scaler": "RobustScaler",
            "fitted": bool(getattr(self.preprocessor, "is_fitted_", False)),
        }

    def _is_isolation_forest(self) -> bool:
        return self.active_model == "isolation_forest"

    def _score_scoring_self_boundary(
        self,
        X_pca: np.ndarray,
        df_raw: Optional[pd.DataFrame],
    ) -> tuple[np.ndarray, np.ndarray]:
        """Score the representation-space SB when available, otherwise legacy raw SB."""
        scoring_sb = self._scoring_self_boundary()
        if scoring_sb is None:
            n = len(X_pca)
            return np.zeros(n, dtype=np.float64), np.zeros(n, dtype=bool)

        if scoring_sb is self.pca_self_boundary:
            pca_df = self.preprocessor.pca_dataframe(X_pca)
            scores = scoring_sb.weighted_score(pca_df)
            _, flags, _ = scoring_sb.score(pca_df)
            return scores, flags

        if df_raw is None:
            n = len(X_pca)
            return np.zeros(n, dtype=np.float64), np.zeros(n, dtype=bool)
        scores = scoring_sb.weighted_score(df_raw)
        _, flags, _ = scoring_sb.score(df_raw)
        return scores, flags

    def _fusion_ready(self) -> bool:
        return (
            hasattr(self.model, "predict_fused")
            and getattr(self.model, "fusion_threshold_", None) is not None
            and bool(getattr(self.model, "fusion_component_scales_", {}))
        )


# ── Helpers ────────────────────────────────────────────────────────────────────────

# ── Note: no random/synthetic IP generation ───────────────────────────────────────────
# When dataset columns (Source IP, Destination IP, Destination Port, Protocol)
# are absent — as is the case with CIC-IDS-2017 pre-extracted flow files —
# alerts will display 'N/A' in those fields.  No values are ever fabricated.
