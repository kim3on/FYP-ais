"""
Detection Engine
=================
Handles real-time and batch anomaly detection against uploaded
packet logs or live traffic streams.

Produces structured alert objects that map directly to the
Alert Log table in the frontend dashboard.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
import uuid

from app.core.preprocessor import CICIDSPreprocessor
from app.core.evaluator import severity_from_score


@dataclass
class AlertRecord:
    """A single anomaly alert — maps to one row in the dashboard table."""
    alert_id:        str
    timestamp:       str
    src_ip:          str
    dst_ip:          str
    dst_port:        str
    protocol:        str
    attack_type:     str        # predicted attack category
    severity:        str        # critical / high / medium / low
    confidence:      float      # [0, 1]
    confidence_pct:  str        # "94%"
    is_false_positive: bool     # analyst can mark this
    is_zero_day:     bool       # True when no known signature matched + high novelty

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionEngine:
    """
    Wraps either the NSA or Isolation Forest model for detection.
    Handles feature alignment, scoring, and alert generation.

    Parameters
    ----------
    model       : fitted NSA or IsolationForest detector
    preprocessor: fitted NSLKDDPreprocessor
    active_model: "nsa" or "isolation_forest"
    """

    # Known attack type patterns inferred from NSL-KDD feature signatures
    _ATTACK_SIGNATURES = {
        "DoS":   "Denial of Service",
        "Probe": "Network Probe",
        "R2L":   "Remote to Local",
        "U2R":   "User to Root",
    }

    def __init__(
        self,
        model,
        preprocessor: CICIDSPreprocessor,
        active_model: str = "nsa",
    ):
        self.model = model
        self.preprocessor = preprocessor
        self.active_model = active_model

    # ------------------------------------------------------------------ #
    #  BATCH DETECTION (CSV upload)                                        #
    # ------------------------------------------------------------------ #

    def detect_from_csv(
        self,
        source,                     # file path, bytes, or file-like
        limit: Optional[int] = None,
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
        X_scaled, df = self.preprocessor.transform(source, filename=filename)
        if limit:
            X_scaled = X_scaled[:limit]
            df = df.iloc[:limit].reset_index(drop=True)

        if hasattr(self.model, 'predict_with_details'):
            labels, scores, min_dists = self.model.predict_with_details(X_scaled)
        else:
            labels, scores = self.model.predict_with_scores(X_scaled)
            min_dists = None

        return self._build_result(labels, scores, df, min_dists=min_dists)

    # ------------------------------------------------------------------ #
    #  REAL-TIME DETECTION (single sample or small batch)                  #
    # ------------------------------------------------------------------ #

    def detect_sample(self, feature_dict: dict) -> dict:
        """
        Detect anomaly in a single network flow given as a dict of features.
        Returns a single AlertRecord if anomalous, else None.
        """
        df_single = pd.DataFrame([feature_dict])
        X_scaled = self.preprocessor.transform_dataframe(df_single)
        if hasattr(self.model, 'predict_with_details'):
            labels, scores, min_dists = self.model.predict_with_details(X_scaled)
        else:
            labels, scores = self.model.predict_with_scores(X_scaled)
            min_dists = None
        return self._build_result(labels, scores, df_single, min_dists=min_dists)

    # ------------------------------------------------------------------ #
    #  INTERNAL                                                            #
    # ------------------------------------------------------------------ #

    def _build_result(
        self,
        labels: np.ndarray,
        scores: np.ndarray,
        df: pd.DataFrame,
        min_dists: Optional[np.ndarray] = None,
    ) -> dict:
        """Convert raw predictions to structured result with alert objects."""
        alerts = []
        anomaly_indices = np.where(labels == 1)[0]

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

            cat = str(self._get(row, ['attack_category'], 'Unknown'))
            attack_type = self._infer_attack_type(row, cat, novelty_score=score)
            is_zero_day = (attack_type == 'Zero-Day Candidate')

            alert = AlertRecord(
                alert_id=str(uuid.uuid4())[:8].upper(),
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                attack_type=attack_type,
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

        return {
            "total_checked":      total,
            "anomalies_found":    n_anomalies,
            "normal_count":       total - n_anomalies,
            "zero_day_candidates": n_zero_day,
            "detection_rate_pct": round(n_anomalies / total * 100, 2) if total else 0,
            "alerts":             alerts,
            "severity_counts":    self._count_severities(alerts),
            "model_used":         self.active_model,
            "analysed_at":        datetime.now(timezone.utc).isoformat(),
        }

    def _infer_attack_type(self, row, category: str, novelty_score: float = 0.0) -> str:
        """Two-stage attack type classifier.

        Stage 1 — known category from preprocessor Label column:
            Sub-classifies each broad category using per-flow CIC-IDS-2017
            feature signatures (e.g. DoS-Hulk vs Slowloris vs GoldenEye).

        Stage 2 — unlabeled / live traffic (category == 'unknown'):
            12 flow-statistic heuristics infer the attack type without
            ground-truth labels, enabling real-time traffic classification.

        Zero-Day Candidate:
            Final fallback when no signature matches AND novelty_score >= 0.65.
        """
        cat = category.lower().strip()

        # ── Helper shortcuts ─────────────────────────────────────────────
        def g(keys, default=0):
            return self._get(row, keys, default)

        pkt_rate  = g(['Flow Packets/s', 'Flow Pkts/s', 'flow packets/s'])
        byte_rate = g(['Flow Bytes/s', 'flow bytes/s'])
        duration  = g(['Flow Duration', 'flow duration'])  # microseconds
        fwd_pkts  = g(['Total Fwd Packets', 'Total Fwd Pkts'])
        bwd_pkts  = g(['Total Backward Packets', 'Total Bwd Pkts', 'Total Bwd Packets'])
        fwd_len   = g(['Fwd Packet Length Mean', 'Fwd Pkt Len Mean'])
        bwd_len   = g(['Bwd Packet Length Mean', 'Bwd Pkt Len Mean'])
        avg_size  = g(['Average Packet Size', 'Avg Fwd Segment Size'])
        syn       = g(['SYN Flag Count', 'SYN Flag Cnt'])
        ack       = g(['ACK Flag Count', 'ACK Flag Cnt'])
        psh       = g(['PSH Flag Count', 'PSH Flag Cnt'])
        rst       = g(['RST Flag Count', 'RST Flag Cnt'])
        urg       = g(['URG Flag Count', 'URG Flag Cnt'])
        fin       = g(['FIN Flag Count', 'FIN Flag Cnt'])
        proto_raw = str(g(['Protocol', 'protocol'], '')).strip()
        is_tcp    = proto_raw in ('6', 'TCP', 'tcp')
        is_udp    = proto_raw in ('17', 'UDP', 'udp')

        # ════════════════════════════════════════════════════════════════
        #  STAGE 1 — known category from labeled dataset
        # ════════════════════════════════════════════════════════════════

        if cat == 'dos':
            if duration > 300_000_000 and fwd_pkts < 100 and is_tcp:
                return 'DoS — Slowloris'
            if duration > 60_000_000 and psh > fwd_pkts * 0.4 and fwd_pkts < 300:
                return 'DoS — GoldenEye'
            if pkt_rate > 5_000 and byte_rate > 100_000 and is_tcp:
                return 'DoS — Hulk'
            if duration > 60_000_000 and fwd_len < 200 and bwd_pkts == 0:
                return 'DoS — SlowHTTPTest'
            return 'DoS Attack'

        if cat == 'ddos':
            if is_udp:
                return 'DDoS — UDP Flood'
            if syn > ack and pkt_rate > 1_000:
                return 'DDoS — SYN Flood'
            return 'DDoS — TCP Flood' if pkt_rate > 5_000 else 'DDoS'

        if cat == 'probe':
            if syn > 0 and fwd_pkts <= 3 and bwd_pkts == 0:
                return 'Port Scan — SYN Stealth'
            if is_udp and fwd_pkts <= 2:
                return 'Port Scan — UDP'
            if fwd_pkts <= 2 and duration < 1_000_000:
                return 'Network Enumeration'
            return 'Port Scan'

        if cat == 'brute force':
            dst_port = str(g(['Destination Port', 'dst_port'], ''))
            _port_names = {'22': 'SSH', '21': 'FTP', '3389': 'RDP',
                           '3306': 'MySQL', '5432': 'PostgreSQL', '23': 'Telnet'}
            if dst_port in _port_names:
                return f'Brute Force — {_port_names[dst_port]}'
            return 'Credential Brute Force'

        if cat == 'web attack':
            raw = str(g(['attack_category'], '')).lower()
            if 'sql' in raw:
                return 'Web Attack — SQL Injection'
            if 'xss' in raw:
                return 'Web Attack — XSS'
            if 'brute' in raw:
                return 'Web Attack — HTTP Brute Force'
            return 'Web Attack'

        if cat == 'botnet':
            return 'Botnet — C&C Communication'

        if cat == 'infiltration':
            return 'Network Infiltration'

        if cat == 'heartbleed':
            return 'Heartbleed — TLS Exploit'

        # ════════════════════════════════════════════════════════════════
        #  STAGE 2 — unlabeled / live traffic: flow-feature heuristics
        #
        #  RULE ORDER MATTERS.  More specific signatures (brute force on
        #  known ports) MUST be checked BEFORE generic volumetric rules
        #  to avoid misclassifying Patator-style attacks as DDoS.
        # ════════════════════════════════════════════════════════════════

        dst_port_raw = str(g(['Destination Port', 'dst_port'], ''))
        _brute_ports = {'21': 'FTP', '22': 'SSH', '23': 'Telnet',
                        '3389': 'RDP', '3306': 'MySQL', '5432': 'PostgreSQL',
                        '445': 'SMB', '1433': 'MSSQL'}

        # ── 1. Credential brute force (MUST come before volumetric rules) ─
        # Patator / Hydra flows: TCP, targeting auth ports, small packets,
        # bidirectional (server responds with auth challenge/reject).
        if is_tcp and dst_port_raw in _brute_ports:
            # Relaxed: even short Patator flows (3+ fwd packets) qualify
            if fwd_pkts >= 3 and avg_size < 600:
                return f'Brute Force — {_brute_ports[dst_port_raw]}'
            # Longer interactive sessions on auth ports
            if fwd_pkts > 20 and fwd_len < 300 and bwd_len < 300:
                return f'Brute Force — {_brute_ports[dst_port_raw]}'

        # Generic brute force (non-standard ports but small-packet pattern)
        if is_tcp and fwd_pkts > 20 and fwd_len < 250 and bwd_len < 250 and psh > 10:
            return 'Credential Brute Force'

        # ── 2. Volumetric floods ──────────────────────────────────────
        if pkt_rate > 10_000:
            if is_udp:
                return 'DDoS — UDP/ICMP Flood'
            return 'DDoS — SYN Flood' if syn > ack else 'DDoS — TCP Flood'

        if pkt_rate > 2_000 and is_tcp and byte_rate > 80_000:
            return 'DoS — Hulk (High Rate)'

        # ── 3. Slow / application-layer DoS ───────────────────────────
        if duration > 300_000_000 and fwd_pkts < 100 and is_tcp:
            return 'DoS — Slowloris'

        if duration > 60_000_000 and psh > 5 and fwd_pkts < 200 and is_tcp:
            return 'DoS — GoldenEye'

        # ── 4. Scanning / reconnaissance ──────────────────────────────
        if syn > 0 and fwd_pkts <= 3 and bwd_pkts == 0 and duration < 2_000_000:
            return 'Port Scan — SYN Stealth'

        if fwd_pkts <= 2 and bwd_pkts == 0 and duration < 500_000:
            return 'Network Scan'

        # ── 5. Web / application attacks ──────────────────────────────
        if is_tcp and psh > 0 and bwd_len > 800 and fwd_pkts > 5 and fin > 0:
            return 'Web Attack — Data Injection' if bwd_len > 5_000 else 'Web Attack — HTTP Exploit'

        # ── 6. Covert / flag exploits ─────────────────────────────────
        if urg > 0:
            return 'TCP Exploit — URG Flag'

        if rst > fwd_pkts * 0.5 and fwd_pkts > 5:
            return 'TCP RST Injection'

        # ── 7. Amplification (UDP reflection) ─────────────────────────
        if is_udp and bwd_len > 1_000 and fwd_pkts <= 3:
            return 'UDP Amplification Attack'

        # ── 8. TLS exploitation ───────────────────────────────────────
        if fwd_len < 50 and bwd_len > 5_000 and is_tcp and duration < 5_000_000:
            return 'Heartbleed — TLS Exploit'

        # ── 9. Covert data exfiltration ───────────────────────────────
        if duration > 500_000_000 and pkt_rate < 50 and bwd_len > fwd_len * 3:
            return 'Data Exfiltration'

        # ── 10. Botnet C&C beacon ─────────────────────────────────────
        if pkt_rate < 20 and duration > 30_000_000 and avg_size < 200:
            return 'Botnet — C&C Beacon'

        # ── 11. Slow attack fallback ──────────────────────────────────
        if duration > 100_000_000 and pkt_rate < 200:
            return 'DoS — Slow Attack'

        # ════════════════════════════════════════════════════════════════
        #  ZERO-DAY — high confidence, no known signature matched
        # ════════════════════════════════════════════════════════════════
        if novelty_score >= 0.65:
            return 'Zero-Day Candidate'

        return 'Network Anomaly'


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


# ── Helpers ────────────────────────────────────────────────────────────────────────

# ── Note: no random/synthetic IP generation ───────────────────────────────────────────
# When dataset columns (Source IP, Destination IP, Destination Port, Protocol)
# are absent — as is the case with CIC-IDS-2017 pre-extracted flow files —
# alerts will display 'N/A' in those fields.  No values are ever fabricated.
