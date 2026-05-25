"""
Post-alert attack attribution helpers.

These heuristics run only after Layer 1 has already flagged a flow as
anomalous. They never read ground-truth label columns.
"""

import pandas as pd

DEFAULT_ZERO_DAY_THRESHOLD = 0.65


def _get(row, keys: list, default):
    """Try multiple column name variants with a fallback default."""
    if isinstance(row, pd.Series):
        for key in keys:
            if key in row.index and pd.notna(row[key]):
                return row[key]
    elif isinstance(row, dict):
        for key in keys:
            if key in row:
                return row[key]
    return default


def attribute_attack(
    row,
    novelty_score: float = 0.0,
    zero_day_threshold: float | None = None,
) -> str:
    """
    Attribute a post-detection anomaly using flow features only.

    Rule order matters: specific credential-brute-force patterns are checked
    before generic volumetric rules so short auth dialogues are not mislabeled
    as floods.
    """
    def g(keys, default=0):
        return _get(row, keys, default)

    pkt_rate = g(["Flow Packets/s", "Flow Pkts/s", "flow packets/s"])
    byte_rate = g(["Flow Bytes/s", "flow bytes/s"])
    duration = g(["Flow Duration", "flow duration"])
    fwd_pkts = g(["Total Fwd Packets", "Total Fwd Pkts"])
    bwd_pkts = g(["Total Backward Packets", "Total Bwd Pkts", "Total Bwd Packets"])
    fwd_len = g(["Fwd Packet Length Mean", "Fwd Pkt Len Mean"])
    bwd_len = g(["Bwd Packet Length Mean", "Bwd Pkt Len Mean"])
    avg_size = g(["Average Packet Size", "Avg Fwd Segment Size"])
    syn = g(["SYN Flag Count", "SYN Flag Cnt"])
    ack = g(["ACK Flag Count", "ACK Flag Cnt"])
    psh = g(["PSH Flag Count", "PSH Flag Cnt"])
    rst = g(["RST Flag Count", "RST Flag Cnt"])
    urg = g(["URG Flag Count", "URG Flag Cnt"])
    fin = g(["FIN Flag Count", "FIN Flag Cnt"])
    proto_raw = str(g(["Protocol", "protocol"], "")).strip()
    is_tcp = proto_raw in ("6", "TCP", "tcp")
    is_udp = proto_raw in ("17", "UDP", "udp")

    dst_port_raw = str(g(["Destination Port", "dst_port"], ""))
    brute_ports = {
        "21": "FTP",
        "22": "SSH",
        "23": "Telnet",
        "3389": "RDP",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "445": "SMB",
        "1433": "MSSQL",
    }

    if is_tcp and dst_port_raw in brute_ports:
        if fwd_pkts >= 3 and avg_size < 600:
            return f"Brute Force — {brute_ports[dst_port_raw]}"
        if fwd_pkts > 20 and fwd_len < 300 and bwd_len < 300:
            return f"Brute Force — {brute_ports[dst_port_raw]}"

    if is_tcp and fwd_pkts > 20 and fwd_len < 250 and bwd_len < 250 and psh > 10:
        return "Credential Brute Force"

    if pkt_rate > 10_000:
        if is_udp:
            return "DDoS — UDP/ICMP Flood"
        return "DDoS — SYN Flood" if syn > ack else "DDoS — TCP Flood"

    if pkt_rate > 2_000 and is_tcp and byte_rate > 80_000:
        return "DoS — Hulk (High Rate)"
    if duration > 300_000_000 and fwd_pkts < 100 and is_tcp:
        return "DoS — Slowloris"
    if duration > 60_000_000 and psh > 5 and fwd_pkts < 200 and is_tcp:
        return "DoS — GoldenEye"
    if syn > 0 and fwd_pkts <= 3 and bwd_pkts == 0 and duration < 2_000_000:
        return "Port Scan — SYN Stealth"
    if fwd_pkts <= 2 and bwd_pkts == 0 and duration < 500_000:
        return "Network Scan"
    if is_tcp and psh > 0 and bwd_len > 800 and fwd_pkts > 5 and fin > 0:
        return "Web Attack — Data Injection" if bwd_len > 5_000 else "Web Attack — HTTP Exploit"
    if urg > 0:
        return "TCP Exploit — URG Flag"
    if rst > fwd_pkts * 0.5 and fwd_pkts > 5:
        return "TCP RST Injection"
    if is_udp and bwd_len > 1_000 and fwd_pkts <= 3:
        return "UDP Amplification Attack"
    if fwd_len < 50 and bwd_len > 5_000 and is_tcp and duration < 5_000_000:
        return "Heartbleed — TLS Exploit"
    if duration > 500_000_000 and pkt_rate < 50 and bwd_len > fwd_len * 3:
        return "Data Exfiltration"
    if pkt_rate < 20 and duration > 30_000_000 and avg_size < 200:
        return "Botnet — C&C Beacon"
    if duration > 100_000_000 and pkt_rate < 200:
        return "DoS — Slow Attack"

    threshold = DEFAULT_ZERO_DAY_THRESHOLD if zero_day_threshold is None else zero_day_threshold
    if novelty_score >= float(threshold):
        return "Zero-Day Candidate"

    return "Unknown Anomaly"
