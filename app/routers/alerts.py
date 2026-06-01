"""
Alerts Router
==============
GET   /api/alerts              — list stored alerts (optional severity filter)
GET   /api/alerts/export.csv   — export analytical alert CSV
GET   /api/alerts/{id}         — single alert detail
PATCH /api/alerts/{id}/fp      — mark alert as false positive
"""

import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.models.db_models import AlertDB
from app.routers.auth import get_current_user

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
    dependencies=[Depends(get_current_user)]
)


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_BASE_SCORE = {"critical": 90, "high": 70, "medium": 50, "low": 30}
ACTION_LEGEND = {
    "FP_AUDIT": "False positive retained for review/audit; no immediate response required.",
    "MANUAL_ZERO_DAY": "Manually inspect raw flow context and monitor recurrence because this is a zero-day candidate.",
    "INVESTIGATE_NOW": "Prioritize investigation; consider containment or source blocking if corroborated.",
    "REVIEW_AUTH": "Review authentication logs and enforce account lockout or credential controls.",
    "CHECK_EXPOSURE": "Check exposed services and monitor for follow-up exploitation.",
    "RATE_LIMIT": "Validate traffic volume and apply rate limiting or upstream filtering where appropriate.",
    "REVIEW_WEB": "Review web access logs and inspect the affected application endpoint.",
    "MONITOR": "Monitor and correlate with host, firewall, and application logs.",
}
ENDPOINT_ROLE_FIELDS = [
    "traffic_direction",
    "flow_initiator_ip",
    "flow_responder_ip",
    "local_ip",
    "remote_ip",
    "suspected_attacker_ip",
    "suspected_victim_ip",
    "suspected_compromised_host",
    "containment_target_ip",
    "endpoint_role_confidence",
    "endpoint_role_reason",
]


def _require_export_role(user):
    """Allow administrator and analyst roles to export alert analysis."""
    role = (getattr(user, "role", "") or "").lower()
    if "administrator" not in role and "analyst" not in role and role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Insufficient role for alert export")


def _attack_family(attack_type: str) -> str:
    text = (attack_type or "").lower()
    if "zero-day" in text:
        return "Unknown / Novel"
    if "ddos" in text:
        return "DDoS"
    if "dos" in text:
        return "DoS"
    if "brute" in text or "credential" in text:
        return "Brute Force"
    if "scan" in text or "probe" in text or "enumeration" in text:
        return "Reconnaissance"
    if "web" in text or "http" in text or "sql" in text or "xss" in text:
        return "Web Attack"
    if "botnet" in text or "beacon" in text:
        return "Botnet"
    if "infiltration" in text or "exfiltration" in text:
        return "Infiltration"
    if "heartbleed" in text:
        return "Heartbleed"
    return "Unknown"


def _endpoint_key(alert: AlertDB) -> tuple[str, str, str, str]:
    return (
        alert.src_ip or "N/A",
        alert.dst_ip or "N/A",
        str(alert.dst_port or "N/A"),
        alert.protocol or "N/A",
    )


def _risk_score(alert: AlertDB, repeat_count: int) -> int:
    if alert.is_false_positive:
        return 0
    severity = (alert.severity or "low").lower()
    confidence = float(alert.confidence or 0.0)
    base = SEVERITY_BASE_SCORE.get(severity, 30)
    score = base * (0.75 + 0.25 * min(max(confidence, 0.0), 1.0))
    if alert.is_zero_day:
        score += 10
    if repeat_count >= 10:
        score += 15
    elif repeat_count >= 3:
        score += 8
    return int(min(round(score), 100))


def _action_code(alert: AlertDB, family: str, repeat_count: int, risk_score: int) -> str:
    if alert.is_false_positive:
        return "FP_AUDIT"
    if alert.is_zero_day:
        return "MANUAL_ZERO_DAY"
    if risk_score >= 90 or repeat_count >= 10:
        return "INVESTIGATE_NOW"
    if family == "Brute Force":
        return "REVIEW_AUTH"
    if family == "Reconnaissance":
        return "CHECK_EXPOSURE"
    if family in {"DoS", "DDoS"}:
        return "RATE_LIMIT"
    if family == "Web Attack":
        return "REVIEW_WEB"
    return "MONITOR"


def _base_alert_query(db: Session, severity: Optional[str], attack_type: Optional[str],
                      include_false_positive: bool, zero_day_only: bool,
                      from_: Optional[str], to: Optional[str]):
    query = db.query(AlertDB)
    if severity:
        query = query.filter(AlertDB.severity == severity.lower())
    if attack_type:
        query = query.filter(AlertDB.attack_type.ilike(f"%{attack_type}%"))
    if not include_false_positive:
        query = query.filter(AlertDB.is_false_positive == False)  # noqa: E712
    if zero_day_only:
        query = query.filter(AlertDB.is_zero_day == True)  # noqa: E712
    if from_:
        query = query.filter(AlertDB.timestamp >= from_)
    if to:
        query = query.filter(AlertDB.timestamp <= to)
    return query


def _csv_safe(value):
    """Prevent Excel formula injection while leaving csv.writer to quote cells."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    if text and text.lstrip()[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def _write_csv_section(writer, title: str, headers: list[str], rows: list[list]):
    writer.writerow([f"# {title}"])
    writer.writerow([_csv_safe(cell) for cell in headers])
    for row in rows:
        writer.writerow([_csv_safe(cell) for cell in row])
    writer.writerow([])


def _parse_timestamp_for_sort(value: str) -> datetime:
    raw = value or ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _percentage(count: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(count / total) * 100:.1f}%"


def _max_severity(alerts: list[AlertDB]) -> str:
    if not alerts:
        return "N/A"
    return max(
        ((a.severity or "low").lower() for a in alerts),
        key=lambda severity: SEVERITY_RANK.get(severity, 0),
    )


def _mode(values) -> str:
    clean = [value for value in values if value]
    if not clean:
        return "Unknown"
    return Counter(clean).most_common(1)[0][0]


def _build_alert_summaries(alerts: list[AlertDB], filters: dict, exported_at: str) -> dict:
    endpoint_counts = Counter(_endpoint_key(alert) for alert in alerts)
    records = []

    for alert in alerts:
        endpoint = _endpoint_key(alert)
        repeat_count = endpoint_counts[endpoint]
        family = _attack_family(alert.attack_type or "")
        severity = (alert.severity or "low").lower()
        risk = _risk_score(alert, repeat_count)
        records.append({
            "alert": alert,
            "family": family,
            "severity": severity,
            "risk": risk,
            "endpoint": endpoint,
            "repeat_count": repeat_count,
            "action_code": _action_code(alert, family, repeat_count, risk),
        })

    total = len(records)
    false_positive_count = sum(1 for item in records if item["alert"].is_false_positive)
    zero_day_count = sum(1 for item in records if item["alert"].is_zero_day)
    actionable_count = sum(1 for item in records if not item["alert"].is_false_positive)
    sorted_alerts = sorted(alerts, key=lambda alert: _parse_timestamp_for_sort(alert.timestamp or ""))
    filter_text = ", ".join(
        f"{key}={value}" for key, value in filters.items()
        if value not in (None, "", False)
    ) or "none"

    report_overview = [
        ["exported_at", exported_at],
        ["filter_used", filter_text],
        ["requested_window_start", filters.get("from") or ""],
        ["requested_window_end", filters.get("to") or ""],
        ["actual_first_seen", sorted_alerts[0].timestamp if sorted_alerts else ""],
        ["actual_last_seen", sorted_alerts[-1].timestamp if sorted_alerts else ""],
        ["total_alerts", total],
        ["false_positive_count", false_positive_count],
        ["zero_day_count", zero_day_count],
        ["actionable_alerts", actionable_count],
    ]
    if total == 0:
        report_overview.append(["note", "No alerts matched this export filter"])

    severity_counts = Counter(item["severity"] for item in records)
    severity_summary = [
        [severity, count, _percentage(count, total)]
        for severity, count in sorted(
            severity_counts.items(),
            key=lambda item: (-SEVERITY_RANK.get(item[0], 0), item[0]),
        )
    ]

    family_counts = Counter(item["family"] for item in records)
    family_summary = [
        [family, count, _percentage(count, total)]
        for family, count in sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    direction_counts = Counter(
        (getattr(item["alert"], "traffic_direction", None) or "unknown").lower()
        for item in records
    )
    direction_summary = [
        [direction, count, _percentage(count, total)]
        for direction, count in sorted(direction_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    by_src = defaultdict(list)
    by_dst = defaultdict(list)
    by_remote = defaultdict(list)
    by_endpoint = defaultdict(list)
    for item in records:
        alert = item["alert"]
        by_src[alert.src_ip or "N/A"].append(item)
        by_dst[alert.dst_ip or "N/A"].append(item)
        remote_ip = getattr(alert, "remote_ip", None) or ""
        if remote_ip and remote_ip.upper() != "N/A":
            by_remote[remote_ip].append(item)
        by_endpoint[item["endpoint"]].append(item)

    def group_sort_key(items):
        return (-len(items), -max(item["risk"] for item in items), _max_severity([item["alert"] for item in items]))

    top_sources = []
    for src_ip, items in sorted(by_src.items(), key=lambda pair: group_sort_key(pair[1]))[:10]:
        alerts_in_group = [item["alert"] for item in items]
        top_sources.append([
            src_ip,
            len(items),
            len({alert.dst_ip or "N/A" for alert in alerts_in_group}),
            _mode(item["family"] for item in items),
            _max_severity(alerts_in_group),
            max(item["risk"] for item in items),
        ])

    top_targets = []
    for dst_ip, items in sorted(by_dst.items(), key=lambda pair: group_sort_key(pair[1]))[:10]:
        alerts_in_group = [item["alert"] for item in items]
        top_targets.append([
            dst_ip,
            len(items),
            len({alert.src_ip or "N/A" for alert in alerts_in_group}),
            _mode(item["family"] for item in items),
            _max_severity(alerts_in_group),
            max(item["risk"] for item in items),
        ])

    top_remote_endpoints = []
    for remote_ip, items in sorted(by_remote.items(), key=lambda pair: group_sort_key(pair[1]))[:10]:
        alerts_in_group = [item["alert"] for item in items]
        top_remote_endpoints.append([
            remote_ip,
            len(items),
            len({getattr(alert, "local_ip", None) or "N/A" for alert in alerts_in_group}),
            _mode(item["family"] for item in items),
            _max_severity(alerts_in_group),
            max(item["risk"] for item in items),
            _mode(getattr(alert, "traffic_direction", None) for alert in alerts_in_group),
        ])

    repeated_endpoints = []
    repeated_groups = [
        (endpoint, items)
        for endpoint, items in by_endpoint.items()
        if len(items) >= 3
    ]
    for endpoint, items in sorted(repeated_groups, key=lambda pair: group_sort_key(pair[1])):
        src_ip, dst_ip, dst_port, protocol = endpoint
        alerts_in_group = sorted(
            [item["alert"] for item in items],
            key=lambda alert: _parse_timestamp_for_sort(alert.timestamp or ""),
        )
        repeated_endpoints.append([
            src_ip,
            dst_ip,
            dst_port,
            protocol,
            len(items),
            alerts_in_group[0].timestamp if alerts_in_group else "",
            alerts_in_group[-1].timestamp if alerts_in_group else "",
            _max_severity(alerts_in_group),
            max(item["risk"] for item in items),
        ])

    priority_items = sorted(
        [item for item in records if not item["alert"].is_false_positive],
        key=lambda item: (
            item["risk"],
            _parse_timestamp_for_sort(item["alert"].timestamp or ""),
        ),
        reverse=True,
    )[:15]
    priority_incidents = []
    for rank, item in enumerate(priority_items, start=1):
        alert = item["alert"]
        priority_incidents.append([
            rank,
            alert.alert_id,
            alert.timestamp,
            item["severity"],
            item["family"],
            alert.attack_type or "Unknown",
            item["risk"],
            alert.src_ip or "N/A",
            alert.dst_ip or "N/A",
            getattr(alert, "traffic_direction", None) or "",
            getattr(alert, "local_ip", None) or "",
            getattr(alert, "remote_ip", None) or "",
            alert.dst_port or "N/A",
            item["action_code"],
        ])

    return {
        "report_overview": report_overview,
        "severity_summary": severity_summary,
        "family_summary": family_summary,
        "direction_summary": direction_summary,
        "top_sources": top_sources,
        "top_targets": top_targets,
        "top_remote_endpoints": top_remote_endpoints,
        "repeated_endpoints": repeated_endpoints,
        "priority_incidents": priority_incidents,
        "action_legend": [[code, description] for code, description in ACTION_LEGEND.items()],
    }


@router.get("")
async def list_alerts(
    severity: Optional[str] = None,
    limit:    int = 100,
    offset:   int = 0,
    db: Session = Depends(get_db)
):
    """List stored alerts with optional severity filter."""
    query = db.query(AlertDB)
    if severity:
        query = query.filter(AlertDB.severity == severity)
    
    total = query.count()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, count in (
        query
        .with_entities(func.lower(AlertDB.severity), func.count(AlertDB.id))
        .group_by(func.lower(AlertDB.severity))
        .all()
    ):
        key = (sev or "low").lower()
        if key in severity_counts:
            severity_counts[key] = int(count or 0)
    zero_day_count = query.filter(AlertDB.is_zero_day == True).count()  # noqa: E712
    alerts = query.order_by(AlertDB.id.desc()).offset(offset).limit(limit).all()
    
    return {
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "returned": len(alerts),
        "severity_counts": severity_counts,
        "zero_day_count": zero_day_count,
        "alerts":  alerts,
    }


@router.get("/export.csv")
async def export_alerts_csv(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    include_false_positive: bool = True,
    zero_day_only: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export a sectioned alert summary CSV for FYP/security review."""
    _require_export_role(user)
    alerts = (
        _base_alert_query(
            db, severity, attack_type, include_false_positive,
            zero_day_only, from_, to
        )
        .order_by(AlertDB.timestamp.asc(), AlertDB.id.asc())
        .all()
    )

    exported_at = datetime.now(timezone.utc).isoformat()
    filters = {
        "from": from_,
        "to": to,
        "severity": severity,
        "attack_type": attack_type,
        "include_false_positive": include_false_positive,
        "zero_day_only": zero_day_only,
    }
    summaries = _build_alert_summaries(alerts, filters, exported_at)

    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    _write_csv_section(writer, "Report Overview", ["metric", "value"], summaries["report_overview"])
    if alerts:
        _write_csv_section(writer, "Severity Summary", ["severity", "count", "percentage"], summaries["severity_summary"])
        _write_csv_section(writer, "Attack Family Summary", ["attack_family", "count", "percentage"], summaries["family_summary"])
        _write_csv_section(writer, "Direction Summary", ["traffic_direction", "count", "percentage"], summaries["direction_summary"])
        _write_csv_section(writer, "Top Sources", ["src_ip", "alert_count", "unique_targets", "top_attack_family", "max_severity", "max_risk_score"], summaries["top_sources"])
        _write_csv_section(writer, "Top Targets", ["dst_ip", "alert_count", "unique_sources", "top_attack_family", "max_severity", "max_risk_score"], summaries["top_targets"])
        _write_csv_section(writer, "Top Remote Endpoints", ["remote_ip", "alert_count", "unique_local_endpoints", "top_attack_family", "max_severity", "max_risk_score", "top_direction"], summaries["top_remote_endpoints"])
        _write_csv_section(writer, "Repeated Endpoint Pairs", ["src_ip", "dst_ip", "dst_port", "protocol", "count", "first_seen", "last_seen", "max_severity", "max_risk_score"], summaries["repeated_endpoints"])
        _write_csv_section(writer, "Priority Incidents", ["priority_rank", "alert_id", "timestamp", "severity", "attack_family", "attack_type", "risk_score", "src_ip", "dst_ip", "traffic_direction", "local_ip", "remote_ip", "dst_port", "action_code"], summaries["priority_incidents"])
        _write_csv_section(writer, "Action Legend", ["action_code", "explanation"], summaries["action_legend"])

    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_summary_{filename_ts}.csv"'
        },
    )


@router.get("/export_raw.csv")
async def export_raw_alerts_csv(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    include_false_positive: bool = True,
    zero_day_only: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Export a raw flat alert list CSV containing all DB fields."""
    _require_export_role(user)
    alerts = (
        _base_alert_query(
            db, severity, attack_type, include_false_positive,
            zero_day_only, from_, to
        )
        .order_by(AlertDB.timestamp.asc(), AlertDB.id.asc())
        .all()
    )

    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    
    # Headers
    headers = [
        "id", "alert_id", "timestamp", "attack_type", "src_ip", "dst_ip", 
        "dst_port", "protocol", "severity", "confidence", "confidence_pct", 
        "is_false_positive", "is_zero_day", *ENDPOINT_ROLE_FIELDS
    ]
    writer.writerow(headers)
    
    for alert in alerts:
        row = [
            alert.id,
            alert.alert_id,
            alert.timestamp,
            alert.attack_type,
            alert.src_ip,
            alert.dst_ip,
            alert.dst_port,
            alert.protocol,
            alert.severity,
            alert.confidence,
            alert.confidence_pct,
            "Yes" if alert.is_false_positive else "No",
            "Yes" if alert.is_zero_day else "No",
            *[getattr(alert, field, "") for field in ENDPOINT_ROLE_FIELDS],
        ]
        writer.writerow([_csv_safe(cell) for cell in row])

    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_raw_{filename_ts}.csv"'
        },
    )


@router.get("/{alert_id}")
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Return a single alert by ID."""
    alert = db.query(AlertDB).filter(AlertDB.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/fp")
async def mark_false_positive(alert_id: str, db: Session = Depends(get_db)):
    """Mark an alert as a false positive (analyst review)."""
    alert = db.query(AlertDB).filter(AlertDB.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_false_positive = True
    db.commit()
    return {"success": True, "alert_id": alert_id}


@router.delete("")
async def clear_all_alerts(db: Session = Depends(get_db)):
    """Delete all alerts from the database."""
    deleted_count = db.query(AlertDB).delete()
    db.commit()
    return {"success": True, "deleted_count": deleted_count}
