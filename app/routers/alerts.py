"""
Alerts Router
==============
GET   /api/alerts              — list stored alerts (optional severity filter)
GET   /api/alerts/export.csv   — export analytical alert CSV
GET   /api/alerts/{id}         — single alert detail
PATCH /api/alerts/{id}/fp      — mark alert as false positive
"""

import csv
from collections import Counter
from datetime import datetime, timezone
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Query, Response
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


CSV_HEADERS = [
    "exported_at",
    "analysis_window_start",
    "analysis_window_end",
    "alert_id",
    "timestamp",
    "date",
    "hour",
    "attack_type",
    "attack_family",
    "severity",
    "severity_rank",
    "confidence",
    "confidence_pct",
    "risk_score",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "endpoint_pair",
    "is_zero_day",
    "is_false_positive",
    "review_status",
    "repeat_count_src_ip",
    "repeat_count_dst_ip",
    "repeat_count_attack_type",
    "repeat_count_endpoint_pair",
    "recommended_action",
    "analysis_note",
]

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_BASE_SCORE = {"critical": 90, "high": 70, "medium": 50, "low": 30}


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


def _split_timestamp(value: str) -> tuple[str, str]:
    raw = value or ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.date().isoformat(), f"{dt.hour:02d}:00"
    except ValueError:
        return raw[:10], raw[11:13] + ":00" if len(raw) >= 13 else ""


def _endpoint_pair(alert: AlertDB) -> str:
    return f"{alert.src_ip or 'N/A'} -> {alert.dst_ip or 'N/A'}:{alert.dst_port or 'N/A'}"


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


def _recommended_action(alert: AlertDB, family: str, repeat_count: int, risk_score: int) -> str:
    if alert.is_false_positive:
        return "No action; retained for audit as false positive"
    if alert.is_zero_day:
        return "Manual review required; compare raw flow features and monitor recurrence"
    if risk_score >= 90 or repeat_count >= 10:
        return "Investigate immediately; consider containment or source blocking"
    if family == "Brute Force":
        return "Review authentication logs and enforce account lockout controls"
    if family == "Reconnaissance":
        return "Check exposed services and monitor for follow-up exploitation"
    if family in {"DoS", "DDoS"}:
        return "Validate traffic volume and apply rate limiting or upstream filtering"
    if family == "Web Attack":
        return "Review web access logs and inspect affected application endpoint"
    return "Monitor and correlate with host, firewall, and application logs"


def _analysis_note(alert: AlertDB, family: str, repeat_count: int, risk_score: int) -> str:
    if alert.is_false_positive:
        return "Alert was reviewed and marked as a false positive."
    parts = [
        f"{family} alert with {alert.severity or 'unknown'} severity",
        f"{alert.confidence_pct or round(float(alert.confidence or 0) * 100)} confidence",
    ]
    if repeat_count > 1:
        parts.append(f"seen {repeat_count} times for the same endpoint pair")
    if alert.is_zero_day:
        parts.append("classified as zero-day candidate")
    parts.append(f"risk score {risk_score}/100")
    return "; ".join(parts) + "."


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
    alerts = query.order_by(AlertDB.id.desc()).offset(offset).limit(limit).all()
    
    return {
        "total":   total,
        "limit":   limit,
        "offset":  offset,
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
    """Export stored alerts with analytical fields for FYP/security review."""
    _require_export_role(user)
    alerts = (
        _base_alert_query(
            db, severity, attack_type, include_false_positive,
            zero_day_only, from_, to
        )
        .order_by(AlertDB.timestamp.asc(), AlertDB.id.asc())
        .all()
    )

    src_counts = Counter(a.src_ip or "N/A" for a in alerts)
    dst_counts = Counter(a.dst_ip or "N/A" for a in alerts)
    attack_counts = Counter(a.attack_type or "Unknown" for a in alerts)
    endpoint_counts = Counter(_endpoint_pair(a) for a in alerts)

    exported_at = datetime.now(timezone.utc).isoformat()
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_HEADERS, lineterminator="\n")
    writer.writeheader()

    for alert in alerts:
        date, hour = _split_timestamp(alert.timestamp or "")
        endpoint = _endpoint_pair(alert)
        repeat_count_endpoint = endpoint_counts[endpoint]
        family = _attack_family(alert.attack_type or "")
        severity_value = (alert.severity or "low").lower()
        risk = _risk_score(alert, repeat_count_endpoint)
        writer.writerow({
            "exported_at": exported_at,
            "analysis_window_start": from_ or "",
            "analysis_window_end": to or "",
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "date": date,
            "hour": hour,
            "attack_type": alert.attack_type,
            "attack_family": family,
            "severity": severity_value,
            "severity_rank": SEVERITY_RANK.get(severity_value, 1),
            "confidence": alert.confidence,
            "confidence_pct": alert.confidence_pct,
            "risk_score": risk,
            "src_ip": alert.src_ip or "N/A",
            "dst_ip": alert.dst_ip or "N/A",
            "dst_port": alert.dst_port or "N/A",
            "protocol": alert.protocol or "N/A",
            "endpoint_pair": endpoint,
            "is_zero_day": "Yes" if alert.is_zero_day else "No",
            "is_false_positive": "Yes" if alert.is_false_positive else "No",
            "review_status": "False Positive" if alert.is_false_positive else "Needs Review",
            "repeat_count_src_ip": src_counts[alert.src_ip or "N/A"],
            "repeat_count_dst_ip": dst_counts[alert.dst_ip or "N/A"],
            "repeat_count_attack_type": attack_counts[alert.attack_type or "Unknown"],
            "repeat_count_endpoint_pair": repeat_count_endpoint,
            "recommended_action": _recommended_action(alert, family, repeat_count_endpoint, risk),
            "analysis_note": _analysis_note(alert, family, repeat_count_endpoint, risk),
        })

    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="alerts_analysis_{filename_ts}.csv"'
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
