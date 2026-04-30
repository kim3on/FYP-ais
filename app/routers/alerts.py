"""
Alerts Router
==============
GET   /api/alerts              — list stored alerts (optional severity filter)
GET   /api/alerts/{id}         — single alert detail
PATCH /api/alerts/{id}/fp      — mark alert as false positive
"""

from fastapi import APIRouter, HTTPException
from typing import Optional

from app.state import _state

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    severity: Optional[str] = None,
    limit:    int = 100,
    offset:   int = 0,
):
    """List stored alerts with optional severity filter."""
    alerts = _state["alerts"]
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    total = len(alerts)
    page  = alerts[offset: offset + limit]
    return {
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "alerts":  page,
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str):
    """Return a single alert by ID."""
    for a in _state["alerts"]:
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


@router.patch("/{alert_id}/fp")
async def mark_false_positive(alert_id: str):
    """Mark an alert as a false positive (analyst review)."""
    for a in _state["alerts"]:
        if a.get("alert_id") == alert_id:
            a["is_false_positive"] = True
            return {"success": True, "alert_id": alert_id}
    raise HTTPException(status_code=404, detail="Alert not found")
