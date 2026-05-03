"""
Alerts Router
==============
GET   /api/alerts              — list stored alerts (optional severity filter)
GET   /api/alerts/{id}         — single alert detail
PATCH /api/alerts/{id}/fp      — mark alert as false positive
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.models.db_models import AlertDB

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


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
