"""
Firewall Router
================
POST /api/firewall/block       — block an IP via Windows Firewall
POST /api/firewall/unblock     — remove a block rule
GET  /api/firewall/blocked     — list all currently blocked IPs
"""

import subprocess
import re
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.models.db_models import BlockedIPDB
from app.routers.auth import get_current_user

router = APIRouter(
    prefix="/api/firewall",
    tags=["firewall"],
    dependencies=[Depends(get_current_user)]
)

# ── In-memory blocked IP registry ────────────────────────────────────
_blocked_ips: dict = {}   # { ip: { blocked_at, reason, rule_name } }

RULE_PREFIX = "AIS-Detect Block"


class BlockRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Blocked by AIS-Detect"


class UnblockRequest(BaseModel):
    ip: str


def _sanitise_ip(ip: str) -> str:
    """Basic validation — only allow dotted-decimal IPv4."""
    ip = ip.strip()
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")
    return ip


# ═══════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/block")
async def block_ip(req: BlockRequest, db: Session = Depends(get_db)):
    """
    Block an IP address by creating an inbound Windows Firewall rule.
    Requires the backend to be running with Administrator privileges.
    """
    ip = _sanitise_ip(req.ip)

    if ip in _blocked_ips:
        return {"message": f"{ip} is already blocked", "already_blocked": True}

    rule_name = f"{RULE_PREFIX}: {ip}"

    try:
        # Create inbound block rule
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f'New-NetFirewallRule -DisplayName "{rule_name}" '
                f'-Direction Inbound -Action Block '
                f'-RemoteAddress {ip} '
                f'-Profile Any '
                f'-Enabled True',
            ],
            capture_output=True, text=True, timeout=10,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Firewall command failed: {result.stderr.strip() or result.stdout.strip()}",
            )

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="PowerShell not found on this system.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Firewall command timed out.")

    blocked_time = datetime.utcnow().isoformat()
    reason = req.reason or "Blocked by AIS-Detect"

    _blocked_ips[ip] = {
        "ip": ip,
        "blocked_at": blocked_time,
        "reason": reason,
        "rule_name": rule_name,
    }

    # Save to DB
    new_block = BlockedIPDB(ip=ip, blocked_at=blocked_time, reason=reason, rule_name=rule_name)
    db.add(new_block)
    db.commit()

    return {
        "message": f"Successfully blocked {ip}",
        "ip": ip,
        "rule_name": rule_name,
    }


@router.post("/unblock")
async def unblock_ip(req: UnblockRequest, db: Session = Depends(get_db)):
    """
    Remove the Windows Firewall block rule for an IP address.
    """
    ip = _sanitise_ip(req.ip)

    if ip not in _blocked_ips:
        raise HTTPException(status_code=404, detail=f"{ip} is not in the blocked list.")

    rule_name = _blocked_ips[ip]["rule_name"]

    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f'Remove-NetFirewallRule -DisplayName "{rule_name}"',
            ],
            capture_output=True, text=True, timeout=10,
        )

        if result.returncode != 0:
            # Rule may have been manually deleted — still remove from registry
            pass

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass   # best effort — still remove from local registry

    del _blocked_ips[ip]

    # Remove from DB
    blocked_record = db.query(BlockedIPDB).filter(BlockedIPDB.ip == ip).first()
    if blocked_record:
        db.delete(blocked_record)
        db.commit()

    return {"message": f"Unblocked {ip}", "ip": ip}


@router.get("/blocked")
async def list_blocked(db: Session = Depends(get_db)):
    """Return all currently blocked IPs from the database."""
    blocked = db.query(BlockedIPDB).all()
    return {
        "blocked": blocked,
        "count": len(blocked),
    }
