"""
Firewall Router
================
POST /api/firewall/block       — add a remote IP to blocklist; dev=1 enforces Windows Firewall on Windows
POST /api/firewall/unblock     — remove a blocklist entry and matching dev firewall rule when applicable
GET  /api/firewall/blocked     — list all currently blocklisted IPs
"""

import ipaddress
import logging
import platform
import subprocess
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Query
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
logger = logging.getLogger(__name__)

# ── In-memory blocked IP registry ────────────────────────────────────
_blocked_ips: dict = {}   # { ip: { blocked_at, reason, rule_name } }

RULE_PREFIX = "AIS-Detect Block"
BLOCKLIST_PREFIX = "AIS-Detect Blocklist"


class BlockRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Blocked by AIS-Detect"


class UnblockRequest(BaseModel):
    ip: str


def _sanitise_ip(ip: str) -> str:
    """Validate and normalize dotted-decimal IPv4 addresses."""
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")

    if parsed.version != 4:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address: {ip}")
    return str(parsed)


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_windows_rule(rule_name: str) -> bool:
    return str(rule_name or "").startswith(f"{RULE_PREFIX}:")


def _entry_mode(rule_name: str) -> str:
    return "windows_firewall" if _is_windows_rule(rule_name) else "blocklist_only"


def _run_windows_block(ip: str, rule_name: str) -> None:
    result = subprocess.run(
        [
            "powershell", "-NoProfile", "-Command",
            f'New-NetFirewallRule -DisplayName "{rule_name}" '
            f'-Direction Outbound -Action Block '
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


def _run_windows_unblock(rule_name: str) -> None:
    result = subprocess.run(
        [
            "powershell", "-NoProfile", "-Command",
            f'Remove-NetFirewallRule -DisplayName "{rule_name}"',
        ],
        capture_output=True, text=True, timeout=10,
    )

    if result.returncode != 0:
        logger.warning(
            "Firewall unblock command failed for %s: %s",
            rule_name,
            result.stderr.strip() or result.stdout.strip(),
        )


# ═══════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/block")
async def block_ip(
    req: BlockRequest,
    dev: bool = Query(False, description="When true on Windows, enforce with Windows Firewall."),
    db: Session = Depends(get_db),
):
    """
    Add a remote IP address to the AIS-Detect blocklist.

    Normal/deployed mode is blocklist-only. When called with ?dev=1 on a
    Windows host, the backend also creates an outbound Windows Firewall rule.
    """
    ip = _sanitise_ip(req.ip)

    if ip in _blocked_ips:
        rule_name = _blocked_ips[ip].get("rule_name", "")
        return {
            "message": f"{ip} is already blocklisted",
            "already_blocked": True,
            "mode": _entry_mode(rule_name),
        }

    enforce_windows = bool(dev and _is_windows())
    rule_name = f"{RULE_PREFIX}: {ip}" if enforce_windows else f"{BLOCKLIST_PREFIX}: {ip}"

    if enforce_windows:
        try:
            _run_windows_block(ip, rule_name)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="PowerShell not found on this system.")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=500, detail="Firewall command timed out.")

    blocked_time = datetime.utcnow().isoformat()
    reason = req.reason or "Blocklisted by AIS-Detect"
    mode = _entry_mode(rule_name)

    _blocked_ips[ip] = {
        "ip": ip,
        "blocked_at": blocked_time,
        "reason": reason,
        "rule_name": rule_name,
        "mode": mode,
    }

    # Save to DB
    new_block = BlockedIPDB(ip=ip, blocked_at=blocked_time, reason=reason, rule_name=rule_name)
    db.add(new_block)
    db.commit()

    return {
        "message": f"Windows Firewall blocked {ip}" if enforce_windows else f"Added {ip} to AIS-Detect blocklist",
        "ip": ip,
        "rule_name": rule_name,
        "mode": mode,
    }


@router.post("/unblock")
async def unblock_ip(req: UnblockRequest, db: Session = Depends(get_db)):
    """
    Remove a blocklist entry and the Windows Firewall rule when applicable.
    """
    ip = _sanitise_ip(req.ip)

    if ip not in _blocked_ips:
        raise HTTPException(status_code=404, detail=f"{ip} is not in the blocked list.")

    rule_name = _blocked_ips[ip]["rule_name"]

    if _is_windows_rule(rule_name) and _is_windows():
        try:
            _run_windows_unblock(rule_name)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("Firewall unblock command could not run for %s: %s", ip, exc)

    del _blocked_ips[ip]

    # Remove from DB
    blocked_record = db.query(BlockedIPDB).filter(BlockedIPDB.ip == ip).first()
    if blocked_record:
        db.delete(blocked_record)
        db.commit()

    return {"message": f"Removed {ip} from blocklist", "ip": ip}


@router.get("/blocked")
async def list_blocked(db: Session = Depends(get_db)):
    """Return all currently blocklisted IPs from the database."""
    blocked = db.query(BlockedIPDB).all()
    return {
        "blocked": [
            {
                "ip": row.ip,
                "blocked_at": row.blocked_at,
                "reason": row.reason,
                "rule_name": row.rule_name,
                "mode": _entry_mode(row.rule_name),
            }
            for row in blocked
        ],
        "count": len(blocked),
    }
