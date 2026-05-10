"""
Capture Router
===============
POST /api/capture/start        — start live packet capture
POST /api/capture/stop         — stop live packet capture
GET  /api/capture/status       — current capture counters
GET  /api/capture/interfaces   — list available network interfaces
GET  /api/capture/chartdata    — last-60-s ring buffer for the live chart
WS   /ws/live                  — WebSocket push for real-time dashboard updates
"""

import asyncio
import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends, status, Query
from sqlalchemy.orm import Session

from app.core.pipeline import models_ready
from app.state import _state, _build_engine
from app.core.database import get_db, SessionLocal
from app.models.db_models import RawFlowDB, AlertDB
from app.routers.auth import get_current_user

router = APIRouter(tags=["capture"])


# ═══════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/api/capture/start")
async def start_capture(interface: Optional[str] = None, user=Depends(get_current_user)):
    """
    Start live packet capture on the given interface.
    Requires root/admin privileges and scapy installed.
    """
    if _state["capture_active"]:
        raise HTTPException(status_code=409, detail="Capture already running")

    if not models_ready():
        raise HTTPException(
            status_code=400,
            detail="Models not trained yet. Train first, then start capture.",
        )

    try:
        from app.core.capture import PacketSniffer
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Scapy not installed. Run: pip install scapy",
        )

    engine = _build_engine()
    loop   = asyncio.get_running_loop()

    def on_flow(features: dict):
        """Called by FlowAggregator each time a flow completes."""
        meta_keys = ['_src_ip', '_dst_ip', '_src_port', '_dst_port', '_protocol']
        meta = {k.lstrip('_'): features.pop(k, '?') for k in meta_keys}

        try:
            result = engine.detect_sample(features)
        except Exception:
            return

        _state["packet_count"] += 1
        _state["flows_completed"] += 1
        _state["chart_normal"].pop(0)
        _state["chart_anomaly"].pop(0)

        db = SessionLocal()
        timestamp = datetime.datetime.utcnow().isoformat()
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_str = proto_map.get(meta.get("protocol", 0), "TCP")

        # Safely convert dst_port to int, defaulting to 0 if 'N/A' or invalid
        try:
            dst_port_int = int(meta.get("dst_port", 0) or 0)
        except (ValueError, TypeError):
            dst_port_int = 0
        
        raw_flow = RawFlowDB(
            timestamp=timestamp,
            src_ip=str(meta.get("src_ip", "")),
            dst_ip=str(meta.get("dst_ip", "")),
            dst_port=dst_port_int,
            protocol=proto_str,
            flow_bytes_s=float(features.get("Flow Bytes/s", 0.0) or 0.0)
        )
        db.add(raw_flow)

        if result["anomalies_found"] > 0:
            _state["anomaly_count"] += 1
            _state["chart_normal"].append(0)
            _state["chart_anomaly"].append(1)

            for alert in result["alerts"]:
                alert["src_ip"]   = meta.get("src_ip",   alert.get("src_ip", ""))
                alert["dst_ip"]   = meta.get("dst_ip",   alert.get("dst_ip", ""))
                alert["dst_port"] = str(meta.get("dst_port", alert.get("dst_port", "")))
                alert["protocol"] = proto_str
                
                try:
                    alert_dst_port_int = int(alert.get("dst_port", 0) or 0)
                except (ValueError, TypeError):
                    alert_dst_port_int = 0

                db_alert = AlertDB(
                    alert_id=alert["alert_id"],
                    timestamp=alert["timestamp"],
                    attack_type=alert["attack_type"],
                    src_ip=alert["src_ip"],
                    dst_ip=alert["dst_ip"],
                    dst_port=alert_dst_port_int,
                    protocol=alert["protocol"],
                    severity=alert["severity"],
                    confidence=alert["confidence"],
                    confidence_pct=alert["confidence_pct"],
                    is_false_positive=False,
                    is_zero_day=alert["is_zero_day"],
                    raw_features=features
                )
                db.add(db_alert)
            _state["alerts"].extend(result["alerts"])
        else:
            _state["chart_normal"].append(1)
            _state["chart_anomaly"].append(0)

        try:
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        asyncio.run_coroutine_threadsafe(_broadcast_live_update(result, meta), loop)

    sniffer = PacketSniffer(on_flow_complete=on_flow, interface=interface)
    sniffer.start()
    _state["sniffer"]        = sniffer
    _state["capture_active"] = True

    return {
        "message":   "Live capture started",
        "interface": interface or "default",
        "status":    "capturing",
    }


@router.post("/api/capture/stop")
async def stop_capture(user=Depends(get_current_user)):
    """Stop the live packet capture."""
    if not _state["capture_active"]:
        raise HTTPException(status_code=400, detail="No capture running")

    sniffer = _state.get("sniffer")
    if sniffer:
        sniffer.stop()

    _state["capture_active"] = False
    _state["sniffer"]        = None

    return {
        "message":          "Capture stopped",
        "packets_captured": _state["packet_count"],
        "anomalies_found":  _state["anomaly_count"],
    }


@router.get("/api/capture/status")
async def capture_status(user=Depends(get_current_user)):
    """Return current capture status and live counters."""
    sniffer = _state.get("sniffer")
    return {
        "active":           _state["capture_active"],
        "packets_captured": _state["packet_count"],
        "anomalies_found":  _state["anomaly_count"],
        "ws_clients":       len(_state["ws_clients"]),
        "sniffer_packets":  sniffer.packets_captured if sniffer else 0,
    }


@router.get("/api/capture/interfaces")
async def list_interfaces(user=Depends(get_current_user)):
    """List available network interfaces using psutil."""
    try:
        import psutil
        return {"interfaces": list(psutil.net_if_addrs().keys())}
    except ImportError:
        return {"interfaces": [], "error": "psutil not installed"}


@router.get("/api/capture/chartdata")
async def chart_data(user=Depends(get_current_user)):
    """
    Return the last 60 seconds of live chart data.
    Polled by the frontend every second as a fallback to WebSocket.
    """
    return {
        "normal":          _state["chart_normal"],
        "anomaly":         _state["chart_anomaly"],
        "total_packets":   _state["packet_count"],
        "total_anomalies": _state["anomaly_count"],
    }


@router.delete("/api/capture/flows")
async def clear_flows(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Clear all raw flows from the database."""
    db.query(RawFlowDB).delete()
    db.commit()
    return {"message": "Raw flows cleared from persistent database"}


# ═══════════════════════════════════════════════════════════════════════
#  WEBSOCKET — real-time push to frontend
# ═══════════════════════════════════════════════════════════════════════

@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket, token: Optional[str] = Query(None)):
    """
    WebSocket endpoint — frontend connects here to receive live updates.
    """
    if not token:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    from app.routers.auth import SECRET_KEY, ALGORITHM
    import jwt
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub"):
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except jwt.PyJWTError:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws.accept()
    _state["ws_clients"].append(ws)

    # Send current snapshot immediately on connect
    await ws.send_json({
        "type": "snapshot",
        "data": {
            "chart_normal":    _state["chart_normal"],
            "chart_anomaly":   _state["chart_anomaly"],
            "packet_count":    _state["packet_count"],
            "anomaly_count":   _state["anomaly_count"],
            "flows_completed": _state["flows_completed"],
            "capture_active":  _state["capture_active"],
            "recent_alerts":   _state["alerts"][-10:],
        },
    })

    try:
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                if msg == "ping":
                    await ws.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if ws in _state["ws_clients"]:
            _state["ws_clients"].remove(ws)


# ═══════════════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════

async def _broadcast_live_update(result: dict, meta: dict):
    """Broadcast a flow detection result to all connected WebSocket clients."""
    if not _state["ws_clients"]:
        return

    message = {
        "type": "flow",
        "data": {
            "anomalies_found":  result.get("anomalies_found", 0),
            "alerts":           result.get("alerts", []),
            "chart_normal":     _state["chart_normal"][-1],
            "chart_anomaly":    _state["chart_anomaly"][-1],
            "packet_count":     _state["packet_count"],
            "anomaly_count":    _state["anomaly_count"],
            "flows_completed":  _state["flows_completed"],
            "src_ip":           meta.get("src_ip", ""),
            "dst_ip":           meta.get("dst_ip", ""),
            "dst_port":         str(meta.get("dst_port", "")),
            "protocol":         meta.get("protocol", 0),
            "flow_bytes_s":     result.get("flow_bytes_s", 0),
        },
    }

    dead = []
    for client in list(_state["ws_clients"]):
        try:
            await client.send_json(message)
        except Exception:
            dead.append(client)

    for client in dead:
        if client in _state["ws_clients"]:
            _state["ws_clients"].remove(client)
