"""
Capture Router
===============
POST /api/capture/start        — start live packet capture
POST /api/capture/stop         — stop live packet capture
GET  /api/capture/status       — current capture counters
GET  /api/capture/interfaces   — list available network interfaces
GET  /api/capture/chartdata    — last-60-s ring buffer for the live chart
POST /api/capture/ingest-flow  — ingest one completed flow from a remote sensor
WS   /ws/live                  — WebSocket push for real-time dashboard updates
"""

import asyncio
import datetime
import tempfile
import logging
from pathlib import Path
from typing import Optional

import pandas as pd
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Depends, status, Query, UploadFile, File
from sqlalchemy.orm import Session

from app.core.pipeline import engine_ready
from app.core.datasets import DATASET_CICIDS2017
from app.core.endpoint_roles import infer_endpoint_roles
from app.core.capture_factory import get_packet_sniffer_class
from app.core.cicflow_bridge import CICFlowMeterAdapter
from app.state import _state, _build_engine
from app.core.database import get_db, SessionLocal
from app.models.db_models import RawFlowDB, AlertDB
from app.routers.auth import get_current_user, require_admin_user

router = APIRouter(tags=["capture"])
logger = logging.getLogger(__name__)

ENDPOINT_ROLE_FIELDS = (
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
)


def _attach_endpoint_roles(alert: dict) -> dict:
    roles = infer_endpoint_roles(
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("attack_type", ""),
    ).to_dict()
    alert.update(roles)
    return alert


def _alert_role_kwargs(alert: dict) -> dict:
    return {field: alert.get(field) for field in ENDPOINT_ROLE_FIELDS}


def _split_flow_payload(payload: dict) -> tuple[dict, dict]:
    """
    Accept either a raw CICIDS feature dict or:
      {"features": {...}, "metadata": {"src_ip": "...", ...}}
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Flow payload must be a JSON object")

    raw_features = payload.get("features") if isinstance(payload.get("features"), dict) else payload
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}

    features = dict(raw_features)
    meta = {}
    for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        if key in metadata:
            meta[key] = metadata[key]
            features.pop(f"_{key}", None)
            features.pop(key, None)
        elif f"_{key}" in features:
            meta[key] = features.pop(f"_{key}")
        else:
            meta[key] = features.pop(key, "")
    return features, meta


def _protocol_label(protocol) -> str:
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", "6": "TCP", "17": "UDP", "1": "ICMP"}
    return proto_map.get(protocol, str(protocol).upper() if protocol not in ("", None) else "TCP")


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value or default)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════
#  REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/api/capture/start")
async def start_capture(interface: Optional[str] = None, user=Depends(require_admin_user)):
    """
    Start live packet capture on the given interface.
    Requires root/admin privileges and scapy installed.
    """
    if _state["capture_active"]:
        raise HTTPException(status_code=409, detail="Capture already running")

    if _state.get("active_dataset_type") != DATASET_CICIDS2017:
        raise HTTPException(
            status_code=400,
            detail="Live capture is CICIDS2017-only. NSL-KDD models are batch benchmark models and cannot score live CICFlowMeter features.",
        )

    if not engine_ready(_state["active_model"], DATASET_CICIDS2017):
        raise HTTPException(
            status_code=400,
            detail=f"{_state['active_model']} is not ready. Train first, then start capture.",
        )

    try:
        PacketSniffer, capture_engine = get_packet_sniffer_class()
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail=(
                "CICFlowMeter capture dependency not installed. Install requirements."
            ),
        )

    engine = _build_engine(DATASET_CICIDS2017)
    loop   = asyncio.get_running_loop()

    def on_flow(features: dict):
        """Called by FlowAggregator each time a flow completes."""
        meta_keys = ['_src_ip', '_dst_ip', '_src_port', '_dst_port', '_protocol']
        meta = {k.lstrip('_'): features.pop(k, '?') for k in meta_keys}
        flow_features = dict(features)

        try:
            result = engine.detect_sample(flow_features)
        except Exception as exc:
            _state["sniffer_error"] = f"Detection failed for completed flow: {exc}"
            logger.exception("Detection failed for completed flow; dropping flow.")
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
            flow_bytes_s=float(flow_features.get("Flow Bytes/s", 0.0) or 0.0)
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
                _attach_endpoint_roles(alert)
                
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
                    **_alert_role_kwargs(alert),
                    raw_features=flow_features
                )
                db.add(db_alert)
            _state["alerts"].extend(result["alerts"])
        else:
            _state["chart_normal"].append(1)
            _state["chart_anomaly"].append(0)

        try:
            db.commit()
        except Exception as exc:
            db.rollback()
            _state["sniffer_error"] = f"Database write failed during live capture: {exc}"
            logger.exception("Database write failed during live capture.")
        finally:
            db.close()

        asyncio.run_coroutine_threadsafe(_broadcast_live_update(result, meta, flow_features), loop)

    _state["sniffer_error"] = None
    feature_columns = list(getattr(engine.preprocessor, "feature_columns_", None) or [])
    sniffer = PacketSniffer(
        on_flow_complete=on_flow,
        interface=interface,
        feature_columns=feature_columns,
    )
    try:
        sniffer.start()
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail=(
                "CICFlowMeter capture dependency is missing. Install requirements."
            ),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Live capture failed to start: {exc}")

    if getattr(sniffer, "error", None) and not sniffer.is_running:
        raise HTTPException(status_code=500, detail=sniffer.error)

    _state["sniffer"]        = sniffer
    _state["capture_active"] = True
    _state["remote_sensor_active"] = False

    return {
        "message":   "Live capture started",
        "interface": interface or "default",
        "capture_engine": capture_engine,
        "flow_mode": getattr(sniffer, "flow_mode", None) or "unknown",
        "status":    "capturing",
    }


@router.post("/api/capture/stop")
async def stop_capture(user=Depends(require_admin_user)):
    """Stop the live packet capture."""
    if not _state["capture_active"]:
        raise HTTPException(status_code=400, detail="No capture running")

    sniffer = _state.get("sniffer")
    packets_captured = sniffer.packets_captured if sniffer else _state["packet_count"]
    if sniffer:
        sniffer.stop(flush=False)

    _state["capture_active"] = False
    _state["remote_sensor_active"] = False
    _state["sniffer"]        = None

    return {
        "message":          "Capture stopped",
        "packets_captured": packets_captured,
        "anomalies_found":  _state["anomaly_count"],
    }


@router.get("/api/capture/status")
async def capture_status(user=Depends(get_current_user)):
    """Return current capture status and live counters."""
    sniffer = _state.get("sniffer")
    sniffer_error = getattr(sniffer, "error", None) if sniffer else _state.get("sniffer_error")
    if sniffer_error:
        _state["sniffer_error"] = sniffer_error

    active = bool(_state["capture_active"])
    if sniffer and active and not sniffer.is_running:
        active = False
        _state["capture_active"] = False

    sniffer_packets = sniffer.packets_captured if sniffer else 0
    return {
        "active":           active,
        "packets_captured": sniffer_packets if sniffer else _state["packet_count"],
        "anomalies_found":  _state["anomaly_count"],
        "flows_completed":  _state["flows_completed"],
        "ws_clients":       len(_state["ws_clients"]),
        "sniffer_packets":  sniffer_packets,
        "sniffer_error":    _state.get("sniffer_error"),
        "interface":        getattr(sniffer, "resolved_interface", None) or ("remote_sensor" if _state.get("remote_sensor_active") else "default"),
        "capture_engine":   getattr(sniffer, "capture_engine", None) or ("remote_sensor" if _state.get("remote_sensor_active") else "none"),
        "flow_mode":        getattr(sniffer, "flow_mode", None) or "none",
        "remote_sensor_active": bool(_state.get("remote_sensor_active")),
        "remote_sensor_last_seen": _state.get("remote_sensor_last_seen"),
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


@router.post("/api/capture/ingest-flow")
async def ingest_remote_flow(payload: dict, user=Depends(require_admin_user)):
    """
    Ingest one completed CICIDS-compatible flow from a remote sensor.

    Packet capture runs on the laptop/lab machine where the traffic exists;
    the Droplet handles inference, persistence, and dashboard streaming.
    """
    if _state.get("active_dataset_type") != DATASET_CICIDS2017:
        raise HTTPException(
            status_code=400,
            detail="Remote sensor ingest is CICIDS2017-only. Train or select a CICIDS2017 model first.",
        )
    if not engine_ready(_state["active_model"], DATASET_CICIDS2017):
        raise HTTPException(status_code=400, detail=f"{_state['active_model']} is not ready. Train first, then ingest sensor flows.")

    flow_features, meta = _split_flow_payload(payload)
    engine = _build_engine(DATASET_CICIDS2017)

    try:
        result = engine.detect_sample(flow_features)
    except Exception as exc:
        logger.exception("Remote sensor flow detection failed.")
        raise HTTPException(status_code=400, detail=f"Remote sensor flow detection failed: {exc}") from exc

    _state["capture_active"] = True
    _state["remote_sensor_active"] = True
    _state["remote_sensor_last_seen"] = datetime.datetime.utcnow().isoformat()
    _state["packet_count"] += 1
    _state["flows_completed"] += 1
    _state["chart_normal"].pop(0)
    _state["chart_anomaly"].pop(0)

    proto_str = _protocol_label(meta.get("protocol", flow_features.get("Protocol", "TCP")))
    timestamp = datetime.datetime.utcnow().isoformat()

    db = SessionLocal()
    try:
        db.add(RawFlowDB(
            timestamp=timestamp,
            src_ip=str(meta.get("src_ip", "")),
            dst_ip=str(meta.get("dst_ip", "")),
            dst_port=_safe_int(meta.get("dst_port")),
            protocol=proto_str,
            flow_bytes_s=float(flow_features.get("Flow Bytes/s", 0.0) or 0.0),
        ))

        if result["anomalies_found"] > 0:
            _state["anomaly_count"] += 1
            _state["chart_normal"].append(0)
            _state["chart_anomaly"].append(1)

            for alert in result["alerts"]:
                alert["src_ip"] = str(meta.get("src_ip") or alert.get("src_ip", ""))
                alert["dst_ip"] = str(meta.get("dst_ip") or alert.get("dst_ip", ""))
                alert["dst_port"] = str(meta.get("dst_port") or alert.get("dst_port", ""))
                alert["protocol"] = proto_str
                _attach_endpoint_roles(alert)

                db.add(AlertDB(
                    alert_id=alert["alert_id"],
                    timestamp=alert["timestamp"],
                    attack_type=alert["attack_type"],
                    src_ip=alert["src_ip"],
                    dst_ip=alert["dst_ip"],
                    dst_port=_safe_int(alert.get("dst_port")),
                    protocol=alert["protocol"],
                    severity=alert["severity"],
                    confidence=alert["confidence"],
                    confidence_pct=alert["confidence_pct"],
                    is_false_positive=False,
                    is_zero_day=alert["is_zero_day"],
                    **_alert_role_kwargs(alert),
                    raw_features=flow_features,
                ))
            _state["alerts"].extend(result["alerts"])
        else:
            _state["chart_normal"].append(1)
            _state["chart_anomaly"].append(0)

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Remote sensor ingest persistence failed.")
        raise HTTPException(status_code=500, detail=f"Remote sensor ingest persistence failed: {exc}") from exc
    finally:
        db.close()

    await _broadcast_live_update(result, meta, flow_features)
    return {
        "message": "Remote sensor flow ingested",
        "anomalies_found": result.get("anomalies_found", 0),
        "flows_completed": _state["flows_completed"],
        "packet_count": _state["packet_count"],
    }


@router.delete("/api/capture/flows")
async def clear_flows(db: Session = Depends(get_db), user=Depends(require_admin_user)):
    """Clear all raw flows from the database."""
    db.query(RawFlowDB).delete()
    db.commit()
    return {"message": "Raw flows cleared from persistent database"}


@router.post("/api/capture/submit-flow")
async def submit_flow_file(
    file: UploadFile = File(...),
    limit: Optional[int] = 1000,
    user=Depends(get_current_user),
):
    """
    Submit an offline flow file for immediate scoring.

    CSV/Parquet files are treated as pre-extracted CICIDS-compatible flow rows.
    PCAP/PCAPNG files are converted through CICFlowMeter before scoring.
    """
    if _state.get("active_dataset_type") != DATASET_CICIDS2017:
        raise HTTPException(
            status_code=400,
            detail="Manual flow submission is CICIDS2017-only. Select or train a CICIDS2017 model first.",
        )
    if not engine_ready(_state["active_model"], DATASET_CICIDS2017):
        raise HTTPException(status_code=400, detail=f"{_state['active_model']} is not ready. Train first, then submit a flow file.")

    filename = file.filename or "submitted-flow"
    suffix = Path(filename).suffix.lower()
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    engine = _build_engine(DATASET_CICIDS2017)
    source_bytes = payload
    detection_filename = filename
    converted = False
    converted_flow_count = None
    flow_preview = []

    if suffix in {".pcap", ".pcapng"}:
        source_bytes, converted_flow_count, flow_preview = _pcap_to_cicids_csv(
            payload,
            suffix=suffix,
            feature_columns=list(getattr(engine.preprocessor, "feature_columns_", None) or []),
        )
        detection_filename = f"{Path(filename).stem}_flows.csv"
        converted = True
    elif suffix not in {".csv", ".parquet", ".pq"}:
        raise HTTPException(
            status_code=400,
            detail="Submit a .csv, .parquet, .pq, .pcap, or .pcapng file",
        )

    try:
        result = engine.detect_from_csv(
            source_bytes,
            limit=int(limit or 0) or None,
            filename=detection_filename,
        )
    except Exception as exc:
        logger.exception("Manual flow submission failed.")
        raise HTTPException(status_code=400, detail=f"Flow submission failed: {exc}") from exc

    _state["alerts"].extend(result.get("alerts", []))
    _state["packet_count"] += int(result.get("total_checked", 0) or 0)
    _state["anomaly_count"] += int(result.get("anomalies_found", 0) or 0)
    _state["last_detect_result"] = result

    _persist_manual_submission(result, flow_preview)

    return {
        "message": "Flow submission analysed",
        "filename": filename,
        "converted": converted,
        "converted_flow_count": converted_flow_count,
        "flow_preview": flow_preview[:25],
        "result": result,
    }


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

    from app.routers.auth import get_user_from_token
    try:
        db = SessionLocal()
        try:
            get_user_from_token(token, db)
        finally:
            db.close()
    except HTTPException:
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
            "packet_count":    _live_packet_count(),
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
        logger.debug("Live WebSocket loop ended unexpectedly.", exc_info=True)
    finally:
        if ws in _state["ws_clients"]:
            _state["ws_clients"].remove(ws)


# ═══════════════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _json_safe(value):
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return str(value)
    return value


def _live_packet_count() -> int:
    sniffer = _state.get("sniffer")
    if sniffer is not None:
        try:
            return int(getattr(sniffer, "packets_captured", 0) or 0)
        except Exception:
            return 0
    return int(_state.get("packet_count", 0) or 0)


def _pcap_to_cicids_csv(payload: bytes, suffix: str, feature_columns: list[str]) -> tuple[bytes, int, list[dict]]:
    """Convert a PCAP/PCAPNG payload to normalized CICIDS-compatible CSV bytes."""
    try:
        from cicflowmeter.flow_session import FlowSession
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import PcapReader
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="CICFlowMeter/Scapy is not installed; PCAP conversion is unavailable.",
        ) from exc

    with tempfile.TemporaryDirectory(prefix="ais_pcap_", ignore_cleanup_errors=True) as tmp_dir:
        tmp_path = Path(tmp_dir)
        input_path = tmp_path / f"submitted{suffix}"
        output_path = tmp_path / "flows.csv"
        input_path.write_bytes(payload)

        try:
            session = FlowSession(output_mode="csv", output=str(output_path), fields=None, verbose=False)
            with PcapReader(str(input_path)) as reader:
                for packet in reader:
                    if IP in packet and (TCP in packet or UDP in packet):
                        session.process(packet)
            session.flush_flows()
        except Exception as exc:
            logger.exception("PCAP to flow conversion failed.")
            raise HTTPException(status_code=400, detail=f"PCAP conversion failed: {exc}") from exc

        if not output_path.exists() or output_path.stat().st_size == 0:
            raise HTTPException(status_code=400, detail="PCAP conversion produced no completed TCP/UDP flows")

        raw_df = pd.read_csv(output_path)
        if raw_df.empty:
            raise HTTPException(status_code=400, detail="PCAP conversion produced no completed TCP/UDP flows")

        adapter = CICFlowMeterAdapter(lambda _features: None, feature_columns=feature_columns)
        rows = []
        for raw in raw_df.to_dict(orient="records"):
            if adapter._packet_count(raw) < 2:
                continue
            row = adapter.normalize(raw)
            row["Source IP"] = row.get("_src_ip", "")
            row["Destination IP"] = row.get("_dst_ip", "")
            row["Source Port"] = row.get("_src_port", "")
            row["Destination Port"] = row.get("_dst_port", row.get("Destination Port", ""))
            row["Protocol"] = row.get("_protocol", row.get("Protocol", ""))
            row["Timestamp"] = datetime.datetime.utcnow().isoformat()
            rows.append(row)

        if not rows:
            raise HTTPException(status_code=400, detail="PCAP conversion produced no multi-packet flows")

        normalized_df = pd.DataFrame(rows)
        csv_bytes = normalized_df.to_csv(index=False).encode("utf-8")
        preview = [_flow_preview_from_row(row) for row in rows[:25]]
        return csv_bytes, len(rows), preview


def _flow_preview_from_row(row: dict) -> dict:
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", "6": "TCP", "17": "UDP", "1": "ICMP"}
    protocol = row.get("Protocol", row.get("_protocol", ""))
    return {
        "timestamp": row.get("Timestamp") or datetime.datetime.utcnow().isoformat(),
        "src_ip": str(row.get("Source IP") or row.get("_src_ip") or ""),
        "dst_ip": str(row.get("Destination IP") or row.get("_dst_ip") or ""),
        "dst_port": str(row.get("Destination Port") or row.get("_dst_port") or ""),
        "protocol": proto_map.get(protocol, str(protocol).upper() if protocol != "" else ""),
        "flow_bytes_s": row.get("Flow Bytes/s", 0),
        "flow_features": {k: _json_safe(v) for k, v in row.items()},
    }


def _persist_manual_submission(result: dict, flow_preview: list[dict]) -> None:
    db = SessionLocal()
    try:
        for flow in flow_preview:
            try:
                dst_port = int(flow.get("dst_port", 0) or 0)
            except (TypeError, ValueError):
                dst_port = 0
            db.add(RawFlowDB(
                timestamp=flow.get("timestamp") or datetime.datetime.utcnow().isoformat(),
                src_ip=str(flow.get("src_ip", "")),
                dst_ip=str(flow.get("dst_ip", "")),
                dst_port=dst_port,
                protocol=str(flow.get("protocol", "")),
                flow_bytes_s=float(flow.get("flow_bytes_s", 0.0) or 0.0),
            ))

        for alert in result.get("alerts", []):
            _attach_endpoint_roles(alert)
            try:
                dst_port = int(alert.get("dst_port", 0) or 0)
            except (TypeError, ValueError):
                dst_port = 0
            db.add(AlertDB(
                alert_id=alert["alert_id"],
                timestamp=alert["timestamp"],
                attack_type=alert["attack_type"],
                src_ip=alert.get("src_ip", "N/A"),
                dst_ip=alert.get("dst_ip", "N/A"),
                dst_port=dst_port,
                protocol=alert.get("protocol", "N/A"),
                severity=alert["severity"],
                confidence=alert["confidence"],
                confidence_pct=alert["confidence_pct"],
                is_false_positive=False,
                is_zero_day=alert["is_zero_day"],
                **_alert_role_kwargs(alert),
                raw_features=alert.get("raw_features", {}),
            ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Manual flow submission persistence failed.")
    finally:
        db.close()


async def _broadcast_live_update(result: dict, meta: dict, features: dict):
    """Broadcast a flow detection result to all connected WebSocket clients."""
    if not _state["ws_clients"]:
        return

    flow_bytes_s = features.get("Flow Bytes/s", result.get("flow_bytes_s", 0))
    message = {
        "type": "flow",
        "data": {
            "anomalies_found":  result.get("anomalies_found", 0),
            "alerts":           result.get("alerts", []),
            "chart_normal":     _state["chart_normal"][-1],
            "chart_anomaly":    _state["chart_anomaly"][-1],
            "packet_count":     _live_packet_count(),
            "anomaly_count":    _state["anomaly_count"],
            "flows_completed":  _state["flows_completed"],
            "src_ip":           meta.get("src_ip", ""),
            "dst_ip":           meta.get("dst_ip", ""),
            "dst_port":         str(meta.get("dst_port", "")),
            "protocol":         meta.get("protocol", 0),
            "flow_bytes_s":     flow_bytes_s,
            "flow_features":    _json_safe(features),
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
