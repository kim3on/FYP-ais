"""
CICFlowMeter-compatible live capture bridge.

This module adapts hieulw/cicflowmeter output to the CICIDS2017 column names
used by the fitted preprocessor.  It preserves the same callback contract as
the legacy PacketSniffer: on_flow_complete(dict).
"""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from decimal import Decimal
from typing import Callable, Optional, Any

logger = logging.getLogger(__name__)
_FLOW_SESSION_FACTORY_LOCK = threading.Lock()

CAPTURE_FILTER = "ip and (tcp or udp)"
MIN_FLOW_PACKETS = 2
GC_INTERVAL = 1.0
LIVE_FLOW_IDLE_TIMEOUT = Decimal("3.0")
LIVE_FLOW_MAX_ACTIVE_AGE = Decimal("30.0")
TCP_TERMINAL_FLAGS = 0x05  # FIN or RST
CAPTURE_FLOW_MODE_CIC_COMPATIBLE = "cic_compatible"
CAPTURE_FLOW_MODE_LIVE_DASHBOARD = "live_dashboard"
SUPPORTED_CAPTURE_FLOW_MODES = {
    CAPTURE_FLOW_MODE_CIC_COMPATIBLE,
    CAPTURE_FLOW_MODE_LIVE_DASHBOARD,
}

TIME_FIELDS_SECONDS_TO_MICROSECONDS = {
    "flow_duration",
    "flow_iat_mean",
    "flow_iat_max",
    "flow_iat_min",
    "flow_iat_std",
    "fwd_iat_tot",
    "fwd_iat_max",
    "fwd_iat_min",
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_tot",
    "bwd_iat_max",
    "bwd_iat_min",
    "bwd_iat_mean",
    "bwd_iat_std",
    "active_max",
    "active_min",
    "active_mean",
    "active_std",
    "idle_max",
    "idle_min",
    "idle_mean",
    "idle_std",
}

CICFLOW_TO_CICIDS = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

CICIDS_COLUMN_ALIASES = {
    "Total Length of Fwd Packets": ("Fwd Packets Length Total",),
    "Total Length of Bwd Packets": ("Bwd Packets Length Total",),
    "Min Packet Length": ("Packet Length Min",),
    "Max Packet Length": ("Packet Length Max",),
    "Average Packet Size": ("Avg Packet Size",),
    "Init_Win_bytes_forward": ("Init Fwd Win Bytes",),
    "Init_Win_bytes_backward": ("Init Bwd Win Bytes",),
    "act_data_pkt_fwd": ("Fwd Act Data Packets",),
    "min_seg_size_forward": ("Fwd Seg Size Min",),
}

METADATA_MAP = {
    "src_ip": "_src_ip",
    "dst_ip": "_dst_ip",
    "src_port": "_src_port",
    "dst_port": "_dst_port",
    "protocol": "_protocol",
}


def selected_capture_flow_mode(value: Optional[str] = None) -> str:
    mode = (value or os.getenv("AIS_CAPTURE_FLOW_MODE") or CAPTURE_FLOW_MODE_CIC_COMPATIBLE).strip().lower()
    if mode not in SUPPORTED_CAPTURE_FLOW_MODES:
        logger.warning(
            "Unsupported AIS_CAPTURE_FLOW_MODE=%r; using %s.",
            mode,
            CAPTURE_FLOW_MODE_CIC_COMPATIBLE,
        )
        return CAPTURE_FLOW_MODE_CIC_COMPATIBLE
    return mode


def _to_float(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        if isinstance(value, Decimal):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class CICFlowMeterAdapter:
    """Map cicflowmeter rows into the app's CICIDS2017 feature contract."""

    def __init__(self, on_flow_complete: Callable[[dict], None], feature_columns: Optional[list[str]] = None):
        self._on_flow_complete = on_flow_complete
        self.feature_columns = list(feature_columns or [])
        self.flows_completed = 0
        self.flows_dropped = 0
        self._warned_missing: set[str] = set()

    def handle_flow(self, data: dict) -> None:
        if self._packet_count(data) < MIN_FLOW_PACKETS:
            self.flows_dropped += 1
            return

        features = self.normalize(data)
        self._on_flow_complete(features)
        self.flows_completed += 1

    def normalize(self, data: dict) -> dict:
        out: dict[str, Any] = {}

        for source, target in CICFLOW_TO_CICIDS.items():
            value = _to_float(data.get(source))
            if source in TIME_FIELDS_SECONDS_TO_MICROSECONDS:
                value *= 1_000_000.0
            out[target] = value

        # The library aliases cwr_flag_count to fwd_urg_flags.  Until raw CWR
        # counting is verified, prefer the legacy-safe value over wrong data.
        out["CWE Flag Count"] = 0.0
        # Some trained CICIDS artifacts include pandas' duplicate-column suffix
        # from the original CSV header.  Keep it aligned with the primary field.
        out["Fwd Header Length.1"] = out.get("Fwd Header Length", 0.0)
        out["Protocol"] = _to_float(data.get("protocol"))

        for source_column, aliases in CICIDS_COLUMN_ALIASES.items():
            source_value = out.get(source_column, 0.0)
            for alias in aliases:
                out[alias] = source_value

        for source, target in METADATA_MAP.items():
            out[target] = data.get(source, 0)

        for column in self.feature_columns:
            if column not in out:
                out[column] = 0.0
                if column not in self._warned_missing:
                    logger.warning("CICFlowMeter adapter filled missing feature '%s' with 0.0", column)
                    self._warned_missing.add(column)

        return out

    @staticmethod
    def _packet_count(data: dict) -> int:
        return int(_to_float(data.get("tot_fwd_pkts")) + _to_float(data.get("tot_bwd_pkts")))


import queue as _queue


class _CallbackWriter:
    """
    Non-blocking writer injected into FlowSession.

    The library's FlowSession holds self._lock while calling write().
    Any blocking work (DB writes, WebSocket I/O) inside write() would
    stall the GC loop and cause flows to queue up silently until
    flush_flows() is called on stop().  This writer enqueues flow dicts
    instantly and returns; a separate dispatcher thread owned by
    CICFlowMeterSniffer drains the queue and calls the real callback
    outside the library lock.
    """

    def __init__(self, flow_queue: _queue.Queue):
        self._queue = flow_queue

    def write(self, data: dict) -> None:
        # Must return quickly -- we are inside FlowSession._lock.
        try:
            self._queue.put_nowait(data)
        except _queue.Full:
            logger.warning("CICFlowMeter dispatch queue full -- dropping flow.")


class CICFlowMeterSniffer:
    """CICFlowMeter-backed sniffer with the legacy PacketSniffer public surface."""

    def __init__(
        self,
        on_flow_complete: Callable[[dict], None],
        interface: Optional[str] = None,
        bpf_filter: str = CAPTURE_FILTER,
        feature_columns: Optional[list[str]] = None,
        flow_mode: Optional[str] = None,
    ):
        self._interface = interface
        self._filter = bpf_filter
        self.flow_mode = selected_capture_flow_mode(flow_mode)
        self._adapter = CICFlowMeterAdapter(on_flow_complete, feature_columns=feature_columns)
        self._sniffer = None
        self._session = None
        self._running = False
        self._gc_stop: Optional[threading.Event] = None
        self._gc_thread: Optional[threading.Thread] = None

        # Queue-based dispatch: _CallbackWriter enqueues flow dicts here;
        # _dispatch_loop drains it outside the library lock.
        self._flow_queue: _queue.Queue = _queue.Queue(maxsize=2000)
        self._dispatch_stop = threading.Event()
        self._dispatch_thread: Optional[threading.Thread] = None
        self._drain_on_stop = False

        self.packets_captured = 0
        self.flows_completed = 0
        self.error: Optional[str] = None
        self.resolved_interface: Optional[str] = None
        self.capture_engine = "cicflowmeter"

    def start(self):
        if self._running:
            return
        try:
            from scapy.sendrecv import AsyncSniffer

            session = self._build_session()
            iface = self._resolve_interface()
            self._session = session
            self._sniffer = AsyncSniffer(
                iface=iface,
                filter=self._filter,
                prn=session.process,
                store=False,
            )
            self._running = True
            self.error = None
            self._dispatch_stop.clear()
            self._start_dispatch_thread()
            self._start_periodic_gc()
            self._sniffer.start()
            logger.info(
                "CICFlowMeterSniffer started on interface=%s flow_mode=%s",
                self.resolved_interface or "default",
                self.flow_mode,
            )
        except ImportError as exc:
            self.error = (
                "cicflowmeter/scapy dependency missing. "
                "Install requirements."
            )
            self._running = False
            logger.exception("Failed to import CICFlowMeter live capture dependency.")
            raise exc
        except PermissionError:
            self.error = "Packet capture requires Administrator/root privileges."
            self._running = False
            logger.exception("CICFlowMeter live capture permission error.")
        except Exception as exc:
            self.error = str(exc)
            self._running = False
            logger.exception("CICFlowMeterSniffer failed to start.")

    def stop(self, flush: bool = False):
        if not self._running:
            return
        self._running = False
        self._stop_periodic_gc()
        try:
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer.join(timeout=2.0)
        except Exception:
            logger.debug("CICFlowMeter AsyncSniffer stop ended with non-fatal error.", exc_info=True)
        if flush and self._session is not None:
            try:
                # flush_flows() enqueues remaining flows via _CallbackWriter.
                # The dispatch thread will drain them before we stop it.
                self._session.flush_flows()
            except Exception as exc:
                self.error = f"Failed to flush CICFlowMeter flows: {exc}"
                logger.exception("Failed to flush CICFlowMeter flows.")
        # Stop dispatch thread after optional flushing. A normal UI stop drops
        # queued backlog instead of replaying it as a sudden alert burst.
        self._stop_dispatch_thread(drain=flush)
        self._sync_counters()
        logger.info(
            "CICFlowMeterSniffer stopped. Packets=%s, Flows=%s",
            self.packets_captured,
            self.flows_completed,
        )

    @property
    def is_running(self) -> bool:
        if self._sniffer is not None and not self._sniffer.running:
            self._running = False
        self._sync_counters()
        return self._running

    def _start_dispatch_thread(self):
        """Start a thread that drains self._flow_queue and fires the callback."""
        def _dispatch_loop():
            while not self._dispatch_stop.is_set():
                try:
                    # Block for up to 0.2 s so the thread exits promptly on stop.
                    data = self._flow_queue.get(timeout=0.2)
                    self._adapter.handle_flow(data)
                except _queue.Empty:
                    continue
                except Exception:
                    logger.exception("CICFlowMeter dispatch error.")
            if self._drain_on_stop:
                # Explicit flush mode drains completed flows before shutdown.
                while not self._flow_queue.empty():
                    try:
                        data = self._flow_queue.get_nowait()
                        self._adapter.handle_flow(data)
                    except _queue.Empty:
                        break
                    except Exception:
                        logger.exception("CICFlowMeter dispatch drain error.")
            else:
                dropped = self._discard_dispatch_queue()
                if dropped:
                    logger.info("Dropped %s queued live flow(s) on capture stop.", dropped)

        self._dispatch_thread = threading.Thread(
            target=_dispatch_loop, daemon=True, name="cicflow-dispatch"
        )
        self._dispatch_thread.start()

    def _stop_dispatch_thread(self, drain: bool = False):
        self._drain_on_stop = bool(drain)
        self._dispatch_stop.set()
        if self._dispatch_thread is not None:
            self._dispatch_thread.join(timeout=5.0)
        self._dispatch_thread = None
        self._drain_on_stop = False

    def _discard_dispatch_queue(self) -> int:
        dropped = 0
        while True:
            try:
                self._flow_queue.get_nowait()
                dropped += 1
            except _queue.Empty:
                break
        if dropped:
            self._adapter.flows_dropped += dropped
        return dropped

    def _build_session(self):
        from cicflowmeter import flow_session as flow_session_module

        flow_queue = self._flow_queue
        original_factory = flow_session_module.output_writer_factory
        with _FLOW_SESSION_FACTORY_LOCK:
            try:
                flow_session_module.output_writer_factory = lambda *_args, **_kwargs: _CallbackWriter(flow_queue)
                return flow_session_module.FlowSession(
                    output_mode="callback",
                    output=None,
                    fields=None,
                    verbose=False,
                )
            finally:
                flow_session_module.output_writer_factory = original_factory

    def _resolve_interface(self) -> Any:
        if not self._interface:
            self.resolved_interface = None
            return None

        if platform.system().lower() != "windows":
            self.resolved_interface = self._interface
            return self._interface

        target = str(self._interface).strip()
        target_cf = target.casefold()

        try:
            from scapy.all import conf

            interfaces = list(conf.ifaces.values())
            for iface in interfaces:
                candidates = [
                    getattr(iface, "name", ""),
                    getattr(iface, "description", ""),
                    getattr(iface, "network_name", ""),
                    getattr(iface, "guid", ""),
                    str(iface),
                ]
                if any(str(value).casefold() == target_cf for value in candidates if value):
                    self.resolved_interface = getattr(iface, "name", target)
                    return iface

            for iface in interfaces:
                candidates = [
                    getattr(iface, "name", ""),
                    getattr(iface, "description", ""),
                    getattr(iface, "network_name", ""),
                    str(iface),
                ]
                if any(target_cf in str(value).casefold() for value in candidates if value):
                    self.resolved_interface = getattr(iface, "name", target)
                    return iface
        except Exception as exc:
            logger.warning("Could not resolve Windows capture interface '%s': %s", target, exc)

        self.resolved_interface = target
        return target

    def _start_periodic_gc(self):
        if self._session is None:
            return
        self._gc_stop = threading.Event()

        def _gc_loop():
            while self._gc_stop is not None and not self._gc_stop.wait(GC_INTERVAL):
                try:
                    if self.flow_mode == CAPTURE_FLOW_MODE_LIVE_DASHBOARD:
                        self._collect_live_ready_flows()
                    else:
                        self._collect_cic_compatible_flows()
                    self._sync_counters()
                except Exception:
                    logger.exception("CICFlowMeter periodic GC failed.")

        self._gc_thread = threading.Thread(target=_gc_loop, daemon=True, name="cicflow-gc")
        self._gc_thread.start()

    def _collect_cic_compatible_flows(self) -> int:
        """
        Emit only CICFlowMeter-compatible completed flows.

        This mode avoids the 3s/30s dashboard expiry that can split normal
        traffic into short micro-flows and create out-of-distribution rate/IAT
        features.  Library GC handles long/idle flows; we additionally emit
        TCP FIN/RST flows because those are genuinely closed.
        """
        collected = self._collect_ready_flows(terminal_only=True)
        if self._session is not None:
            now = Decimal(str(time.time()))
            self._session.garbage_collect(now)
        return collected

    def _collect_live_ready_flows(self) -> int:
        """
        Emit flows during capture on live-friendly timeouts.

        cicflowmeter's built-in garbage_collect waits for a 240 s idle timeout
        or a 90 s active duration. That is correct for offline files but makes
        the dashboard look empty until stop_capture flushes everything. This
        collector keeps the same FlowSession internals but applies shorter live
        expiry rules.
        """
        if self._session is None:
            return 0
        return self._collect_ready_flows(terminal_only=False)

    def _collect_ready_flows(self, terminal_only: bool) -> int:
        if self._session is None:
            return 0

        flows = getattr(self._session, "flows", None)
        lock = getattr(self._session, "_lock", None)
        output_writer = getattr(self._session, "output_writer", None)
        if flows is None or lock is None or output_writer is None:
            now = Decimal(str(time.time()))
            self._session.garbage_collect(now)
            return 0

        now = Decimal(str(time.time()))
        with lock:
            items = list(flows.items())

        collected = 0
        for key, flow in items:
            if flow is None or not self._is_flow_ready(flow, now, terminal_only=terminal_only):
                continue

            with lock:
                if flows.get(key) is not flow:
                    continue
                del flows[key]

            try:
                data = flow.get_data(getattr(self._session, "fields", None))
                output_writer.write(data)
                collected += 1
            except Exception:
                logger.exception("Failed to emit completed live flow.")

        if collected:
            logger.debug("CICFlowMeter GC emitted %s flow(s).", collected)
        return collected

    def _is_flow_ready(self, flow: Any, now: Decimal, terminal_only: bool) -> bool:
        if self._flow_has_terminal_tcp_flag(flow):
            return True

        if terminal_only:
            return False

        idle_age = self._elapsed_since(now, getattr(flow, "latest_timestamp", now))
        if idle_age >= LIVE_FLOW_IDLE_TIMEOUT:
            return True

        active_age = self._elapsed_since(now, getattr(flow, "start_timestamp", now))
        if active_age >= LIVE_FLOW_MAX_ACTIVE_AGE:
            return True

        return False

    @staticmethod
    def _elapsed_since(now: Decimal, timestamp: Any) -> Decimal:
        try:
            elapsed = now - Decimal(str(timestamp))
        except Exception:
            return Decimal("0")
        return max(elapsed, Decimal("0"))

    @staticmethod
    def _flow_has_terminal_tcp_flag(flow: Any) -> bool:
        for packet, _direction in list(getattr(flow, "packets", []))[-4:]:
            try:
                if "TCP" not in packet:
                    continue
                if int(packet["TCP"].flags) & TCP_TERMINAL_FLAGS:
                    return True
            except Exception:
                continue
        return False

    def _stop_periodic_gc(self):
        if self._gc_stop is not None:
            self._gc_stop.set()
        if self._gc_thread is not None:
            self._gc_thread.join(timeout=2.0)
        self._gc_stop = None
        self._gc_thread = None

    def _sync_counters(self):
        if self._session is not None:
            self.packets_captured = int(getattr(self._session, "packets_count", 0) or 0)
        self.flows_completed = int(self._adapter.flows_completed)
