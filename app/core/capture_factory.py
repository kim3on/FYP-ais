"""Capture engine selection for the CICFlowMeter-based live extractor."""

from __future__ import annotations

CAPTURE_ENGINE_CICFLOWMETER = "cicflowmeter"
SUPPORTED_CAPTURE_ENGINES = {CAPTURE_ENGINE_CICFLOWMETER}


def selected_capture_engine() -> str:
    return CAPTURE_ENGINE_CICFLOWMETER


def get_packet_sniffer_class():
    from app.core.cicflow_bridge import CICFlowMeterSniffer

    return CICFlowMeterSniffer, selected_capture_engine()
