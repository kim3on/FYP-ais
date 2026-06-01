"""Direction-only endpoint attribution for anomalous network flows.

This module does not change detection decisions. It only labels whether a flow
is inbound or outbound relative to the configured local CIDR ranges.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import os
from typing import Iterable


DEFAULT_LOCAL_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
)

EMPTY_IP_MARKERS = {"", "?", "n/a", "na", "none", "null", "unknown", "-"}


@dataclass(frozen=True)
class EndpointRoleResult:
    traffic_direction: str
    flow_initiator_ip: str
    flow_responder_ip: str
    local_ip: str
    remote_ip: str
    suspected_attacker_ip: str
    suspected_victim_ip: str
    suspected_compromised_host: str
    containment_target_ip: str
    endpoint_role_confidence: str
    endpoint_role_reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def infer_endpoint_roles(
    src_ip: object,
    dst_ip: object,
    attack_type: str = "",
    local_cidrs: Iterable[str] | None = None,
) -> EndpointRoleResult:
    """Infer simple traffic direction from source/destination IP metadata."""
    src_text = _clean_ip_text(src_ip)
    dst_text = _clean_ip_text(dst_ip)
    src_addr = _parse_ip(src_text)
    dst_addr = _parse_ip(dst_text)

    if src_addr is None or dst_addr is None:
        return _result(
            direction="unknown",
            src_ip=src_text,
            dst_ip=dst_text,
            reason="Missing or invalid source/destination IP metadata.",
        )

    networks = _load_local_networks(local_cidrs)
    src_local = _is_local(src_addr, networks)
    dst_local = _is_local(dst_addr, networks)

    if src_local and not dst_local:
        return _result(
            direction="outbound",
            src_ip=src_text,
            dst_ip=dst_text,
            local_ip=src_text,
            remote_ip=dst_text,
            reason="Source IP is local and destination IP is outside the configured local CIDRs.",
        )
    if not src_local and dst_local:
        return _result(
            direction="inbound",
            src_ip=src_text,
            dst_ip=dst_text,
            local_ip=dst_text,
            remote_ip=src_text,
            reason="Source IP is outside the configured local CIDRs and destination IP is local.",
        )

    return _result(
        direction="unknown",
        src_ip=src_text,
        dst_ip=dst_text,
        reason=(
            "Flow is local-to-local or external-to-external, so it is not labelled "
            "as inbound or outbound."
        ),
    )


def _result(
    *,
    direction: str,
    src_ip: str,
    dst_ip: str,
    local_ip: str = "",
    remote_ip: str = "",
    suspected_attacker_ip: str = "",
    suspected_victim_ip: str = "",
    suspected_compromised_host: str = "",
    containment_target_ip: str = "",
    confidence: str = "",
    reason: str,
) -> EndpointRoleResult:
    return EndpointRoleResult(
        traffic_direction=direction,
        flow_initiator_ip=src_ip,
        flow_responder_ip=dst_ip,
        local_ip=local_ip,
        remote_ip=remote_ip,
        suspected_attacker_ip=suspected_attacker_ip,
        suspected_victim_ip=suspected_victim_ip,
        suspected_compromised_host=suspected_compromised_host,
        containment_target_ip=containment_target_ip,
        endpoint_role_confidence=confidence,
        endpoint_role_reason=reason,
    )


def _clean_ip_text(value: object) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text.lower() in EMPTY_IP_MARKERS else text


def _parse_ip(value: str):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _load_local_networks(local_cidrs: Iterable[str] | None = None):
    if local_cidrs is None:
        raw = os.getenv("AIS_LOCAL_CIDRS", "")
        cidrs = [item.strip() for item in raw.split(",") if item.strip()] or list(DEFAULT_LOCAL_CIDRS)
    else:
        cidrs = [str(item).strip() for item in local_cidrs if str(item).strip()]

    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _is_local(addr, networks) -> bool:
    return any(addr in network for network in networks)
