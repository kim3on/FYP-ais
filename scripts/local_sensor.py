"""
AIS-Detect local sensor agent.

Run this on the laptop/lab machine that can see the traffic. It captures
packets locally, converts them to CICIDS-compatible flow features, then sends
completed flows to the deployed AIS-Detect backend.
"""

from __future__ import annotations

import argparse
import getpass
import json
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from urllib import error, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.cicflow_bridge import CICFlowMeterSniffer, CAPTURE_FLOW_MODE_LIVE_DASHBOARD


def _json_post(url: str, payload: dict, token: str | None = None, timeout: float = 15.0) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8")
    return json.loads(data) if data else {}


def _json_get(url: str, token: str | None = None, timeout: float = 15.0) -> dict:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8")
    return json.loads(data) if data else {}


def _login(api_base: str, username: str, password: str) -> str:
    result = _json_post(
        f"{api_base}/api/auth/login",
        {"username": username, "password": password},
        timeout=15.0,
    )
    token = result.get("token")
    if not token:
        raise RuntimeError("Login succeeded but no token was returned")
    return token


def _list_interfaces() -> None:
    try:
        from scapy.all import conf
    except Exception as exc:
        raise RuntimeError(f"Scapy is not available: {exc}") from exc

    for iface in conf.ifaces.values():
        name = getattr(iface, "name", "")
        description = getattr(iface, "description", "")
        network_name = getattr(iface, "network_name", "")
        print(f"{name}\t{description}\t{network_name}")


def _sensor_payload(features: dict) -> dict:
    return {
        "metadata": {
            "src_ip": features.get("_src_ip", ""),
            "dst_ip": features.get("_dst_ip", ""),
            "src_port": features.get("_src_port", ""),
            "dst_port": features.get("_dst_port", ""),
            "protocol": features.get("_protocol", ""),
        },
        "features": features,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AIS-Detect local packet sensor")
    parser.add_argument("--api-base", required=True, help="Deployed backend base URL, e.g. https://ais-detect-152-42-209-219.nip.io")
    parser.add_argument("--username", default="admin", help="AIS-Detect username")
    parser.add_argument("--password", help="AIS-Detect password. If omitted, prompted securely.")
    parser.add_argument("--token", help="Existing JWT token. If omitted, username/password login is used.")
    parser.add_argument("--interface", help="Local capture interface name. Omit to use Scapy default.")
    parser.add_argument("--list-interfaces", action="store_true", help="List local Scapy interfaces and exit")
    parser.add_argument("--queue-size", type=int, default=2000, help="Max completed flows buffered before dropping")
    parser.add_argument("--control-interval", type=float, default=2.0, help="Seconds between backend stop-control polls")
    args = parser.parse_args()

    if args.list_interfaces:
        _list_interfaces()
        return 0

    api_base = args.api_base.rstrip("/")
    token = args.token
    auth_password = args.password
    if not token:
        auth_password = auth_password or getpass.getpass(f"Password for {args.username}: ")
        token = _login(api_base, args.username, auth_password)

    flow_queue: queue.Queue[dict] = queue.Queue(maxsize=args.queue_size)
    stop_event = threading.Event()
    stats = {"queued": 0, "sent": 0, "dropped": 0, "errors": 0, "anomalies": 0}

    def on_flow(features: dict) -> None:
        try:
            flow_queue.put_nowait(dict(features))
            stats["queued"] += 1
        except queue.Full:
            stats["dropped"] += 1

    def sender() -> None:
        nonlocal token
        endpoint = f"{api_base}/api/capture/ingest-flow"
        while not stop_event.is_set() or not flow_queue.empty():
            try:
                features = flow_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            for attempt in range(2):
                try:
                    result = _json_post(endpoint, _sensor_payload(features), token=token, timeout=15.0)
                    stats["sent"] += 1
                    stats["anomalies"] += int(result.get("anomalies_found", 0) or 0)
                    break
                except error.HTTPError as exc:
                    if exc.code == 401 and auth_password and attempt == 0:
                        token = _login(api_base, args.username, auth_password)
                        continue
                    stats["errors"] += 1
                    print(f"[sensor] ingest failed: HTTP {exc.code} {exc.reason}", file=sys.stderr)
                    break
                except Exception as exc:
                    stats["errors"] += 1
                    print(f"[sensor] ingest failed: {exc}", file=sys.stderr)
                    break

    def control_poller() -> None:
        endpoint = f"{api_base}/api/capture/sensor-control"
        while not stop_event.wait(max(args.control_interval, 0.5)):
            try:
                control = _json_get(endpoint, token=token, timeout=10.0)
                if control.get("stop_requested"):
                    print("[sensor] remote stop requested by dashboard")
                    request_stop()
                    return
            except Exception as exc:
                print(f"[sensor] control poll failed: {exc}", file=sys.stderr)

    sender_thread = threading.Thread(target=sender, daemon=True, name="sensor-sender")
    sender_thread.start()
    control_thread = threading.Thread(target=control_poller, daemon=True, name="sensor-control")

    sniffer = CICFlowMeterSniffer(
        on_flow_complete=on_flow,
        interface=args.interface,
        flow_mode=CAPTURE_FLOW_MODE_LIVE_DASHBOARD,
    )

    def request_stop(_signum=None, _frame=None) -> None:
        if stop_event.is_set():
            return
        stop_event.set()
        sniffer.stop(flush=True)

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)

    print(f"[sensor] sending flows to {api_base}")
    print(f"[sensor] interface: {args.interface or 'scapy default'}")
    print("[sensor] press Ctrl+C to stop")

    sniffer.start()
    if getattr(sniffer, "error", None):
        raise RuntimeError(sniffer.error)

    last_sent = 0
    try:
        _json_post(
            f"{api_base}/api/capture/sensor-started",
            {"interface": args.interface or "scapy default"},
            token=token,
            timeout=10.0,
        )
        control_thread.start()
        while not stop_event.is_set():
            time.sleep(5)
            if stats["sent"] != last_sent:
                last_sent = stats["sent"]
                print(
                    "[sensor] sent={sent} queued={queued} dropped={dropped} "
                    "errors={errors} anomalies={anomalies}".format(**stats)
                )
    finally:
        request_stop()
        sender_thread.join(timeout=10.0)
        try:
            _json_post(f"{api_base}/api/capture/sensor-stopped", stats, token=token, timeout=10.0)
        except Exception as exc:
            print(f"[sensor] stopped acknowledgement failed: {exc}", file=sys.stderr)
        print(
            "[sensor] stopped. sent={sent} queued={queued} dropped={dropped} "
            "errors={errors} anomalies={anomalies}".format(**stats)
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
