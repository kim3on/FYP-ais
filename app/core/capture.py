"""
Live Packet Capture & CIC-IDS-2017 Feature Extractor
======================================================
Captures live network traffic, aggregates packets into flows,
computes the same 77 CIC-IDS-2017 features that the model was
trained on, then feeds each completed flow to the AIS detector.

Requirements
------------
    pip install scapy psutil

Needs root / admin privileges to open a raw socket:
    Linux:  sudo python ...  OR  sudo setcap cap_net_raw+ep $(which python3)
    Windows: run as Administrator

How it works
------------
1.  Scapy sniffs packets on the chosen interface.
2.  FlowAggregator groups packets into bi-directional flows by
    (src_ip, dst_ip, src_port, dst_port, protocol) 5-tuple.
3.  A flow is "completed" when:
      - A TCP FIN or RST flag is seen, OR
      - The flow has been idle for FLOW_TIMEOUT seconds, OR
      - The flow has accumulated MAX_FLOW_PACKETS packets.
4.  FlowFeatureExtractor computes all 77 CIC-IDS-2017 features
    from the raw packet list.
5.  The scored result is pushed to a callback (→ WebSocket).

Feature alignment
-----------------
The 77 features computed here match exactly the column names in
the CICIDSPreprocessor's feature_columns_ list so the model
scaler.transform() works without any remapping.
"""

import time
import threading
import statistics
from dataclasses import dataclass, field
from typing import Callable, Optional
import logging

logger = logging.getLogger(__name__)

# ── Flow settings ─────────────────────────────────────────────────────
FLOW_TIMEOUT       = 30       # seconds of inactivity before flow is closed
MAX_FLOW_PACKETS   = 1000     # force-close after this many packets
MIN_FLOW_PACKETS   = 2        # discard single-packet flows (not enough data)
CAPTURE_INTERFACE  = None     # None = default/all interfaces
CAPTURE_FILTER     = "ip"     # BPF filter — capture only IP packets

# ── TCP flag bitmasks ──────────────────────────────────────────────────
_F = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04,
      'PSH': 0x08, 'ACK': 0x10, 'URG': 0x20,
      'ECE': 0x40, 'CWE': 0x80}


@dataclass
class PacketRecord:
    """Lightweight record of one captured packet."""
    timestamp:   float    # time.time()
    length:      int      # total packet length in bytes
    ip_flags:    int      # IP flags
    tcp_flags:   int      # TCP flags (0 for UDP/ICMP)
    header_len:  int      # IP+TCP/UDP header length
    payload_len: int      # data payload bytes
    direction:   str      # 'fwd' or 'bwd'
    win_size:    int      # TCP window size
    urgent:      int      # TCP urgent pointer


@dataclass
class Flow:
    """All packets belonging to one network flow."""
    flow_id:    tuple                       # (src,dst,sport,dport,proto)
    proto:      int                         # 6=TCP, 17=UDP, else ICMP
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    start_time: float = field(default_factory=time.time)
    last_time:  float = field(default_factory=time.time)
    packets:    list  = field(default_factory=list)   # list[PacketRecord]
    active_start: Optional[float] = None
    active_periods: list = field(default_factory=list)  # list of durations
    idle_periods:   list = field(default_factory=list)

    def add(self, pkt: PacketRecord):
        now = pkt.timestamp
        if self.packets:
            gap = now - self.last_time
            if gap > 1.0:                  # > 1 s idle gap
                self.idle_periods.append(gap)
                if self.active_start is not None:
                    self.active_periods.append(now - self.active_start)
                    self.active_start = now
            else:
                if self.active_start is None:
                    self.active_start = self.last_time
        self.last_time = now
        self.packets.append(pkt)

    def is_expired(self, now: float) -> bool:
        return (
            (now - self.last_time) > FLOW_TIMEOUT or
            len(self.packets) >= MAX_FLOW_PACKETS
        )


# ════════════════════════════════════════════════════════════
#  FEATURE EXTRACTOR
# ════════════════════════════════════════════════════════════

class FlowFeatureExtractor:
    """
    Computes all 77 CIC-IDS-2017 numeric features from a Flow object.
    Returns a dict with keys matching the CICIDSPreprocessor feature schema.
    """

    def extract(self, flow: Flow) -> dict:
        pkts = flow.packets
        if len(pkts) < 1:
            return {}

        fwd = [p for p in pkts if p.direction == 'fwd']
        bwd = [p for p in pkts if p.direction == 'bwd']

        dur = max((flow.last_time - flow.start_time) * 1_000_000, 1)  # microseconds

        # Packet lengths
        all_lens = [p.length     for p in pkts]
        fwd_lens = [p.length     for p in fwd]
        bwd_lens = [p.length     for p in bwd]
        fwd_pay  = [p.payload_len for p in fwd]
        bwd_pay  = [p.payload_len for p in bwd]

        # IAT (inter-arrival times in microseconds)
        def iat(seq):
            if len(seq) < 2:
                return []
            ts = sorted(p.timestamp for p in seq)
            return [(ts[i+1]-ts[i])*1e6 for i in range(len(ts)-1)]

        all_iat = iat(pkts)
        fwd_iat = iat(fwd)
        bwd_iat = iat(bwd)

        # TCP flag counts
        def flag_count(seq, flag):
            return sum(1 for p in seq if p.tcp_flags & _F.get(flag, 0))

        # Active / Idle
        act = flow.active_periods or [dur / 1e6]
        idl = flow.idle_periods   or [0.0]

        # Init window sizes
        fwd_init_win = fwd[0].win_size  if fwd else -1
        bwd_init_win = bwd[0].win_size  if bwd else -1

        def _mean(lst): return statistics.mean(lst) if lst else 0.0
        def _std(lst):  return statistics.stdev(lst) if len(lst) > 1 else 0.0
        def _max(lst):  return max(lst) if lst else 0
        def _min(lst):  return min(lst) if lst else 0
        def _sum(lst):  return sum(lst) if lst else 0

        n_fwd = len(fwd)
        n_bwd = len(bwd)
        n_all = len(pkts)

        flow_bytes_s   = (_sum(all_lens) / dur * 1e6) if dur > 0 else 0
        flow_pkts_s    = (n_all / dur * 1e6)          if dur > 0 else 0
        fwd_pkts_s     = (n_fwd / dur * 1e6)          if dur > 0 else 0
        bwd_pkts_s     = (n_bwd / dur * 1e6)          if dur > 0 else 0
        down_up_ratio  = (n_bwd / n_fwd)              if n_fwd > 0 else 0

        fwd_hdr_len  = _sum(p.header_len for p in fwd)
        bwd_hdr_len  = _sum(p.header_len for p in bwd)

        return {
            'Destination Port':            flow.dst_port,
            'Flow Duration':               dur,
            'Total Fwd Packets':           n_fwd,
            'Total Backward Packets':      n_bwd,
            'Total Length of Fwd Packets': _sum(fwd_pay),
            'Total Length of Bwd Packets': _sum(bwd_pay),
            'Fwd Packet Length Max':       _max(fwd_lens),
            'Fwd Packet Length Min':       _min(fwd_lens),
            'Fwd Packet Length Mean':      _mean(fwd_lens),
            'Fwd Packet Length Std':       _std(fwd_lens),
            'Bwd Packet Length Max':       _max(bwd_lens),
            'Bwd Packet Length Min':       _min(bwd_lens),
            'Bwd Packet Length Mean':      _mean(bwd_lens),
            'Bwd Packet Length Std':       _std(bwd_lens),
            'Flow Bytes/s':                flow_bytes_s,
            'Flow Packets/s':              flow_pkts_s,
            'Flow IAT Mean':               _mean(all_iat),
            'Flow IAT Std':                _std(all_iat),
            'Flow IAT Max':                _max(all_iat),
            'Flow IAT Min':                _min(all_iat),
            'Fwd IAT Total':               _sum(fwd_iat),
            'Fwd IAT Mean':                _mean(fwd_iat),
            'Fwd IAT Std':                 _std(fwd_iat),
            'Fwd IAT Max':                 _max(fwd_iat),
            'Fwd IAT Min':                 _min(fwd_iat),
            'Bwd IAT Total':               _sum(bwd_iat),
            'Bwd IAT Mean':                _mean(bwd_iat),
            'Bwd IAT Std':                 _std(bwd_iat),
            'Bwd IAT Max':                 _max(bwd_iat),
            'Bwd IAT Min':                 _min(bwd_iat),
            'Fwd PSH Flags':               flag_count(fwd, 'PSH'),
            'Bwd PSH Flags':               flag_count(bwd, 'PSH'),
            'Fwd URG Flags':               flag_count(fwd, 'URG'),
            'Bwd URG Flags':               flag_count(bwd, 'URG'),
            'Fwd Header Length':           fwd_hdr_len,
            'Bwd Header Length':           bwd_hdr_len,
            'Fwd Packets/s':               fwd_pkts_s,
            'Bwd Packets/s':               bwd_pkts_s,
            'Min Packet Length':           _min(all_lens),
            'Max Packet Length':           _max(all_lens),
            'Packet Length Mean':          _mean(all_lens),
            'Packet Length Std':           _std(all_lens),
            'Packet Length Variance':      (_std(all_lens) ** 2),
            'FIN Flag Count':              flag_count(pkts, 'FIN'),
            'SYN Flag Count':              flag_count(pkts, 'SYN'),
            'RST Flag Count':              flag_count(pkts, 'RST'),
            'PSH Flag Count':              flag_count(pkts, 'PSH'),
            'ACK Flag Count':              flag_count(pkts, 'ACK'),
            'URG Flag Count':              flag_count(pkts, 'URG'),
            'CWE Flag Count':              flag_count(pkts, 'CWE'),
            'ECE Flag Count':              flag_count(pkts, 'ECE'),
            'Down/Up Ratio':               down_up_ratio,
            'Average Packet Size':         _mean(all_lens),
            'Avg Fwd Segment Size':        _mean(fwd_lens),
            'Avg Bwd Segment Size':        _mean(bwd_lens),
            'Fwd Avg Bytes/Bulk':          0,
            'Fwd Avg Packets/Bulk':        0,
            'Fwd Avg Bulk Rate':           0,
            'Bwd Avg Bytes/Bulk':          0,
            'Bwd Avg Packets/Bulk':        0,
            'Bwd Avg Bulk Rate':           0,
            'Subflow Fwd Packets':         n_fwd,
            'Subflow Fwd Bytes':           _sum(fwd_pay),
            'Subflow Bwd Packets':         n_bwd,
            'Subflow Bwd Bytes':           _sum(bwd_pay),
            'Init_Win_bytes_forward':      fwd_init_win,
            'Init_Win_bytes_backward':     bwd_init_win,
            'act_data_pkt_fwd':            sum(1 for p in fwd if p.payload_len > 0),
            'min_seg_size_forward':        _min(p.header_len for p in fwd) if fwd else 0,
            'Active Mean':                 _mean([a * 1e6 for a in act]),
            'Active Std':                  _std([a  * 1e6 for a in act]),
            'Active Max':                  _max([a  * 1e6 for a in act]),
            'Active Min':                  _min([a  * 1e6 for a in act]),
            'Idle Mean':                   _mean([i * 1e6 for i in idl]),
            'Idle Std':                    _std([i  * 1e6 for i in idl]),
            'Idle Max':                    _max([i  * 1e6 for i in idl]),
            'Idle Min':                    _min([i  * 1e6 for i in idl]),
            # Metadata (not used by model, used by alert display)
            '_src_ip':   flow.src_ip,
            '_dst_ip':   flow.dst_ip,
            '_src_port': flow.src_port,
            '_dst_port': flow.dst_port,
            '_protocol': flow.proto,
        }


# ════════════════════════════════════════════════════════════
#  FLOW AGGREGATOR
# ════════════════════════════════════════════════════════════

class FlowAggregator:
    """
    Receives individual packet metadata and groups them into flows.
    Calls on_flow_complete(features_dict) when a flow finishes.
    Thread-safe via a lock.
    """

    def __init__(self, on_flow_complete: Callable[[dict], None]):
        self._flows:    dict[tuple, Flow] = {}
        self._lock      = threading.Lock()
        self._extractor = FlowFeatureExtractor()
        self._on_complete = on_flow_complete
        self._reaper    = threading.Thread(target=self._reap_loop,
                                           daemon=True, name='flow-reaper')
        self._reaper.start()

    def ingest(self, raw_pkt):
        """
        Parse a Scapy packet and add it to the appropriate flow.
        Called from the sniffer thread.
        """
        try:
            pkt_data = self._parse(raw_pkt)
        except Exception:
            return
        if pkt_data is None:
            return

        fid, rec, src_ip, dst_ip, sport, dport, proto = pkt_data

        with self._lock:
            # Canonical flow id: always (lower_ip, higher_ip, ...) so that
            # fwd and bwd packets share the same flow entry
            rev_fid = (dst_ip, src_ip, dport, sport, proto)

            if fid in self._flows:
                fl = self._flows[fid]
                rec.direction = 'fwd'
            elif rev_fid in self._flows:
                fl = self._flows[rev_fid]
                rec.direction = 'bwd'
            else:
                fl = Flow(flow_id=fid, proto=proto,
                          src_ip=src_ip, dst_ip=dst_ip,
                          src_port=sport, dst_port=dport)
                self._flows[fid] = fl
                rec.direction = 'fwd'

            fl.add(rec)

            # Complete on TCP FIN/RST
            if proto == 6 and (rec.tcp_flags & (_F['FIN'] | _F['RST'])):
                self._complete(fl)

    def _parse(self, raw_pkt) -> Optional[tuple]:
        """Extract fields from a Scapy IP packet. Returns None if not IP."""
        from scapy.layers.inet import IP, TCP, UDP

        if not raw_pkt.haslayer(IP):
            return None

        ip  = raw_pkt[IP]
        now = float(raw_pkt.time) if hasattr(raw_pkt, 'time') else time.time()

        src_ip = ip.src
        dst_ip = ip.dst
        proto  = ip.proto
        ip_hdr = ip.ihl * 4

        tcp_flags = 0
        win_size  = 0
        urgent    = 0
        sport     = 0
        dport     = 0
        transport_hdr = 0

        if raw_pkt.haslayer(TCP):
            tcp = raw_pkt[TCP]
            sport      = tcp.sport
            dport      = tcp.dport
            tcp_flags  = int(tcp.flags)
            win_size   = tcp.window
            urgent     = tcp.urgptr
            transport_hdr = tcp.dataofs * 4 if tcp.dataofs else 20
        elif raw_pkt.haslayer(UDP):
            from scapy.layers.inet import UDP as SCAPY_UDP
            udp = raw_pkt[SCAPY_UDP]
            sport = udp.sport
            dport = udp.dport
            transport_hdr = 8

        total_len   = len(raw_pkt)
        header_len  = ip_hdr + transport_hdr
        payload_len = max(0, total_len - header_len)

        fid = (src_ip, dst_ip, sport, dport, proto)
        rec = PacketRecord(
            timestamp=now,
            length=total_len,
            ip_flags=int(ip.flags) if ip.flags else 0,
            tcp_flags=tcp_flags,
            header_len=header_len,
            payload_len=payload_len,
            direction='fwd',
            win_size=win_size,
            urgent=urgent,
        )
        return fid, rec, src_ip, dst_ip, sport, dport, proto

    def _complete(self, flow: Flow):
        """Extract features and fire callback. Must be called under lock."""
        key = flow.flow_id
        self._flows.pop(key, None)
        rev = (flow.dst_ip, flow.src_ip, flow.dst_port, flow.src_port, flow.proto)
        self._flows.pop(rev, None)

        if len(flow.packets) < MIN_FLOW_PACKETS:
            return

        feats = self._extractor.extract(flow)
        if feats:
            try:
                self._on_complete(feats)
            except Exception as e:
                logger.warning(f"Flow callback error: {e}")

    def _reap_loop(self):
        """Background thread: expire idle / oversized flows every 5 s."""
        while True:
            time.sleep(5)
            now = time.time()
            with self._lock:
                expired = [fid for fid, fl in self._flows.items()
                           if fl.is_expired(now)]
                for fid in expired:
                    fl = self._flows.get(fid)
                    if fl:
                        self._complete(fl)

    def flush_all(self):
        """Force-complete all open flows. Call on shutdown."""
        with self._lock:
            for fl in list(self._flows.values()):
                self._complete(fl)


# ════════════════════════════════════════════════════════════
#  PACKET SNIFFER
# ════════════════════════════════════════════════════════════

class PacketSniffer:
    """
    Wraps Scapy's sniff() in a background thread.
    Feeds each packet to FlowAggregator.

    Usage
    -----
        def on_flow(features):
            print(features)

        sniffer = PacketSniffer(on_flow_complete=on_flow, interface='eth0')
        sniffer.start()
        ...
        sniffer.stop()
    """

    def __init__(
        self,
        on_flow_complete: Callable[[dict], None],
        interface: Optional[str] = None,
        bpf_filter: str = CAPTURE_FILTER,
    ):
        self._interface   = interface
        self._filter      = bpf_filter
        self._aggregator  = FlowAggregator(on_flow_complete)
        self._thread: Optional[threading.Thread] = None
        self._running     = False
        self._stop_event  = threading.Event()

        # Stats
        self.packets_captured = 0
        self.flows_completed  = 0

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name='pkt-sniffer'
        )
        self._thread.start()
        logger.info(f"PacketSniffer started on interface={self._interface or 'all'}")

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        self._aggregator.flush_all()
        logger.info(
            f"PacketSniffer stopped. "
            f"Packets={self.packets_captured}, Flows={self.flows_completed}"
        )

    def _sniff_loop(self):
        try:
            from scapy.all import sniff, conf
            conf.verb = 0   # suppress Scapy banners

            def _pkt_handler(pkt):
                if not self._running:
                    return
                self.packets_captured += 1
                self._aggregator.ingest(pkt)

            sniff(
                iface=self._interface,
                filter=self._filter,
                prn=_pkt_handler,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except ImportError:
            logger.error(
                "Scapy is not installed. "
                "Run:  pip install scapy"
            )
            self._running = False
        except PermissionError:
            logger.error(
                "Packet capture requires root/admin privileges. "
                "Run with sudo, or: sudo setcap cap_net_raw+ep $(which python3)"
            )
            self._running = False
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running


# ════════════════════════════════════════════════════════════
#  DEMO: run standalone to test capture without FastAPI
# ════════════════════════════════════════════════════════════

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')

    print("AIS-Detect — Live Packet Capture Demo")
    print("Press Ctrl+C to stop\n")

    def on_flow(feats):
        src = feats.get('_src_ip', '?')
        dst = feats.get('_dst_ip', '?')
        dur = feats.get('Flow Duration', 0)
        pkts = feats.get('Total Fwd Packets', 0) + feats.get('Total Backward Packets', 0)
        bps = feats.get('Flow Bytes/s', 0)
        print(f"  Flow: {src}:{feats.get('_src_port','?')} → "
              f"{dst}:{feats.get('_dst_port','?')} | "
              f"pkts={pkts} dur={dur/1e6:.3f}s bps={bps:.0f}")

    sniffer = PacketSniffer(on_flow_complete=on_flow)
    sniffer.start()

    try:
        while True:
            time.sleep(1)
            print(f"  [capture] pkts={sniffer.packets_captured}", end='\r')
    except KeyboardInterrupt:
        print("\nStopping...")
        sniffer.stop()
