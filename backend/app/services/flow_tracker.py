"""
Bidirectional Network Flow Tracker (SentinelX 2.0)

Groups packets into bidirectional network flows keyed by transport protocol
and the canonical (unordered) endpoint pair, so packets travelling in both
directions belong to the same flow record.

Design notes / documented semantics
------------------------------------
* Byte counts refer to the **captured packet length** as reported by the
  parser (frame length for live capture and PCAP replay, synthetic size for
  simulated packets). IP total length / payload length are not used.
* Flow direction ("forward") is defined by the source endpoint of the FIRST
  packet of the flow; later packets from that endpoint are forward, the
  opposite direction is reverse.
* TCP/UDP flows are keyed by (protocol, sorted endpoint pairs including
  ports). ICMP flows are keyed by (ICMP, sorted IP pair [, icmp id when the
  parser provides it]) - ICMP has no transport ports and none are invented.
* Out-of-order packets update first/last-seen via min/max and still count
  toward packet/byte totals. Repeated (retransmitted) packets are counted
  again - deduplication would require TCP sequence tracking and is out of
  scope; this limitation is documented in the research notes.
* Malformed or header-less packets are skipped without raising.
* The table is bounded (FLOW_MAX_TRACKED) with least-recently-used eviction
  and idle/active timeouts, so memory cannot grow without limit.
* Access is guarded by an RLock: the capture thread, asyncio pipeline and
  offline PCAP jobs may touch the tracker concurrently.
"""
import logging
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

from app.config import settings

logger = logging.getLogger(__name__)

# Protocol label -> transport family used for flow keying.
_TCP_LABELS = {"TCP", "HTTP", "HTTPS"}
_UDP_LABELS = {"UDP", "DNS"}


def transport_protocol(protocol: Optional[str], flags: Optional[str],
                       src_port: Optional[int], dst_port: Optional[int]) -> str:
    """Resolve the transport-level protocol for flow keying.

    Application-layer labels (HTTP/HTTPS/DNS) are folded back to their
    transport. When the label is unknown we infer from observable structure:
    TCP flag strings imply TCP, otherwise presence of ports implies UDP,
    otherwise the transport is unknown ("OTHER").
    """
    label = (protocol or "").upper()
    if label in ("ICMP", "ICMPV6"):
        return "ICMP"
    if label in _TCP_LABELS:
        return "TCP"
    if label in _UDP_LABELS:
        return "UDP"
    if flags:
        return "TCP"
    if src_port is not None and dst_port is not None:
        return "UDP"
    return "OTHER"


def _norm_ip(ip: str) -> str:
    """Normalize an IP string (IPv6-safe canonical form)."""
    try:
        import ipaddress
        return str(ipaddress.ip_address(ip))
    except Exception:
        return ip or "?"


def _endpoint_sort_key(ip: str, port: Optional[int]) -> Tuple[str, int]:
    return (_norm_ip(ip), int(port) if port is not None else -1)


class FlowKey:
    """Canonical bidirectional flow identifier.

    Endpoints are sorted so both directions of a conversation resolve to the
    same key. For connectionless protocols without ports only IPs are used.
    """

    __slots__ = ("transport", "ep_a", "ep_b", "icmp_id", "_hash")

    def __init__(self, transport: str, ep_a: Tuple[str, int], ep_b: Tuple[str, int],
                 icmp_id: Optional[int] = None):
        self.transport = transport
        self.ep_a = ep_a
        self.ep_b = ep_b
        self.icmp_id = icmp_id
        self._hash = hash((transport, ep_a, ep_b, icmp_id))

    @classmethod
    def from_packet(cls, src_ip: str, dst_ip: str, src_port: Optional[int],
                    dst_port: Optional[int], transport: str,
                    icmp_id: Optional[int] = None) -> "FlowKey":
        a = _endpoint_sort_key(src_ip, src_port)
        b = _endpoint_sort_key(dst_ip, dst_port)
        if a <= b:
            return cls(transport, a, b, icmp_id)
        return cls(transport, b, a, icmp_id)

    def __eq__(self, other):
        return (isinstance(other, FlowKey)
                and self.transport == other.transport
                and self.ep_a == other.ep_a
                and self.ep_b == other.ep_b
                and self.icmp_id == other.icmp_id)

    def __hash__(self):
        return self._hash

    def __str__(self):
        proto = self.transport.lower()
        a_ip, a_port = self.ep_a
        b_ip, b_port = self.ep_b
        if self.transport in ("TCP", "UDP") and a_port >= 0 and b_port >= 0:
            return f"{proto}:{a_ip}:{a_port}-{b_ip}:{b_port}"
        if self.transport == "ICMP" and self.icmp_id is not None:
            return f"icmp:{a_ip}-{b_ip}:id{self.icmp_id}"


class FlowRecord:
    """Accumulated statistics for one bidirectional flow."""

    __slots__ = (
        "key", "flow_id", "transport", "src_ip", "dst_ip", "src_port", "dst_port",
        "first_seen", "last_seen",
        "fwd_packets", "rev_packets", "fwd_bytes", "rev_bytes",
        "syn_count", "ack_count", "fin_count", "rst_count",
        "rev_syn_count", "rev_ack_count", "rev_fin_count", "rev_rst_count",
        "icmp_requests", "icmp_responses",
        "connection_attempts", "response_seen",
        "is_simulation", "provenance",
        "termination_reason", "packet_refs",
        "_first_ts_epoch",
    )

    def __init__(self, key: FlowKey, transport: str, src_ip: str, dst_ip: str,
                 src_port: Optional[int], dst_port: Optional[int],
                 ts: datetime, is_simulation: bool = False,
                 provenance: str = "live"):
        self.key = key
        self.flow_id = str(key)
        self.transport = transport
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.first_seen = ts
        self.last_seen = ts
        try:
            self._first_ts_epoch = ts.timestamp()
        except Exception:
            self._first_ts_epoch = time.time()
        self.fwd_packets = 0
        self.rev_packets = 0
        self.fwd_bytes = 0
        self.rev_bytes = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.rev_syn_count = 0
        self.rev_ack_count = 0
        self.rev_fin_count = 0
        self.rev_rst_count = 0
        self.icmp_requests = 0
        self.icmp_responses = 0
        self.connection_attempts = 0     # forward SYN-without-ACK observed
        self.response_seen = False       # any reverse-direction packet observed
        self.is_simulation = is_simulation
        self.provenance = provenance      # "live" | "pcap" | "simulation"
        self.termination_reason: Optional[str] = None  # reset/closed/idle_timeout/active_timeout
        # Bounded per-flow evidence ring: (ts, direction, size, flags)
        self.packet_refs: Deque[tuple] = deque(
            maxlen=max(4, settings.EVIDENCE_MAX_PACKET_REFS)
        )

    # ── Accounting ─────────────────────────────────────────────────────

    def update(self, ts: datetime, forward: bool, size: int,
               flags: Optional[str], icmp_type: Optional[int] = None) -> None:
        # Out-of-order safe: min/max timestamps.
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts

        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += size
        else:
            self.rev_packets += 1
            self.rev_bytes += size
            self.response_seen = True

        if flags:
            if "S" in flags:
                # Any SYN flag observation (includes SYN-ACK).
                if forward:
                    self.syn_count += 1
                else:
                    self.rev_syn_count += 1
                if "A" not in flags and forward:
                    # SYN-without-ACK: an attempt to open a connection.
                    self.connection_attempts += 1
            if "A" in flags:
                if forward:
                    self.ack_count += 1
                else:
                    self.rev_ack_count += 1
            if "F" in flags:
                if forward:
                    self.fin_count += 1
                else:
                    self.rev_fin_count += 1
            if "R" in flags:
                if forward:
                    self.rst_count += 1
                else:
                    self.rev_rst_count += 1
                if self.termination_reason is None:
                    self.termination_reason = "reset"

        if self.transport == "ICMP" and icmp_type is not None:
            # 0 = echo reply, 8 = echo request (IPv4 ICMP).
            if icmp_type == 8:
                self.icmp_requests += 1
            elif icmp_type == 0:
                self.icmp_responses += 1

        self.packet_refs.append((
            ts.isoformat() if isinstance(ts, datetime) else str(ts),
            "fwd" if forward else "rev",
            size,
            flags,
        ))

    # ── Derived statistics ─────────────────────────────────────────────

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.rev_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.rev_bytes

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def packets_per_second(self) -> float:
        d = self.duration_seconds
        return self.total_packets / d if d > 0 else float(self.total_packets)

    @property
    def bytes_per_second(self) -> float:
        d = self.duration_seconds
        return self.total_bytes / d if d > 0 else float(self.total_bytes)

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_seen.timestamp()

    def age_seconds(self) -> float:
        return max(0.0, time.time() - self._first_ts_epoch)

    def to_dict(self, include_refs: bool = False) -> dict:
        d = {
            "flow_id": self.flow_id,
            "transport": self.transport,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "fwd_packets": self.fwd_packets,
            "rev_packets": self.rev_packets,
            "fwd_bytes": self.fwd_bytes,
            "rev_bytes": self.rev_bytes,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "rev_syn_count": self.rev_syn_count,
            "rev_ack_count": self.rev_ack_count,
            "rev_fin_count": self.rev_fin_count,
            "rev_rst_count": self.rev_rst_count,
            "icmp_requests": self.icmp_requests,
            "icmp_responses": self.icmp_responses,
            "connection_attempts": self.connection_attempts,
            "response_seen": self.response_seen,
            "is_simulation": self.is_simulation,
            "provenance": self.provenance,
            "termination_reason": self.termination_reason,
        }
        if include_refs:
            d["packet_refs"] = list(self.packet_refs)
        return d

class FlowTracker:
    """Bounded, thread-safe table of bidirectional flows."""

    def __init__(self,
                 idle_timeout: Optional[int] = None,
                 active_timeout: Optional[int] = None,
                 max_flows: Optional[int] = None):
        self.idle_timeout = int(idle_timeout if idle_timeout is not None
                                else settings.FLOW_IDLE_TIMEOUT)
        self.active_timeout = int(active_timeout if active_timeout is not None
                                  else settings.FLOW_ACTIVE_TIMEOUT)
        self.max_flows = int(max_flows if max_flows is not None
                             else settings.FLOW_MAX_TRACKED)
        self._flows: "OrderedDict[FlowKey, FlowRecord]" = OrderedDict()
        self._lock = threading.RLock()
        self._evicted = 0
        self._expired = 0
        self._last_sweep = time.time()
        # Per-source scan accounting: src -> deque[(epoch, dst_ip, dst_port)]
        self._scan_events: Dict[str, Deque[tuple]] = {}
        self._scan_window = int(settings.FLOW_SCAN_WINDOW)

    # ── Ingestion ──────────────────────────────────────────────────────

    def process_packet(self, pkt: dict) -> Optional[FlowRecord]:
        """Feed one parsed packet dict. Returns the flow it belongs to.

        Never raises on malformed input: bad packets are skipped safely.
        """
        try:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip:
                return None

            flags = pkt.get("flags")
            src_port = pkt.get("src_port")
            dst_port = pkt.get("dst_port")
            protocol = pkt.get("protocol")
            transport = transport_protocol(protocol, flags, src_port, dst_port)

            if transport in ("TCP", "UDP"):
                key = FlowKey.from_packet(src_ip, dst_ip, src_port, dst_port, transport)
            elif transport == "ICMP":
                key = FlowKey.from_packet(src_ip, dst_ip, None, None, "ICMP",
                                          pkt.get("icmp_id"))
            else:
                key = FlowKey.from_packet(src_ip, dst_ip, None, None, "OTHER")

            ts = pkt.get("timestamp") or datetime.utcnow()
            if not isinstance(ts, datetime):
                ts = datetime.utcnow()

            size = int(pkt.get("packet_size") or 0)
            is_sim = bool(pkt.get("is_simulation", False))
            provenance = "simulation" if is_sim else pkt.get("provenance", "live")

            with self._lock:
                self._maybe_sweep()
                flow = self._flows.get(key)
                if flow is None:
                    # Forward direction is defined by the first packet's source.
                    flow = FlowRecord(
                        key=key, transport=transport,
                        src_ip=_norm_ip(src_ip), dst_ip=_norm_ip(dst_ip),
                        src_port=src_port, dst_port=dst_port,
                        ts=ts, is_simulation=is_sim, provenance=provenance,
                    )
                    self._flows[key] = flow
                    if len(self._flows) > self.max_flows:
                        self._evict_oldest()
                else:
                    self._flows.move_to_end(key)
                    if is_sim:
                        flow.is_simulation = True

                forward = (_norm_ip(src_ip) == flow.src_ip
                           and (flow.src_port is None or src_port == flow.src_port))

                flow.update(ts, forward, size, flags, pkt.get("icmp_type"))

                if transport in ("TCP", "UDP") and forward and dst_port is not None:
                    self._record_scan_event(src_ip, ts, dst_ip, dst_port)
                return flow
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"Flow tracking skipped malformed packet: {e}")
            return None

    # ── Scan accounting ────────────────────────────────────────────────

    def _record_scan_event(self, src_ip: str, ts: datetime, dst_ip: str, dst_port: int):
        events = self._scan_events.get(src_ip)
        if events is None:
            events = deque()
            self._scan_events[src_ip] = events
        events.append((ts.timestamp(), dst_ip, dst_port))
        # bound per-source memory
        cutoff = ts.timestamp() - max(self._scan_window * 10, 60)
        while events and events[0][0] < cutoff:
            events.popleft()

    def scan_summary(self, src_ip: str, window_seconds: Optional[int] = None,
                     now_epoch: Optional[float] = None) -> dict:
        """Distinct destination ports/hosts contacted by src_ip in the window.

        Counts are based on forwarded flow packets (connection attempts),
        independent of SYN flags, so connectionless (UDP) scans are covered.
        """
        window = int(window_seconds or self._scan_window)
        now = now_epoch if now_epoch is not None else time.time()
        cutoff = now - window
        events = self._scan_events.get(src_ip)
        ports = set()
        hosts = set()
        total = 0
        if events:
            for ts, dst_ip, dst_port in events:
                if ts >= cutoff:
                    ports.add(dst_port)
                    hosts.add(dst_ip)
                    total += 1
        return {
            "distinct_ports": len(ports),
            "distinct_hosts": len(hosts),
            "attempts": total,
            "window_seconds": window,
            "ports_sample": sorted(ports)[:32],
            "hosts_sample": sorted(hosts)[:32],
        }

    # ── Lifecycle ──────────────────────────────────────────────────────

    def _evict_oldest(self):
        # OrderedDict keeps insertion order (move_to_end on activity),
        # so the first item is the least recently used.
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)
            self._evicted += 1

    def _maybe_sweep(self, force: bool = False):
        now = time.time()
        if not force and now - self._last_sweep < 5.0:
            return
        self._last_sweep = now
        self.sweep()

    def sweep(self) -> int:
        """Expire idle/active flows. Returns number of flows expired."""
        now = time.time()
        expired = 0
        to_remove = []
        for key, flow in self._flows.items():
            idle = now - flow.last_seen.timestamp()
            if idle > self.idle_timeout:
                flow.termination_reason = flow.termination_reason or "idle_timeout"
                to_remove.append(key)
                expired += 1
            elif flow.age_seconds() > self.active_timeout:
                flow.termination_reason = flow.termination_reason or "active_timeout"
                to_remove.append(key)
                expired += 1
        for key in to_remove:
            self._flows.pop(key, None)
        # Prune stale scan events

    # ── Queries ────────────────────────────────────────────────────────

    def get(self, flow_id: str) -> Optional[FlowRecord]:
        with self._lock:
            for flow in self._flows.values():
                if flow.flow_id == flow_id:
                    return flow
        return None

    def flows_for_ip(self, ip: str) -> List[FlowRecord]:
        ipn = _norm_ip(ip)
        with self._lock:
            return [f for f in self._flows.values()
                    if f.src_ip == ipn or f.dst_ip == ipn]

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_flows": len(self._flows),
                "evicted": self._evicted,
                "expired": self._expired,
                "max_flows": self.max_flows,
                "idle_timeout": self.idle_timeout,
                "active_timeout": self.active_timeout,
            }

    def snapshot(self,
                 ip: Optional[str] = None,
                 port: Optional[int] = None,
                 protocol: Optional[str] = None,
                 since: Optional[datetime] = None,
                 until: Optional[datetime] = None,
                 provenance: Optional[str] = None,
                 limit: int = 100,
                 offset: int = 0) -> Tuple[List[dict], int]:
        """Filtered, paginated view of tracked flows (newest first)."""
        ipn = _norm_ip(ip) if ip else None
        proto = protocol.upper() if protocol else None
        with self._lock:
            items = []
            for flow in self._flows.values():
                if ipn and ipn not in (flow.src_ip, flow.dst_ip):
                    continue
                if port is not None and port not in (flow.src_port, flow.dst_port):
                    continue
                if proto and flow.transport != proto:
                    continue
                if since and flow.last_seen < since:
                    continue
                if until and flow.first_seen > until:
                    continue
                if provenance and flow.provenance != provenance:
                    continue
                items.append(flow)
            total = len(items)
            items.sort(key=lambda f: f.last_seen, reverse=True)
            page = items[offset:offset + limit]
            return [f.to_dict() for f in page], total

    def associated_flows(self, src_ip: str, dst_ip: Optional[str] = None) -> List[str]:
        """Flow ids opened by src_ip (optionally toward dst_ip).

        Used to link alerts to supporting flow records for evidence.
        """
        ipn = _norm_ip(src_ip)
        dstn = _norm_ip(dst_ip) if dst_ip else None
        ids = []
        with self._lock:
            for flow in self._flows.values():
                if flow.src_ip != ipn:
                    continue
                if dstn and flow.dst_ip != dstn:
                    continue
                ids.append(flow.flow_id)
        return ids[:settings.EVIDENCE_MAX_PACKET_REFS * 2]

    def scan_summary(self, src_ip: str, window_seconds: int = 10) -> dict:
        """Distinct destination ports and hosts contacted by src_ip within window_seconds."""
        ipn = _norm_ip(src_ip)
        cutoff = datetime.utcnow().timestamp() - window_seconds
        with self._lock:
            dst_ports = set()
            dst_hosts = set()
            attempts = 0
            for flow in self._flows.values():
                if flow.src_ip == ipn and flow.last_seen.timestamp() >= cutoff:
                    attempts += flow.packets_fwd
                    if flow.dst_port is not None and flow.dst_port > 0:
                        dst_ports.add(flow.dst_port)
                    if flow.dst_ip:
                        dst_hosts.add(flow.dst_ip)
            return {
                "distinct_ports": len(dst_ports),
                "distinct_hosts": len(dst_hosts),
                "attempts": attempts,
                "window_seconds": window_seconds,
                "ports_sample": sorted(list(dst_ports))[:10],
                "hosts_sample": sorted(list(dst_hosts))[:10],
            }


# Singleton used by the live pipeline.
flow_tracker = FlowTracker()
