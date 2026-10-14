"""
Traffic Processor
Maintains per-IP sliding-window counters for detection engine.
Uses per-second buckets for O(1) lookups rather than scanning full event lists.
"""
import asyncio
import ipaddress
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

from app.config import settings
from app.services.flow_tracker import flow_tracker

logger = logging.getLogger(__name__)

# Backend own ports to ignore
_BACKEND_PORTS = {8000, 8003, 5173}


def _ip_in_networks(ip_str: str, networks: list) -> bool:
    if not networks or not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in networks)
    except Exception:
        return False


def _is_inbound(src_ip: str, dst_ip: str,
                local_ips: Set[str], whitelist_ips: Set[str],
                protected_networks: Optional[list] = None) -> bool:
    """
    Return True if the packet is targeting this machine or protected networks
    (inbound, LAN, or local test scan), and the source is not whitelisted.
    Outbound connections to external hosts (where dst_ip is external) return False.
    """
    if src_ip in whitelist_ips:
        return False
    # If the destination IP is explicitly this machine or inside protected networks, it is targeting us!
    if dst_ip and (dst_ip in local_ips or (protected_networks and _ip_in_networks(dst_ip, protected_networks))):
        return True
    # If destination IP is missing/unspecified, treat as inbound if source is not our own local IP
    if not dst_ip and src_ip not in local_ips:
        return True
    return False


class _Bucket:
    """One-second aggregated counter bucket."""
    __slots__ = ("second", "count", "ports", "syn_count", "icmp_count", "per_port_counts")

    def __init__(self, second: int):
        self.second: int = second
        self.count: int = 0
        self.ports: Set[Optional[int]] = set()
        self.syn_count: int = 0
        self.icmp_count: int = 0
        self.per_port_counts: dict = {}


class PerIPCounter:
    """
    Per-IP sliding-window counter backed by per-second buckets.
    Public methods are identical to the original PerIPCounter so detectors
    don't need to change.

    `clock` is an injectable callable returning epoch seconds; the default
    is wall-clock time. The evaluation harness injects a virtual clock so
    replayed packet timestamps drive the sliding windows deterministically.
    """

    def __init__(self, window_seconds: int = 300, clock=None):
        self.window = window_seconds
        self._buckets: deque[_Bucket] = deque()
        self._clock = clock or time.time
        self._last_add: float = self._clock()

    # ── Internal helpers ──────────────────────────────────────────────

    def _current_second(self) -> int:
        return int(self._clock())

    def _prune(self, now_sec: int):
        cutoff = now_sec - self.window
        while self._buckets and self._buckets[0].second <= cutoff:
            self._buckets.popleft()

    def _get_or_create_bucket(self, second: int) -> _Bucket:
        if self._buckets and self._buckets[-1].second == second:
            return self._buckets[-1]
        b = _Bucket(second)
        self._buckets.append(b)
        return b

    # ── Public API ────────────────────────────────────────────────────

    def add(self, dst_port: Optional[int], protocol: str,
            flags: Optional[str], size: int):
        now_sec = self._current_second()
        self._last_add = self._clock()
        self._prune(now_sec)
        b = self._get_or_create_bucket(now_sec)
        b.count += 1
        is_syn_only = bool(flags and "S" in flags and "A" not in flags)
        if is_syn_only:
            b.syn_count += 1
            if dst_port is not None:
                b.ports.add(dst_port)
                b.per_port_counts[dst_port] = b.per_port_counts.get(dst_port, 0) + 1
        if protocol == "ICMP":
            b.icmp_count += 1

    def _buckets_in_window(self, seconds: int) -> List[_Bucket]:
        cutoff = self._current_second() - seconds
        return [b for b in self._buckets if b.second > cutoff]

    def count_in_window(self, seconds: int) -> int:
        return sum(b.count for b in self._buckets_in_window(seconds))

    def unique_ports_in_window(self, seconds: int) -> int:
        """Count unique destination ports touched by SYN-only packets (inbound scan detection)."""
        ports: Set = set()
        for b in self._buckets_in_window(seconds):
            ports.update(b.ports)
        return len(ports)

    def syn_unique_ports_in_window(self, seconds: int) -> int:
        return self.unique_ports_in_window(seconds)

    def syn_count_in_window(self, seconds: int) -> int:
        return sum(b.syn_count for b in self._buckets_in_window(seconds))

    def icmp_count_in_window(self, seconds: int) -> int:
        return sum(b.icmp_count for b in self._buckets_in_window(seconds))

    def pps(self, seconds: int = 1) -> float:
        return self.count_in_window(seconds) / max(seconds, 1)

    # Legacy compatibility
    def events_in_window(self, seconds: int) -> list:
        """Legacy: return list of (datetime, port, protocol_placeholder, flags, size) tuples."""
        result = []
        for b in self._buckets_in_window(seconds):
            for port, cnt in getattr(b, "per_port_counts", {}).items():
                for _ in range(cnt):
                    result.append((datetime.utcnow(), port, "TCP", "S", 0))
        return result

    def idle_seconds(self) -> float:
        return time.time() - self._last_add


class TrafficProcessor:
    """Central traffic state manager. One instance lives for the process lifetime."""

    def __init__(self, clock=None):
        # Injectable clock (epoch seconds) for deterministic replay in the
        # evaluation harness; defaults to wall-clock time.
        self._clock = clock or time.time
        self._counters: Dict[str, PerIPCounter] = defaultdict(
            lambda: PerIPCounter(window_seconds=300, clock=self._clock)
        )
        self._global_pps: deque = deque(maxlen=300)  # 5-minute history of (time, pps)
        self._total_packets = 0
        self._total_bytes = 0
        self._inbound_packets = 0
        self._protocol_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        # Track IPs that arrived via simulation so engine can tag alerts correctly
        self.sim_ips: Set[str] = set()
        # Warm-up: don't alert until we have baseline
        self._warmup_done = False
        self._baseline_samples: deque = deque(maxlen=300)
        self._alert_active = False

        # Cache local/whitelist IPs and protected networks from settings
        self._local_ips: Set[str] = set(settings.get_local_ips())
        self._whitelist_ips: Set[str] = set(settings.get_whitelist_ips())
        self._protected_networks = []
        for net_str in settings.get_protected_networks():
            try:
                self._protected_networks.append(ipaddress.ip_network(net_str, strict=False))
            except Exception as e:
                logger.warning(f"Invalid protected network '{net_str}': {e}")

    # ── Inbound helper ────────────────────────────────────────────────

    def is_inbound(self, src_ip: str, dst_ip: str,
                   src_port: Optional[int] = None,
                   dst_port: Optional[int] = None) -> bool:
        """Return True for inbound packets from outside the local network."""
        # Ignore packets on backend's own ports
        if src_port in _BACKEND_PORTS or dst_port in _BACKEND_PORTS:
            return False
        return _is_inbound(src_ip, dst_ip, self._local_ips, self._whitelist_ips, self._protected_networks)

    def is_whitelisted(self, src_ip: str) -> bool:
        return src_ip in self._whitelist_ips

    # ── Processing ────────────────────────────────────────────────────

    async def process(self, pkt: dict):
        """Ingest one parsed packet dict."""
        async with self._lock:
            src = pkt["src_ip"]
            dst = pkt.get("dst_ip", "")
            src_port = pkt.get("src_port")
            dst_port = pkt.get("dst_port")
            is_sim = pkt.get("is_simulation", False)

            # Bidirectional flow tracking (SentinelX 2.0).
            # Runs for every packet regardless of direction so that flow
            # statistics stay complete; failures never block ingestion.
            try:
                flow_tracker.process_packet(pkt)
            except Exception as e:  # pragma: no cover - defensive
                logger.debug(f"Flow tracking error (packet skipped): {e}")

            # Track simulation source IPs
            if is_sim:
                self.sim_ips.add(src)

            # Always count totals
            self._total_packets += 1
            self._total_bytes += pkt.get("packet_size", 0)
            self._protocol_counts[pkt.get("protocol", "OTHER")] += 1

            # Only feed per-IP detector counters for inbound packets
            # (or simulation packets which bypass direction checks)
            if is_sim or self.is_inbound(src, dst, src_port, dst_port):
                self._inbound_packets += 1
                self._counters[src].add(
                    dst_port,
                    pkt.get("protocol", "OTHER"),
                    pkt.get("flags"),
                    pkt.get("packet_size", 0),
                )

    def sample_global_pps(self, value: float):
        """Record a global PPS sample for dashboard PPS chart."""
        now = datetime.utcnow()
        self._global_pps.append((now, value))

    def sample_inbound_pps(self, value: float):
        """Record an inbound PPS sample to feed the baseline."""
        if not self._alert_active:
            self._baseline_samples.append(value)
        if not self._warmup_done and len(self._baseline_samples) >= 30:
            self._warmup_done = True

    def get_baseline_pps(self) -> float:
        """Median baseline over warm-up window, excluding alert samples."""
        samples = self._baseline_samples
        if len(samples) < 10:
            return 0.0
        sorted_s = sorted(samples)
        mid = len(sorted_s) // 2
        if len(sorted_s) % 2 == 0:
            return (sorted_s[mid - 1] + sorted_s[mid]) / 2.0
        return float(sorted_s[mid])

    def is_warmup_done(self) -> bool:
        return self._warmup_done

    def prime_baseline(self, pps: float, samples: int = 30):
        """Prime the inbound baseline if warmup is not done. Never overwrites a real baseline."""
        if not self._warmup_done and len(self._baseline_samples) < 30:
            for _ in range(samples):
                self._baseline_samples.append(float(pps))
            self._warmup_done = True

    def set_alert_active(self, active: bool):
        """Call from detection loop so baseline excludes alert-period samples."""
        self._alert_active = active

    def get_counter(self, ip: str) -> PerIPCounter:
        return self._counters[ip]

    def get_all_ips(self) -> List[str]:
        return list(self._counters.keys())

    def get_total_packets(self) -> int:
        return self._total_packets

    def get_inbound_packets(self) -> int:
        return self._inbound_packets

    def get_total_bytes(self) -> int:
        return self._total_bytes

    def get_protocol_counts(self) -> Dict[str, int]:
        return dict(self._protocol_counts)

    def get_pps_history(self, n: int = 60) -> List[dict]:
        history = list(self._global_pps)[-n:]
        return [{"time": t.isoformat(), "pps": v} for t, v in history]

    def evict_idle(self, seconds: int = 300):
        """Remove counters and sim_ip entries for IPs idle longer than `seconds`."""
        evicted = [ip for ip, c in self._counters.items() if c.idle_seconds() > seconds]
        for ip in evicted:
            del self._counters[ip]
            self.sim_ips.discard(ip)
        if evicted:
            logger.debug(f"Evicted {len(evicted)} idle IP counters.")


# Singleton
traffic_processor = TrafficProcessor()
