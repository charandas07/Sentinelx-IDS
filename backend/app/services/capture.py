"""
Packet Capture Engine
Uses Scapy for live capture when available (e.g. with Npcap / WinPcap / root / Admin).
Automatically falls back to a Windows Native Capture Engine (Decoy Port Listeners +
GetExtendedTcpTable connection monitor) on Windows when raw packet capture is unavailable,
ensuring real-time detection of live port scans and attacks even without Npcap or Admin privileges.
"""
import logging
import threading
import time
import os
import socket
import select
from collections import deque
from datetime import datetime
from typing import Optional, Callable, List, Any, Set, Tuple

logger = logging.getLogger(__name__)

# ── Global capture state ──────────────────────────────────────────────────────
_sniffer: Optional[Any] = None
_packet_queue: deque = deque(maxlen=10000)
_packet_callbacks: List[Callable] = []
_dropped_packets: int = 0
_stats = {
    "packets_captured": 0,
    "bytes_captured": 0,
    "start_time": None,
    "last_packet_time": None,
    "capture_available": False,
    "capture_error": None,
    "dropped_packets": 0,
    "active_iface": None,
}
_stats_lock = threading.Lock()

# ── Windows Native Fallback State ──────────────────────────────────────────────
_native_running: bool = False
_native_threads: List[threading.Thread] = []
_native_sockets: List[socket.socket] = []
_seen_tcp_conns: Set[Tuple[int, str, int, str, int]] = set()
_seen_tcp_last_pruned: float = 0.0

# Decoy ports for incoming probe detection (skips already-bound ports)
_DEFAULT_DECOY_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000, 9090,
    9990, 9991, 9992, 9993, 9994, 9995
] + list(range(7000, 7060))


def register_callback(cb: Callable):
    """Register a function to be called with each parsed packet dict."""
    _packet_callbacks.append(cb)


def is_capturing() -> bool:
    scapy_ok = bool(
        _sniffer is not None and
        getattr(_sniffer, "thread", None) is not None and
        _sniffer.thread.is_alive() and
        getattr(_sniffer, "exception", None) is None
    )
    return scapy_ok or _native_running


def get_stats() -> dict:
    with _stats_lock:
        return dict(_stats)


def get_last_error() -> Optional[str]:
    with _stats_lock:
        return _stats.get("capture_error")


def list_interfaces() -> List[str]:
    """Return list of available network interfaces."""
    try:
        from scapy.interfaces import get_if_list
        ifs = get_if_list()
        if ifs:
            return ifs
    except Exception:
        pass

    if os.name == 'nt':
        try:
            from scapy.arch.windows import get_windows_if_list
            names = [i['name'] for i in get_windows_if_list() if i.get('ips')]
            if names:
                return names
        except Exception:
            pass

    try:
        import socket
        return [socket.gethostname()]
    except Exception:
        return []


def _parse_packet(pkt) -> Optional[dict]:
    """Extract relevant fields from a Scapy packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = None
        icmp_type = None
        icmp_id = None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = str(tcp.flags)
            if dst_port == 53 or src_port == 53:
                protocol = "DNS"
            elif dst_port in (80, 8080):
                protocol = "HTTP"
            elif dst_port in (443, 8443):
                protocol = "HTTPS"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            protocol = "UDP"
            src_port = udp.sport
            dst_port = udp.dport
            if dst_port == 53 or src_port == 53:
                protocol = "DNS"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            try:
                icmp = pkt[ICMP]
                icmp_type = int(icmp.type)
                icmp_id = int(getattr(icmp, "id", 0) or 0)
            except Exception:
                icmp_type = None
                icmp_id = None

        try:
            ts = datetime.utcfromtimestamp(float(pkt.time))
        except Exception:
            ts = datetime.utcnow()

        return {
            "timestamp": ts,
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": len(pkt),
            "flags": flags,
            "icmp_type": icmp_type,
            "icmp_id": icmp_id,
            "status": "NORMAL",
            "is_simulation": False,
        }
    except Exception as e:
        logger.debug(f"Packet parse error: {e}")
        return None


def _handle_parsed(parsed: dict):
    if not parsed:
        return
    with _stats_lock:
        _stats["packets_captured"] += 1
        _stats["bytes_captured"] += parsed.get("packet_size", 60)
        _stats["last_packet_time"] = datetime.utcnow()

    if len(_packet_queue) >= _packet_queue.maxlen:
        try:
            _packet_queue.popleft()
        except IndexError:
            pass
        with _stats_lock:
            _stats["dropped_packets"] = _stats.get("dropped_packets", 0) + 1
        if _stats["dropped_packets"] % 100 == 1:
            logger.warning(
                f"Packet queue overflow: {_stats['dropped_packets']} packets dropped"
            )

    _packet_queue.append(parsed)
    for cb in _packet_callbacks:
        try:
            cb(parsed)
        except Exception:
            pass


def _handle(pkt):
    parsed = _parse_packet(pkt)
    if parsed:
        _handle_parsed(parsed)


def _start_windows_native_capture(iface: Optional[str] = None):
    """
    Windows native capture engine:
    1. Binds decoy listener sockets on common scan ports to intercept incoming scans.
    2. Runs GetExtendedTcpTable poller to detect TCP connection attempts across all ports.
    """
    global _native_running, _native_threads, _native_sockets, _seen_tcp_conns
    _native_running = True
    _native_threads = []
    _native_sockets = []
    _seen_tcp_conns.clear()

    try:
        from app.config import settings
        local_ips = set(settings.get_local_ips())
    except Exception:
        local_ips = {"127.0.0.1"}

    primary_ip = next(iter(local_ips - {"127.0.0.1"}), "127.0.0.1")

    # 1. Bind Decoy Sockets
    sock_map = {}
    for p in _DEFAULT_DECOY_PORTS:
        if p in (8000, 8003, 5173, 3000):
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', p))
            s.listen(5)
            s.setblocking(False)
            sock_map[s] = p
            _native_sockets.append(s)
        except Exception:
            pass

    logger.info(f"Windows Native Capture active with {len(_native_sockets)} decoy port listeners")

    def _decoy_loop():
        while _native_running:
            if not sock_map:
                time.sleep(0.5)
                continue
            try:
                readable, _, _ = select.select(list(sock_map.keys()), [], [], 0.1)
                for s in readable:
                    target_port = sock_map.get(s)
                    if not target_port:
                        continue
                    try:
                        conn, addr = s.accept()
                        conn.close()
                        src_ip, src_port = addr[0], addr[1]
                        parsed = {
                            "timestamp": datetime.utcnow(),
                            "src_ip": str(src_ip),
                            "dst_ip": primary_ip,
                            "src_port": int(src_port),
                            "dst_port": int(target_port),
                            "protocol": "TCP",
                            "packet_size": 60,
                            "flags": "S",
                            "icmp_type": None,
                            "icmp_id": None,
                            "status": "NORMAL",
                            "is_simulation": False,
                        }
                        _handle_parsed(parsed)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Decoy listener error: {e}")
                time.sleep(0.1)

    # 2. GetExtendedTcpTable Poller
    import ctypes, struct
    from ctypes import wintypes

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ('dwState', wintypes.DWORD),
            ('dwLocalAddr', wintypes.DWORD),
            ('dwLocalPort', wintypes.DWORD),
            ('dwRemoteAddr', wintypes.DWORD),
            ('dwRemotePort', wintypes.DWORD),
            ('dwOwningPid', wintypes.DWORD)
        ]

    def _tcp_table_poller():
        global _seen_tcp_last_pruned
        row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        table_size = wintypes.DWORD(65536)
        buf = ctypes.create_string_buffer(65536)

        while _native_running:
            try:
                table_size.value = 65536
                res = ctypes.windll.iphlpapi.GetExtendedTcpTable(
                    buf, ctypes.byref(table_size), True, 2, 5, 0
                )
                now = time.time()
                if res == 0:
                    num = struct.unpack('I', buf[:4])[0]
                    if now - _seen_tcp_last_pruned > 30.0:
                        _seen_tcp_conns.clear()
                        _seen_tcp_last_pruned = now

                    for i in range(num):
                        offset = 4 + i * row_size
                        state, l_addr, l_port_raw, r_addr, r_port_raw, pid = struct.unpack(
                            'IIIIII', buf[offset:offset+row_size]
                        )
                        if state == 2 or r_port_raw == 0:
                            continue

                        l_port = socket.ntohs(l_port_raw & 0xFFFF)
                        r_port = socket.ntohs(r_port_raw & 0xFFFF)
                        l_ip = socket.inet_ntoa(struct.pack('I', l_addr))
                        r_ip = socket.inet_ntoa(struct.pack('I', r_addr))

                        if l_port in (8000, 8003, 5173) or r_port in (8000, 8003, 5173):
                            continue

                        key = (state, l_ip, l_port, r_ip, r_port)
                        if key in _seen_tcp_conns:
                            continue
                        _seen_tcp_conns.add(key)

                        if l_ip in local_ips and r_ip in local_ips:
                            src_ip = l_ip
                            dst_ip = r_ip
                            src_port = l_port
                            dst_port = r_port
                        elif l_ip in local_ips:
                            src_ip = r_ip
                            dst_ip = l_ip
                            src_port = r_port
                            dst_port = l_port
                        else:
                            src_ip = l_ip
                            dst_ip = r_ip
                            src_port = l_port
                            dst_port = r_port

                        parsed = {
                            "timestamp": datetime.utcnow(),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "packet_size": 60,
                            "flags": "S",
                            "icmp_type": None,
                            "icmp_id": None,
                            "status": "NORMAL",
                            "is_simulation": False,
                        }
                        _handle_parsed(parsed)
            except Exception as e:
                logger.debug(f"TCP table poller error: {e}")
            time.sleep(0.04)

    t1 = threading.Thread(target=_decoy_loop, daemon=True, name="DecoyListener")
    t2 = threading.Thread(target=_tcp_table_poller, daemon=True, name="TCPTablePoller")
    t1.start()
    t2.start()
    _native_threads.extend([t1, t2])


def start_capture(iface: Optional[str] = None, bpf_filter: str = "ip") -> bool:
    """Start live packet capture asynchronously. Returns True if capture started."""
    global _sniffer
    if is_capturing():
        return True

    if _sniffer is not None or _native_running:
        stop_capture()

    with _stats_lock:
        _stats["start_time"] = datetime.utcnow()
        _stats["dropped_packets"] = 0
        _stats["capture_error"] = None
        _stats["capture_available"] = True
        _stats["active_iface"] = iface or "auto"

    scapy_started = False
    try:
        from scapy.all import conf
        # On Windows, Scapy strictly requires conf.use_pcap (Npcap/WinPcap) to sniff
        if os.name == 'nt' and not getattr(conf, 'use_pcap', False):
            logger.info("Scapy pcap provider not found on Windows; bypassing Scapy.")
        else:
            from scapy.sendrecv import AsyncSniffer

            _sniffer = AsyncSniffer(iface=iface, filter=bpf_filter, prn=_handle, store=False)
            _sniffer.start()
            time.sleep(0.4)
            if (
                getattr(_sniffer, "thread", None) is not None and
                _sniffer.thread.is_alive() and
                getattr(_sniffer, "exception", None) is None
            ):
                scapy_started = True
                logger.info("Scapy packet capture active.")
            else:
                exc = getattr(_sniffer, "exception", None)
                if exc:
                    logger.warning(f"Scapy capture thread exception: {exc}")
                try:
                    _sniffer.stop()
                except Exception:
                    pass
                _sniffer = None
    except Exception as e:
        logger.warning(f"Scapy capture start failed: {e}")
        _sniffer = None

    if not scapy_started:
        if os.name == 'nt':
            logger.info("Falling back to Windows Native Capture Engine.")
            _start_windows_native_capture(iface)
            with _stats_lock:
                _stats["capture_available"] = True
                _stats["capture_error"] = None
                _stats["active_iface"] = "windows-native"
            return True
        else:
            with _stats_lock:
                _stats["capture_available"] = False
                _stats["capture_error"] = "Packet capture unavailable. Run with root / CAP_NET_RAW."
                _stats["active_iface"] = None
            return False

    return True


def stop_capture():
    """Stop live packet capture."""
    global _sniffer, _native_running, _native_sockets
    _native_running = False
    for s in _native_sockets:
        try:
            s.close()
        except Exception:
            pass
    _native_sockets.clear()

    if _sniffer is not None:
        try:
            if getattr(_sniffer, "running", False):
                _sniffer.stop()
        except Exception as e:
            logger.debug(f"Error stopping sniffer: {e}")
        finally:
            _sniffer = None
    with _stats_lock:
        _stats["active_iface"] = None
    logger.info("Packet capture stopped.")


def drain_queue() -> list:
    """Return and clear all pending parsed packets."""
    items = []
    while True:
        try:
            items.append(_packet_queue.popleft())
        except IndexError:
            break
    return items
