"""
PCAP File Analyzer
Uses dpkt (with scapy fallback) to parse .pcap/.pcapng files.
"""
import io
import time
import logging
from collections import defaultdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


async def analyze_pcap(filepath: str, db) -> dict:
    """Analyze a PCAP file and return a report dict."""
    start = time.time()
    packets = _parse_pcap(filepath)

    if not packets:
        return {
            "filename": filepath.split("/")[-1].split("\\")[-1],
            "packets_analyzed": 0,
            "protocols": {},
            "top_src_ips": [],
            "top_dst_ips": [],
            "top_ports": [],
            "potential_attacks": [],
            "overall_threat_score": 0.0,
            "alerts_generated": 0,
            "analysis_time_seconds": time.time() - start,
        }

    # Aggregate statistics
    protocols: dict = defaultdict(int)
    src_ips: dict = defaultdict(int)
    dst_ips: dict = defaultdict(int)
    ports: dict = defaultdict(int)
    per_ip_ports: dict = defaultdict(set)
    per_ip_packets: dict = defaultdict(int)
    syn_count: dict = defaultdict(int)
    icmp_count: dict = defaultdict(int)

    for pkt in packets:
        proto = pkt.get("protocol", "OTHER")
        protocols[proto] += 1
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if src:
            src_ips[src] += 1
            per_ip_packets[src] += 1
        if dst:
            dst_ips[dst] += 1
        dport = pkt.get("dst_port")
        if dport:
            ports[dport] += 1
            if src:
                per_ip_ports[src].add(dport)
        if proto == "ICMP" and src:
            icmp_count[src] += 1
        flags = pkt.get("flags", "") or ""
        if proto == "TCP" and "S" in flags and "A" not in flags and src:
            syn_count[src] += 1

    potential_attacks = []
    threat_score = 0.0

    # Port scan detection
    for ip, ports_set in per_ip_ports.items():
        if len(ports_set) > 15:
            potential_attacks.append(f"PORT_SCAN from {ip} ({len(ports_set)} unique ports)")
            threat_score = min(100, threat_score + 25)

    # Brute force
    BRUTE_PORTS = {22: "SSH", 21: "FTP", 3389: "RDP"}
    for ip, count in per_ip_packets.items():
        for port, service in BRUTE_PORTS.items():
            port_count = sum(1 for p in packets if p.get("src_ip") == ip and p.get("dst_port") == port)
            if port_count > 8:
                potential_attacks.append(f"BRUTE_FORCE from {ip} on {service}:{port} ({port_count} attempts)")
                threat_score = min(100, threat_score + 20)

    # SYN flood
    for ip, count in syn_count.items():
        if count > 50:
            potential_attacks.append(f"SYN_FLOOD from {ip} ({count} SYN packets)")
            threat_score = min(100, threat_score + 30)

    # ICMP flood
    for ip, count in icmp_count.items():
        if count > 30:
            potential_attacks.append(f"ICMP_FLOOD from {ip} ({count} ICMP packets)")
            threat_score = min(100, threat_score + 15)

    def top_n(d: dict, n: int = 10):
        return [{"key": k, "count": v} for k, v in sorted(d.items(), key=lambda x: -x[1])[:n]]

    # Persist alerts to DB
    alerts_generated = 0
    if potential_attacks and db:
        try:
            from app.models.alert import Alert
            for attack_str in potential_attacks:
                parts = attack_str.split(" from ")
                attack_type = parts[0].strip().replace(" ", "_")
                src_ip = parts[1].split(" ")[0] if len(parts) > 1 else "UNKNOWN"
                alert = Alert(
                    timestamp=datetime.utcnow(),
                    attack_type=attack_type,
                    severity="HIGH",
                    src_ip=src_ip,
                    details=f"[PCAP] {attack_str}",
                    threat_score=threat_score,
                    is_simulation=False,
                )
                db.add(alert)
                alerts_generated += 1
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to save PCAP alerts: {e}")

    return {
        "filename": filepath.split("/")[-1].split("\\")[-1],
        "packets_analyzed": len(packets),
        "protocols": dict(protocols),
        "top_src_ips": top_n(src_ips),
        "top_dst_ips": top_n(dst_ips),
        "top_ports": top_n(ports),
        "potential_attacks": list(set(potential_attacks)),
        "overall_threat_score": round(threat_score, 1),
        "alerts_generated": alerts_generated,
        "analysis_time_seconds": round(time.time() - start, 3),
    }


def _parse_pcap(filepath: str) -> list:
    """Parse PCAP file using dpkt, with scapy fallback."""
    packets = []

    # Try dpkt first
    try:
        import dpkt
        with open(filepath, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    import socket
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    proto = "OTHER"
                    sport = None
                    dport = None
                    flags = None
                    icmp_type = None
                    icmp_id = None
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        proto = "TCP"
                        sport = ip.data.sport
                        dport = ip.data.dport
                        f_val = ip.data.flags
                        flags = ""
                        if f_val & dpkt.tcp.TH_SYN:
                            flags += "S"
                        if f_val & dpkt.tcp.TH_ACK:
                            flags += "A"
                        if dport in (80, 8080):
                            proto = "HTTP"
                        elif dport in (443,):
                            proto = "HTTPS"
                        elif dport == 53:
                            proto = "DNS"
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        proto = "UDP"
                        sport = ip.data.sport
                        dport = ip.data.dport
                        if dport == 53:
                            proto = "DNS"
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        proto = "ICMP"
                        try:
                            icmp_type = int(ip.data.type)
                            # Echo request/reply carry an id in the 8-byte header.
                            if icmp_type in (0, 8):
                                icmp_id = int(ip.data.data[:2].hex(), 16) if isinstance(ip.data.data, bytes) and len(ip.data.data) >= 2 else None
                        except Exception:
                            icmp_type = None
                            icmp_id = None
                    packets.append({
                        "src_ip": src, "dst_ip": dst,
                        "src_port": sport, "dst_port": dport,
                        "protocol": proto, "flags": flags,
                        "packet_size": len(buf),
                        "icmp_type": icmp_type, "icmp_id": icmp_id,
                    })
                except Exception:
                    continue
        return packets
    except ImportError:
        logger.warning("dpkt not available, falling back to Scapy")
    except Exception as e:
        logger.warning(f"dpkt parse failed: {e}, trying Scapy")

    # Scapy fallback
    try:
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        scapy_pkts = rdpcap(filepath)
        for pkt in scapy_pkts:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            proto = "OTHER"
            sport = dport = None
            flags = None
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
            packets.append({
                "src_ip": str(ip.src), "dst_ip": str(ip.dst),
                "src_port": sport, "dst_port": dport,
                "protocol": proto, "flags": flags,
                "packet_size": len(pkt),
            })
    except Exception as e:
        logger.error(f"Scapy parse also failed: {e}")

    return packets
