"""Port Scan Detector.

Counts unique destination ports only from SYN-without-ACK packets,
so server replies (ACK, SYN-ACK) to ephemeral source ports never
falsely trigger port-scan alerts.

Flow-aware upgrade (SentinelX 2.0): additionally consults the bidirectional
flow tracker's distinct-port accounting, which covers connectionless (UDP)
probing and reports how many distinct destination hosts were contacted, so a
vertical scan (one host, many ports) can be distinguished from a horizontal
scan (many hosts, few ports each).
"""
from typing import Optional
from app.config import settings
from app.services.traffic_processor import TrafficProcessor
from app.services.flow_tracker import flow_tracker


def check(
    processor: TrafficProcessor,
    src_ip: str,
    rule_threshold: Optional[float] = None,
    rule_window: Optional[int] = None,
    tracker=None,
) -> Optional[dict]:
    """Return alert dict if port scan detected, else None."""
    # Never alert on whitelisted IPs
    if processor.is_whitelisted(src_ip):
        return None

    threshold = int(rule_threshold or settings.PORT_SCAN_THRESHOLD)
    window = int(rule_window or settings.PORT_SCAN_WINDOW)

    counter = processor.get_counter(src_ip)

    # Baseline signal: SYN-only packets' unique destination ports
    syn_ports = counter.syn_unique_ports_in_window(window)

    # Flow-aware signal: distinct dst ports attempted at flow level
    # (TCP SYN attempts plus UDP/other probes within the window).
    try:
        scan = (tracker or flow_tracker).scan_summary(src_ip, window_seconds=window)
    except Exception:
        scan = {"distinct_ports": 0, "distinct_hosts": 0, "attempts": 0,
                "window_seconds": window, "ports_sample": [], "hosts_sample": []}

    # Use the stronger of both observables; both count destination ports
    # contacted by this source in the window.
    unique_ports = max(syn_ports, scan["distinct_ports"])
    distinct_hosts = scan["distinct_hosts"]

    if unique_ports >= threshold:
        total = counter.count_in_window(window)
        # Determine the most-likely target host from flow-level scan accounting
        target_ips = scan.get("hosts_sample", []) if isinstance(scan.get("hosts_sample"), list) else []
        dst_ip = target_ips[0] if target_ips else (settings.get_local_ips()[0] if settings.get_local_ips() else "127.0.0.1")
        if distinct_hosts <= 1:
            scan_kind = "vertical"
            scan_text = (f"vertical scan: {unique_ports} distinct ports on a single host")
        else:
            scan_kind = "horizontal"
            scan_text = (f"horizontal scan: {unique_ports} distinct ports across "
                         f"{distinct_hosts} hosts")
        return {
            "attack_type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_count": total,
            "connection_count": unique_ports,
            "detection_rule": (
                f"port_scan: {unique_ports} unique dst ports in {window}s "
                f"(threshold={threshold}, kind={scan_kind})"
            ),
            "recommended_action": (
                f"Block IP {src_ip}, investigate intent. "
                f"Port scan detected ({scan_text})."
            ),
            "details": (
                f"Source IP contacted {unique_ports} unique destination ports "
                f"within {window} seconds ({scan_text})"
            ),
            # Structured values for evidence + tests
            "observed": {
                "unique_dst_ports": unique_ports,
                "distinct_dst_hosts": distinct_hosts,
                "syn_only_ports": syn_ports,
                "flow_level_ports": scan["distinct_ports"],
                "packet_count": total,
            },
            "threshold": float(threshold),
            "window": window,
            "evidence_extra": {
                "scan_kind": scan_kind,
                "ports_sample": scan.get("ports_sample", []),
                "hosts_sample": scan.get("hosts_sample", []),
            },
        }
    return None

