"""Brute Force Detector.
Counts only SYN-without-ACK attempts to auth service ports so that
server responses (ACK, RST) are never counted as attack attempts.

Flow-aware upgrade (SentinelX 2.0): also counts per-flow connection
attempts toward the auth port and observes whether any flow got a response,
which is reported as evidence context. IMPORTANT LIMITATION: packet capture
cannot reveal login outcomes on encrypted transports; the alert describes
repeated connection attempts / suspected brute-force activity only.
"""
from typing import Optional
from app.config import settings
from app.services.traffic_processor import TrafficProcessor
from app.services.flow_tracker import flow_tracker

# Web ports (80, 443) are excluded to prevent false positives for normal web visitors
BRUTE_FORCE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    3389: "RDP", 5900: "VNC",
}


def check(
    processor: TrafficProcessor,
    src_ip: str,
    rule_threshold: Optional[float] = None,
    rule_window: Optional[int] = None,
    tracker=None,
) -> Optional[dict]:
    """Return alert if brute force detected."""
    # Never alert on whitelisted IPs
    if processor.is_whitelisted(src_ip):
        return None

    threshold = int(rule_threshold or settings.BRUTE_FORCE_THRESHOLD)
    window = int(rule_window or settings.BRUTE_FORCE_WINDOW)

    counter = processor.get_counter(src_ip)
    # events_in_window returns (datetime, port, proto, flags, size) tuples
    events = counter.events_in_window(window)

    # Check SYN-only connections to known auth service ports
    for port, service in BRUTE_FORCE_PORTS.items():
        attempts = sum(1 for e in events if e[1] == port)
        if attempts >= threshold:
            # Flow-aware context: flows from this source toward the service
            # port and whether the target ever responded.
            flows = [f for f in (tracker or flow_tracker).flows_for_ip(src_ip)
                     if f.dst_port == port and f.transport == "TCP"]
            flows_with_response = sum(1 for f in flows if f.response_seen)
            return {
                "attack_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_port": port,
                "protocol": "TCP",
                "packet_count": attempts,
                "connection_count": attempts,
                "detection_rule": (
                    f"brute_force: {attempts} SYN attempts to {service}:{port} "
                    f"in {window}s (threshold={threshold})"
                ),
                "recommended_action": (
                    f"Block IP {src_ip}, enable account lockout for {service} service."
                ),
                "details": (
                    f"Possible brute force on {service} (port {port}): "
                    f"{attempts} attempts in {window}s"
                ),
                "observed": {
                    "connection_attempts": attempts,
                    "flow_count": len(flows),
                    "flows_with_response": flows_with_response,
                },
                "threshold": float(threshold),
                "window": window,
                "evidence_extra": {
                    "service": service,
                    "flow_ids": [f.flow_id for f in flows[:10]],
                    "response_context": (
                        f"{flows_with_response}/{len(flows)} observed flows received a "
                        "reverse-direction response; login outcomes are NOT observable "
                        "from passive capture."
                    ),
                },
            }
    return None

