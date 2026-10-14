"""ICMP Flood Detector.

Flow-aware upgrade (SentinelX 2.0): separates echo requests from echo
replies using flow-level ICMP type accounting, so reply traffic from the
target is visible in the evidence and request/response imbalance can be
reported.
"""
from typing import Optional
from app.config import settings
from app.services.traffic_processor import TrafficProcessor
from app.services.flow_tracker import flow_tracker


def check(processor: TrafficProcessor, src_ip: str, rule_threshold: Optional[float] = None, rule_window: Optional[int] = None, tracker=None) -> Optional[dict]:
    """Return alert if ICMP flood detected."""
    threshold = int(rule_threshold or settings.ICMP_FLOOD_THRESHOLD)
    window = int(rule_window or settings.ICMP_FLOOD_WINDOW)

    counter = processor.get_counter(src_ip)
    icmp_count = counter.icmp_count_in_window(window)

    if icmp_count >= threshold:
        # Flow-aware context: request/response split from ICMP flows.
        icmp_flows = [f for f in (tracker or flow_tracker).flows_for_ip(src_ip)
                      if f.transport == "ICMP"]
        requests = sum(f.icmp_requests for f in icmp_flows)
        responses = sum(f.icmp_responses for f in icmp_flows)
        return {
            "attack_type": "ICMP_FLOOD",
            "severity": "HIGH",
            "src_ip": src_ip,
            "protocol": "ICMP",
            "packet_count": icmp_count,
            "connection_count": icmp_count,
            "detection_rule": f"icmp_flood: {icmp_count} ICMP packets in {window}s (threshold={threshold})",
            "recommended_action": f"Rate-limit ICMP from {src_ip}, consider blocking if persistent.",
            "details": f"ICMP flood: {icmp_count} ICMP packets received in {window}s from {src_ip}",
            "observed": {
                "icmp_packets": icmp_count,
                "echo_requests": requests,
                "echo_replies": responses,
            },
            "threshold": float(threshold),
            "window": window,
            "evidence_extra": {
                "flow_ids": [f.flow_id for f in icmp_flows[:10]],
                "request_response_note": (
                    f"{requests} echo requests vs {responses} echo replies observed on "
                    "tracked ICMP flows for this source."
                ),
            },
        }
    return None

