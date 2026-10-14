"""SYN Flood Detector.

Flow-aware upgrade (SentinelX 2.0): compares forward SYN counts against
reverse ACK observations in related flows where available. Because passive
capture cannot guarantee it sees the complete connection state (capture
point may miss return paths), the SYN/ACK ratio is reported as *indicative*
evidence, not proof that SYNs went unanswered.
"""
from typing import Optional
from app.config import settings
from app.services.traffic_processor import TrafficProcessor
from app.services.flow_tracker import flow_tracker


def check(processor: TrafficProcessor, src_ip: str, rule_threshold: Optional[float] = None, rule_window: Optional[int] = None, tracker=None) -> Optional[dict]:
    """Return alert if SYN flood detected."""
    threshold = int(rule_threshold or settings.SYN_FLOOD_THRESHOLD)
    window = int(rule_window or settings.SYN_FLOOD_WINDOW)

    counter = processor.get_counter(src_ip)
    syn_count = counter.syn_count_in_window(window)

    if syn_count >= threshold:
        total = counter.count_in_window(window)
        ratio = syn_count / max(total, 1)

        # Flow-aware context: SYN packets vs reverse ACKs observed on flows
        # opened by this source.
        flows = (tracker or flow_tracker).flows_for_ip(src_ip)
        fwd_syn = sum(f.syn_count for f in flows)
        rev_ack = sum(f.rev_ack_count for f in flows)
        ack_ratio = rev_ack / max(fwd_syn, 1)

        return {
            "attack_type": "SYN_FLOOD",
            "severity": "CRITICAL",
            "src_ip": src_ip,
            "protocol": "TCP",
            "packet_count": syn_count,
            "connection_count": total,
            "detection_rule": f"syn_flood: {syn_count} SYN packets in {window}s (threshold={threshold}, ratio={ratio:.1%})",
            "recommended_action": f"Enable SYN cookies, rate-limit {src_ip}, contact upstream provider.",
            "details": f"SYN flood: {syn_count} SYN packets ({ratio:.1%} of traffic) in {window}s",
            "observed": {
                "syn_count": syn_count,
                "total_packets": total,
                "syn_ratio": round(ratio, 4),
                "flow_fwd_syn": fwd_syn,
                "flow_rev_ack": rev_ack,
                "ack_syn_ratio": round(ack_ratio, 4),
            },
            "threshold": float(threshold),
            "window": window,
            "evidence_extra": {
                "flow_ids": [f.flow_id for f in flows[:10]],
                "completeness_note": (
                    f"Reverse ACKs observed for {rev_ack} of {fwd_syn} forward SYNs on "
                    "tracked flows; capture point coverage may be partial, so unanswered "
                    "SYNs cannot be conclusively established."
                ),
            },
        }
    return None

