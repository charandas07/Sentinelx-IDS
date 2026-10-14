"""Traffic Anomaly / Traffic Spike / DoS Pattern Detector.
Uses a median baseline computed over a warm-up window.
Alerts are suppressed until warm-up completes and samples taken
during active alert periods are excluded from the baseline.
"""
from typing import Optional
from app.config import settings
from app.services.traffic_processor import TrafficProcessor


def check(
    processor: TrafficProcessor,
    src_ip: str,
    rule_threshold: Optional[float] = None,
    rule_window: Optional[int] = None,
) -> Optional[dict]:
    """Return alert if abnormal traffic volume detected from an IP."""
    # Never alert on whitelisted IPs
    if processor.is_whitelisted(src_ip):
        return None

    # Require warm-up to be complete before alerting
    if not processor.is_warmup_done():
        return None

    multiplier = rule_threshold or settings.TRAFFIC_SPIKE_MULTIPLIER
    window = int(rule_window or 10)

    counter = processor.get_counter(src_ip)
    baseline = processor.get_baseline_pps()
    current_pps = counter.pps(window)

    # Need at least a meaningful baseline before alerting
    if baseline < 5:
        return None

    if current_pps > baseline * multiplier:
        return {
            "attack_type": "TRAFFIC_SPIKE",
            "severity": "MEDIUM",
            "src_ip": src_ip,
            "protocol": "MIXED",
            "packet_count": int(current_pps * window),
            "connection_count": counter.count_in_window(window),
            "detection_rule": (
                f"traffic_spike: {current_pps:.1f} pps vs baseline "
                f"{baseline:.1f} pps (multiplier={multiplier}x)"
            ),
            "recommended_action": (
                f"Investigate {src_ip} for DoS intent. Monitor for escalation."
            ),
            "details": (
                f"Traffic spike: {current_pps:.1f} pps from {src_ip} "
                f"(baseline={baseline:.1f}, ratio={current_pps/baseline:.1f}x)"
            ),
            "observed": {
                "current_pps": round(current_pps, 2),
                "baseline_pps": round(baseline, 2),
                "ratio": round(current_pps / baseline, 2),
                "packet_count": counter.count_in_window(window),
            },
            "threshold": float(multiplier),
            "window": window,
            "evidence_extra": {
                "note": (
                    "Anomaly relative to learned baseline; not proof of denial of "
                    "service. Baseline excludes samples taken during active alerts."
                ),
            },
        }
    return None


def check_global_spike(
    processor: TrafficProcessor,
    current_pps: float,
) -> Optional[dict]:
    """Check if global traffic volume is anomalous (DoS from multiple sources)."""
    # Require warm-up
    if not processor.is_warmup_done():
        return None

    baseline = processor.get_baseline_pps()
    if baseline < 5:
        return None
    if current_pps > baseline * settings.TRAFFIC_SPIKE_MULTIPLIER * 2:
        return {
            "attack_type": "DOS_PATTERN",
            "severity": "CRITICAL",
            "src_ip": "MULTIPLE",
            "protocol": "MIXED",
            "packet_count": int(current_pps),
            "connection_count": len(processor.get_all_ips()),
            "detection_rule": (
                f"dos_pattern: global {current_pps:.1f} pps vs baseline {baseline:.1f} pps"
            ),
            "recommended_action": (
                "Possible volumetric DDoS. Contact ISP, enable upstream filtering."
            ),
            "details": (
                f"Global traffic anomaly: {current_pps:.1f} pps "
                f"(baseline={baseline:.1f} pps)"
            ),
            "observed": {
                "global_pps": round(current_pps, 2),
                "baseline_pps": round(baseline, 2),
                "ratio": round(current_pps / baseline, 2),
                "active_sources": len(processor.get_all_ips()),
            },
            "threshold": float(settings.TRAFFIC_SPIKE_MULTIPLIER * 2),
            "window": 10,
            "evidence_extra": {
                "note": (
                    "Global volumetric anomaly; a single capture point cannot "
                    "confirm distributed attribution."
                ),
            },
        }
    return None
