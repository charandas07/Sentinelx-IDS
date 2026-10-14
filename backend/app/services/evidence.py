"""
Evidence builder for explainable, evidence-linked alerts (SentinelX 2.0).

Every new alert gets a structured evidence document answering:
  which rule fired, observed values vs thresholds, evaluation window,
  relevant endpoints, related flow ids, supporting packet references,
  why the severity was assigned, and what the evidence CANNOT prove.
"""
import json
from datetime import datetime
from typing import List, Optional

from app.config import settings

RULE_VERSION = "2.0"

# Human-readable limitations per attack type: what passive capture cannot prove.
EVIDENCE_LIMITATIONS = {
    "PORT_SCAN": (
        "Passive observation counts distinct destination ports contacted; it cannot "
        "confirm scanner intent or which ports actually responded open/closed without "
        "application-level or firewall feedback."
    ),
    "BRUTE_FORCE": (
        "Repeated connection attempts to an authentication service port are observable, "
        "but encrypted transport does not expose login success/failure. This alert does "
        "NOT confirm successful or failed authentication - only a high rate of connection "
        "attempts consistent with brute-force activity."
    ),
    "SYN_FLOOD": (
        "SYN counts are derived from TCP flags in captured packets. Not every SYN is "
        "malicious (retransmissions, outliers) and full connection state may be unseen if "
        "capture is point-missing or packets were dropped; ratio figures are indicative."
    ),
    "ICMP_FLOOD": (
        "ICMP rate is measured from captured echo packets only; the capture point may not "
        "see all traffic on the path, so absolute rates can be under- or over-stated."
    ),
    "TRAFFIC_SPIKE": (
        "A traffic anomaly relative to the learned baseline is not by itself proof of a "
        "denial-of-service attack; legitimate flash crowds can look similar."
    ),
    "DOS_PATTERN": (
        "Volumetric anomaly across sources; without upstream/flow-accounting data a "
        "confirmed DDoS attribution is not possible from a single capture point."
    ),
}

SEVERITY_RATIONALE = {
    "CRITICAL": "Rule configured severity CRITICAL: high confidence pattern with potential availability impact.",
    "HIGH": "Rule configured severity HIGH: strong indicator of hostile activity requiring investigation.",
    "MEDIUM": "Rule configured severity MEDIUM: anomalous behaviour, possible benign explanation.",
    "LOW": "Rule configured severity LOW: weak indicator, informational.",
    "INFO": "Rule configured severity INFO: recorded for context only.",
}


def build_evidence(
    *,
    attack_type: str,
    observed: dict,
    threshold: float,
    window_seconds: int,
    detection_time: datetime,
    src_ip: str,
    dst_ip: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: Optional[str],
    flow_ids: Optional[List[str]] = None,
    packet_refs: Optional[list] = None,
    severity: str = "HIGH",
    rule_name: Optional[str] = None,
    detection_rule_text: Optional[str] = None,
    provenance: str = "live",
    incident_id: Optional[int] = None,
    flow_stats: Optional[dict] = None,
    extra: Optional[dict] = None,
) -> dict:
    """Assemble the structured evidence document stored on the alert."""
    flow_ids = flow_ids or []
    packet_refs = packet_refs or []
    max_refs = settings.EVIDENCE_MAX_PACKET_REFS

    evidence = {
        "rule": {
            "name": rule_name or attack_type.lower(),
            "attack_type": attack_type,
            "version": RULE_VERSION,
            "statement": detection_rule_text,
        },
        "detected_at": detection_time.isoformat(),
        "evaluation": {
            "observed": observed,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "condition": _condition_text(observed, threshold, window_seconds),
        },
        "endpoints": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        },
        "related_flow_ids": flow_ids[:max_refs],
        "flow_statistics": flow_stats,
        "packet_evidence": {
            "refs": packet_refs[:max_refs],
            "available": bool(packet_refs) or bool(flow_ids),
            "note": (
                "References point to in-memory flow records or PCAP packet indices; "
                "full payload is intentionally not retained."
                if packet_refs or flow_ids else
                "No flow or packet references were available at detection time "
                "(buffers may have expired or tracking was disabled)."
            ),
        },
        "severity": {
            "assigned": severity,
            "rationale": SEVERITY_RATIONALE.get(severity, "Rule-configured severity."),
        },
        "provenance": provenance,   # live | pcap | simulation
        "limitations": EVIDENCE_LIMITATIONS.get(
            attack_type,
            "Rule-based detection from passive capture; conclusions are indicative, not conclusive."
        ),
        "confidence_note": (
            "This is a rule-triggered alert, not a confirmed attack. Verify against "
            "the linked flows/packets and other sources before acting."
        ),
    }
    if incident_id is not None:
        evidence["incident_id"] = incident_id
    if extra:
        evidence["extra"] = extra
    return evidence


def _condition_text(observed: dict, threshold: float, window_seconds: int) -> str:
    """One-line statement of the rule condition that evaluated true."""
    if not observed:
        return f"condition met (threshold={threshold}, window={window_seconds}s)"
    parts = ", ".join(f"{k}={v}" for k, v in observed.items())
    return f"observed[{parts}] exceeded threshold={threshold} within {window_seconds}s"


def dumps(evidence: dict) -> str:
    """Serialize evidence to JSON with a hard size bound (bounded storage)."""
    text = json.dumps(evidence, default=str)
    max_bytes = 16 * 1024   # 16 KB cap per alert evidence document
    if len(text) > max_bytes:
        evidence = dict(evidence)
        evidence["truncated"] = True
        text = json.dumps(evidence, default=str)[:max_bytes]
    return text
