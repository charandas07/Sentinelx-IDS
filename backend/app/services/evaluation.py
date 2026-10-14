"""
Reproducible IDS Evaluation Framework (SentinelX 2.0).

Compares three detection configurations on identical traffic and identical
ground-truth labels:

  A - Baseline:   independent per-IP threshold rules (flow signals zeroed)
  B - Flow-aware: rules enhanced with bidirectional flow statistics
  C - Proposed:   flow-aware rules + temporal correlation + evidence docs

Counting unit and matching rule (documented, deterministic):
  * Ground truth is a list of labelled time segments. Attack segments carry
    an attack type and (optionally) a source IP; benign segments carry only
    a time range.
  * One true positive (TP) = an attack segment matched by >=1 alert with the
    same attack type whose timestamp falls inside the segment widened by the
    rule window. Additional alerts matching the same segment are counted as
    duplicates (reported separately), NOT as extra TPs.
  * A false negative (FN) = an attack segment with no matching alert.
  * A false positive (FP) = an alert that matches no attack segment.
  * A true negative (TN) = a benign segment that contains no alert.
  * Metrics are undefined (reported as unavailable) when their denominator
    is zero. Incident counts for config C are reported separately from
    alert-level metrics.

Synthetic traffic is generated from a seeded PRNG so runs are reproducible.
Synthetic results are NOT equivalent to real-world validation - this is
stated in every exported report.
"""
import csv
import json
import logging
import os
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from app.config import settings
from app.services.flow_tracker import FlowTracker
from app.services.traffic_processor import TrafficProcessor

logger = logging.getLogger(__name__)

SOFTWARE_VERSION = "2.0.0"

CONFIG_LABELS = {
    "A": "Baseline: independent per-IP threshold rules",
    "B": "Flow-aware detection (bidirectional flow statistics)",
    "C": "Proposed: flow-aware detection + temporal correlation + evidence",
}

_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class VirtualClock:
    """Deterministic epoch-seconds clock for replayed traffic."""

    def __init__(self, start_epoch: float):
        self._epoch = float(start_epoch)

    def __call__(self) -> float:
        return self._epoch

    def advance_to(self, epoch: float):
        if epoch > self._epoch:
            self._epoch = float(epoch)


# ── Synthetic dataset generation ──────────────────────────────────────

BENIGN_PORTS = [80, 443, 53, 8080, 8443]
ATTACK_SCENARIOS = {
    "mixed": ["port_scan", "brute_force", "syn_flood", "icmp_flood"],
    "port_scan": ["port_scan"],
    "brute_force": ["brute_force"],
    "syn_flood": ["syn_flood"],
    "icmp_flood": ["icmp_flood"],
    "benign": [],
}


def generate_synthetic_dataset(
    seed: int = 42,
    duration_s: int = 120,
    scenario: str = "mixed",
    benign_pps: int = 20,
) -> Tuple[list, list]:
    """Generate (packets, ground_truth) for a reproducible synthetic run.

    Packets carry a UTC datetime timestamp. Ground truth is a list of
    labelled segments (see module docstring for the semantics).
    """
    if scenario not in ATTACK_SCENARIOS:
        raise ValueError(f"Unknown scenario '{scenario}'. Options: {sorted(ATTACK_SCENARIOS)}")
    rng = random.Random(seed)
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    packets: list = []
    ground_truth: list = []

    internal = [f"192.168.1.{i}" for i in range(2, 30)]

    # ── Benign background for the whole duration ──────────────────────
    for sec in range(duration_s):
        n = max(1, int(rng.gauss(benign_pps, max(2, benign_pps * 0.15))))
        for _ in range(n):
            ts = t0 + timedelta(seconds=sec, milliseconds=rng.randint(0, 999))
            src = rng.choice(internal)
            dst = rng.choice(internal + ["93.184.216.34", "8.8.8.8", "1.1.1.1"])
            port = rng.choice(BENIGN_PORTS)
            proto = "TCP" if port != 53 else "UDP"
            packets.append({
                "timestamp": ts, "src_ip": src, "dst_ip": dst,
                "src_port": rng.randint(49152, 65535), "dst_port": port,
                "protocol": proto,
                "flags": ("PA" if proto == "TCP" else None),
                "packet_size": rng.randint(64, 1400),
                "is_simulation": True,
            })

    # ── Attack segments spread through the run ────────────────────────
    kinds = ATTACK_SCENARIOS[scenario]
    n_segments = max(1, len(kinds))
    span = max(10, duration_s // (n_segments + 1))
    for idx, kind in enumerate(kinds):
        start_s = 10 + idx * span
        attacker = f"203.0.113.{10 + idx}"
        target = rng.choice(internal)
        if kind == "port_scan":
            end_s = start_s + 8
            for p in range(40):
                ts = t0 + timedelta(seconds=start_s + (p * 0.2))
                packets.append({
                    "timestamp": ts, "src_ip": attacker, "dst_ip": target,
                    "src_port": rng.randint(40000, 50000), "dst_port": 1024 + p * 7,
                    "protocol": "TCP", "flags": "S", "packet_size": 60,
                    "is_simulation": True,
                })
            ground_truth.append({
                "kind": "attack", "attack_type": "PORT_SCAN", "src_ip": attacker,
                "start": (t0 + timedelta(seconds=start_s)).isoformat(),
                "end": (t0 + timedelta(seconds=end_s)).isoformat(),
            })
        elif kind == "brute_force":
            end_s = start_s + 15
            for a in range(16):
                ts = t0 + timedelta(seconds=start_s + a)
                packets.append({
                    "timestamp": ts, "src_ip": attacker, "dst_ip": target,
                    "src_port": rng.randint(40000, 50000), "dst_port": 22,
                    "protocol": "TCP", "flags": "S", "packet_size": 128,
                    "is_simulation": True,
                })
            ground_truth.append({
                "kind": "attack", "attack_type": "BRUTE_FORCE", "src_ip": attacker,
                "start": (t0 + timedelta(seconds=start_s)).isoformat(),
                "end": (t0 + timedelta(seconds=end_s)).isoformat(),
            })
        elif kind == "syn_flood":
            end_s = start_s + 5
            for s in range(130):
                ts = t0 + timedelta(seconds=start_s + s * 0.04)
                packets.append({
                    "timestamp": ts, "src_ip": attacker, "dst_ip": target,
                    "src_port": rng.randint(40000, 50000), "dst_port": 80,
                    "protocol": "TCP", "flags": "S", "packet_size": 60,
                    "is_simulation": True,
                })
            ground_truth.append({
                "kind": "attack", "attack_type": "SYN_FLOOD", "src_ip": attacker,
                "start": (t0 + timedelta(seconds=start_s)).isoformat(),
                "end": (t0 + timedelta(seconds=end_s)).isoformat(),
            })
        elif kind == "icmp_flood":
            end_s = start_s + 5
            for s in range(80):
                ts = t0 + timedelta(seconds=start_s + s * 0.06)
                packets.append({
                    "timestamp": ts, "src_ip": attacker, "dst_ip": target,
                    "src_port": None, "dst_port": None,
                    "protocol": "ICMP", "flags": None, "packet_size": 84,
                    "icmp_type": 8, "icmp_id": 1000 + idx,
                    "is_simulation": True,
                })
            ground_truth.append({
                "kind": "attack", "attack_type": "ICMP_FLOOD", "src_ip": attacker,
                "start": (t0 + timedelta(seconds=start_s)).isoformat(),
                "end": (t0 + timedelta(seconds=end_s)).isoformat(),
            })

    # Benign segments: split the duration into windows, mark those that do
    # NOT overlap any attack segment as benign ground truth (TN units).
    attack_spans = [
        (datetime.fromisoformat(g["start"]), datetime.fromisoformat(g["end"]))
        for g in ground_truth
    ]
    seg_len = 15
    for s in range(0, duration_s, seg_len):
        seg_start = t0 + timedelta(seconds=s)
        seg_end = seg_start + timedelta(seconds=seg_len)
        overlaps = any(seg_start <= a_end and seg_end >= a_start
                       for a_start, a_end in attack_spans)
        if not overlaps:
            ground_truth.append({
                "kind": "benign",
                "start": seg_start.isoformat(),
                "end": seg_end.isoformat(),
            })

    packets.sort(key=lambda p: p["timestamp"])
    return packets, ground_truth


def build_manifest(dataset_id: str, description: str, packets: list,
                   ground_truth: list, source: str = "synthetic",
                   limitations: Optional[list] = None) -> dict:
    """Assemble a dataset manifest (provenance + labels + limitations)."""
    attack_types = sorted({g["attack_type"] for g in ground_truth if g.get("kind") == "attack"})
    default_limits = (
        [
            "Synthetic traffic exercises rule logic deterministically but does not "
            "model real application behaviour, retransmissions or middlebox effects.",
            "Labels are segment-level; individual packets inside an attack segment "
            "are not guaranteed malicious.",
        ] if source == "synthetic" else
        [
            "Ground truth is segment-level unless stated; packets inside an attack "
            "segment are not guaranteed malicious.",
        ]
    )
    return {
        "dataset_id": dataset_id,
        "description": description,
        "source": source,                    # synthetic | pcap
        "capture_type": "simulated" if source == "synthetic" else "offline_pcap",
        "generated_at": datetime.utcnow().isoformat(),
        "packet_count": len(packets),
        "time_range": {
            "start": packets[0]["timestamp"].isoformat() if packets else None,
            "end": packets[-1]["timestamp"].isoformat() if packets else None,
        },
        "label_source": "scenario-constructed" if source == "synthetic" else "manifest",
        "label_granularity": "segment",      # time segments, not per-packet
        "attack_types": attack_types,
        "limitations": limitations or default_limits,
    }



# ── Replay + detection ────────────────────────────────────────────────

def _epoch(dt: datetime) -> float:
    """Epoch seconds for a packet timestamp.

    Naive datetimes are interpreted as UTC so the virtual clock,
    packet timestamps and detection times share one timeline.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc).timestamp()
    return dt.timestamp()


def _alert_time(a: dict) -> Optional[datetime]:
    """Detection timestamp of a replay alert (datetime or None)."""
    ts = a.get("_detected_at") or a.get("timestamp")
    return ts if isinstance(ts, datetime) else None


async def _replay_detect(packets: list, config: str, rules: dict,
                         detect_every_s: float = 1.0) -> Tuple[list, dict]:
    """Replay packets through a detection configuration.

    Returns (alerts, info). Each alert is a plain dict with at least
    attack_type, src_ip, timestamp (datetime) and the evidence fields.

    Config A: baseline - per-IP counters only; a *null* FlowTracker is
    injected so flow-level signals are zero, reproducing the original
    rule behaviour. Config B/C: a real FlowTracker is fed the same packets.
    """
    clock = VirtualClock(_epoch(packets[0]["timestamp"]) - 1.0 if packets else 0.0)
    processor = TrafficProcessor(clock=clock)
    processor.prime_baseline(5.0, samples=30)   # stable synthetic baseline
    tracker = FlowTracker(clock=clock)

    alerts: list = []
    last_detect = clock() - detect_every_s

    for pkt in packets:
        ts = pkt.get("timestamp")
        if isinstance(ts, datetime):
            clock.advance_to(_epoch(ts))
        await processor.process(pkt)
        if config in ("B", "C"):
            tracker.process_packet(pkt)
        if clock() - last_detect >= detect_every_s:
            last_detect = clock()
            alerts.extend(_run_detectors(processor, tracker, config, rules, clock()))

    # Final sweep at end-of-stream so late triggers aren't missed.
    alerts.extend(_run_detectors(processor, tracker, config, rules, clock()))

    # De-duplicate identical (src, type) alerts inside one replay pass; the
    # production engine uses wall-clock cooldowns for this, which do not
    # translate to replay time. Dedup keeps the evaluation deterministic.
    seen = set()
    deduped = []
    for a in alerts:
        key = (a["src_ip"], a["attack_type"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(a)

    info = {
        "packets": len(packets),
        "processor_ips": len(processor.get_all_ips()),
        "flow_stats": tracker.stats(),
    }
    return deduped, info



def _run_detectors(processor, tracker, config: str, rules: dict,
                   now_epoch: float) -> list:
    """Evaluate all detectors once; returns alert dicts (not persisted)."""
    import importlib
    from app.services import evidence as evidence_service

    out = []
    for src_ip in processor.get_all_ips():
        for name, attack_type in (
            ("port_scan", "PORT_SCAN"), ("brute_force", "BRUTE_FORCE"),
            ("syn_flood", "SYN_FLOOD"), ("icmp_flood", "ICMP_FLOOD"),
            ("traffic_anomaly", "TRAFFIC_SPIKE"),
        ):
            mod = importlib.import_module(f"app.detection.{name}")
            rule = rules.get(attack_type)
            if rule and not rule.enabled:
                continue
            # Baseline config A injects a null tracker so flow-enhanced
            # observables read zero, reproducing the original rule logic.
            use_tracker = tracker if config in ("B", "C") else _EMPTY_TRACKER
            try:
                result = mod.check(
                    processor, src_ip,
                    rule_threshold=rule.threshold if rule else None,
                    rule_window=int(rule.time_window) if rule and rule.time_window else None,
                    tracker=use_tracker,
                )
            except TypeError:
                # traffic_anomaly has no tracker parameter
                result = mod.check(
                    processor, src_ip,
                    rule_threshold=rule.threshold if rule else None,
                    rule_window=int(rule.time_window) if rule and rule.time_window else None,
                )
            except Exception as e:
                logger.debug(f"Eval detector {attack_type} error: {e}")
                continue
            if result:
                result["_detected_at_epoch"] = now_epoch
                result["_detected_at"] = datetime.fromtimestamp(
                    now_epoch, tz=timezone.utc)
                if rule:
                    result["severity"] = rule.severity
                if config == "C":
                    result["evidence"] = evidence_service.build_evidence(
                        attack_type=result["attack_type"],
                        observed=result.get("observed", {}),
                        threshold=result.get("threshold", 0),
                        window_seconds=result.get("window", 0),
                        detection_time=result["_detected_at"],
                        src_ip=src_ip,
                        dst_ip=result.get("dst_ip"),
                        src_port=result.get("src_port"),
                        dst_port=result.get("dst_port"),
                        protocol=result.get("protocol"),
                        severity=result.get("severity", "HIGH"),
                        detection_rule_text=result.get("detection_rule"),
                        provenance="simulation",
                        extra=result.get("evidence_extra"),
                    )
                out.append(result)
    return out


class _NullFlowTracker:
    """Tracker stand-in that reports no flow data (baseline config A)."""

    def scan_summary(self, *a, **kw):
        return {"distinct_ports": 0, "distinct_hosts": 0, "attempts": 0,
                "window_seconds": kw.get("window_seconds", 0),
                "ports_sample": [], "hosts_sample": []}

    def flows_for_ip(self, *a, **kw):
        return []

    def associated_flows(self, *a, **kw):
        return []


_EMPTY_TRACKER = _NullFlowTracker()



# ── Metrics ───────────────────────────────────────────────────────────

def _safe_div(num: float, den: float) -> Optional[float]:
    return (num / den) if den else None


def compute_metrics(alerts: list, ground_truth: list,
                    incidents: Optional[list] = None,
                    processing_seconds: Optional[float] = None,
                    packet_count: Optional[int] = None) -> dict:
    """Alert-level metrics against segment ground truth.

    Each attack segment is widened by its rule window (the
    largest window in the ground truth when a segment carries
    none, default 30s) so detections landing slightly outside
    the segment still count as matches. Undefined metrics
    (zero denominators) are returned as None, never 0.
    """
    attack_segments = [g for g in ground_truth if g.get("kind") == "attack"]
    benign_segments = [g for g in ground_truth if g.get("kind") == "benign"]

    max_window = max((int(g.get("window", 30)) for g in ground_truth),
                     default=30)

    def widened_bounds(seg: dict) -> Tuple[datetime, datetime]:
        tol = int(seg.get("window", max_window))
        return (datetime.fromisoformat(seg["start"]) - timedelta(seconds=tol),
                datetime.fromisoformat(seg["end"]) + timedelta(seconds=tol))

    def matches(a: dict, seg: dict,
                bounds: Tuple[datetime, datetime]) -> bool:
        if a["attack_type"] != seg["attack_type"]:
            return False
        if seg.get("src_ip") and a["src_ip"] not in (seg["src_ip"], "MULTIPLE"):
            return False
        ts = _alert_time(a)
        return ts is not None and bounds[0] <= ts <= bounds[1]

    attack_bounds = [(seg, widened_bounds(seg)) for seg in attack_segments]

    tp = 0
    fn = 0
    duplicates = 0
    latencies: list = []

    for seg, bounds in attack_bounds:
        candidates = [a for a in alerts if matches(a, seg, bounds)]
        if candidates:
            tp += 1
            seg_start = datetime.fromisoformat(seg["start"])
            first = min(candidates, key=_alert_time)
            det = _alert_time(first)
            if det is not None:
                latencies.append(max(0.0, (det - seg_start).total_seconds()))
            # Alerts beyond the first match on the same segment are
            # duplicates, not extra true positives.
            duplicates += len(candidates) - 1
        else:
            fn += 1

    fp = sum(
        1 for a in alerts
        if not any(matches(a, seg, bounds) for seg, bounds in attack_bounds)
    )

    tn = 0
    for seg in benign_segments:
        seg_start = datetime.fromisoformat(seg["start"])
        seg_end = datetime.fromisoformat(seg["end"])
        covered = False
        for a in alerts:
            ts = _alert_time(a)
            if ts is not None and seg_start <= ts <= seg_end:
                covered = True
                break
        if not covered:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = ((2 * precision * recall) / (precision + recall)
          if precision is not None and recall is not None
          and (precision + recall) else None)
    fpr = _safe_div(fp, fp + tn)

    notes = []
    if precision is None:
        notes.append("precision undefined: no predicted positives (TP+FP=0)")
    if recall is None:
        notes.append("recall undefined: no positive ground-truth segments")
    if fpr is None:
        notes.append("false-positive rate undefined: no evaluable benign segments")

    evidence_total = len(alerts)
    evidence_present = sum(1 for a in alerts if a.get("evidence"))
    throughput_pps = (packet_count / processing_seconds
                      if processing_seconds and packet_count is not None
                      else None)

    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "detection_latencies_s": [round(x, 2) for x in latencies],
        "mean_detection_latency_s": (round(sum(latencies) / len(latencies), 2)
                                     if latencies else None),
        "throughput_pps": (round(throughput_pps, 1)
                           if throughput_pps is not None else None),
        "processing_seconds": (round(processing_seconds, 3)
                               if processing_seconds is not None else None),
        "raw_alerts": len(alerts),
        "correlated_incidents": len(incidents) if incidents is not None else None,
        "duplicate_alerts": duplicates,
        "evidence_completeness": (round(evidence_present / evidence_total, 3)
                                   if evidence_total else None),
        "notes": notes,
    }


# ── Incident correlation (in memory) ────────────────────────

def _build_incident(batch: list) -> dict:
    """Incident record for one group of temporally correlated alerts."""
    from app.services.correlator import _classify

    counts: dict = {}
    for a in batch:
        counts[a["attack_type"]] = counts.get(a["attack_type"], 0) + 1
    types = set(counts)
    classification, title = _classify(types)
    times = [_alert_time(a) for a in batch]
    severity = max(
        (a.get("severity") or "LOW" for a in batch),
        key=lambda s: _SEV_ORDER.get(s, 0),
    )
    breakdown = ", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
    return {
        "classification": classification,
        "title": title,
        "status": "OPEN",
        "severity": severity,
        "src_ip": batch[0]["src_ip"],
        "first_seen": min(times).isoformat(),
        "last_seen": max(times).isoformat(),
        "alert_count": len(batch),
        "attack_types": sorted(types),
        "affected_dst_ips": sorted({a["dst_ip"] for a in batch
                                    if a.get("dst_ip")}),
        "all_alerts_have_evidence": all(bool(a.get("evidence"))
                                        for a in batch),
        "explanation": (
            f"{len(batch)} alert(s) from source {batch[0]['src_ip']} "
            f"within a {settings.CORRELATION_WINDOW}s inactivity window. "
            f"Activity mix: {breakdown}. Grouping is by source IP and "
            "time proximity only; NAT, shared hosts or dynamic "
            "addressing may mean the alerts did not originate from "
            "one host."
        ),
    }


def _correlate_alerts(alerts: list) -> list:
    """Group alerts into incidents using the production correlator's
    semantics: alerts from the same source within CORRELATION_WINDOW
    of the incident's last-seen time join the open incident.

    Classification reuses the correlator's rules over the group's
    full attack-type set. Computed in memory only - the harness
    does not persist incidents.
    """
    by_src: dict = {}
    for a in alerts:
        src = a.get("src_ip")
        if src in ("MULTIPLE", "", None):
            # Global alerts have no single source to correlate on.
            continue
        by_src.setdefault(src, []).append(a)

    incidents = []
    for src in sorted(by_src):
        items = [a for a in by_src[src] if _alert_time(a) is not None]
        items.sort(key=_alert_time)
        batch: list = []
        last_seen = None
        for a in items:
            ts = _alert_time(a)
            if batch and (ts - last_seen).total_seconds() > settings.CORRELATION_WINDOW:
                incidents.append(_build_incident(batch))
                batch = []
            batch.append(a)
            last_seen = ts
        if batch:
            incidents.append(_build_incident(batch))
    return incidents


# ── Comparison runner ───────────────────────────────────────

class _DefaultRule:
    """Rule stand-in exposing DetectionRule's attribute interface."""

    def __init__(self, name: str, attack_type: str, threshold: float,
                 time_window: int, severity: str = "HIGH",
                 enabled: bool = True,
                 recommended_action: Optional[str] = None):
        self.name = name
        self.attack_type = attack_type
        self.threshold = threshold
        self.time_window = time_window
        self.severity = severity
        self.enabled = enabled
        self.recommended_action = recommended_action


def default_rules() -> dict:
    """Rule set mirroring seed.DEFAULT_RULES, driven by settings."""
    specs = [
        ("port_scan", "PORT_SCAN", settings.PORT_SCAN_THRESHOLD,
         settings.PORT_SCAN_WINDOW, "HIGH"),
        ("brute_force", "BRUTE_FORCE", settings.BRUTE_FORCE_THRESHOLD,
         settings.BRUTE_FORCE_WINDOW, "HIGH"),
        ("syn_flood", "SYN_FLOOD", settings.SYN_FLOOD_THRESHOLD,
         settings.SYN_FLOOD_WINDOW, "CRITICAL"),
        ("icmp_flood", "ICMP_FLOOD", settings.ICMP_FLOOD_THRESHOLD,
         settings.ICMP_FLOOD_WINDOW, "HIGH"),
        ("traffic_spike", "TRAFFIC_SPIKE", settings.TRAFFIC_SPIKE_MULTIPLIER,
         10, "MEDIUM"),
    ]
    return {attack_type: _DefaultRule(name, attack_type, threshold,
                                      time_window, severity)
            for name, attack_type, threshold, time_window, severity in specs}


def _serialize_alert(a: dict) -> dict:
    """Public view of a replay alert (ISO timestamps, no internals)."""
    out = {k: v for k, v in a.items() if not k.startswith("_")}
    det = _alert_time(a)
    if det is not None:
        out["detected_at"] = det.isoformat()
    return out


def _rule_config_summary(rules: dict) -> dict:
    return {
        attack_type: {
            "name": getattr(r, "name", attack_type.lower()),
            "enabled": bool(getattr(r, "enabled", True)),
            "threshold": getattr(r, "threshold", None),
            "time_window": getattr(r, "time_window", None),
            "severity": getattr(r, "severity", None),
        }
        for attack_type, r in rules.items()
    }


async def run_evaluation(
    seed: int = 42,
    duration_s: int = 120,
    scenario: str = "mixed",
    benign_pps: int = 20,
    configs: Tuple[str, ...] = ("A", "B", "C"),
    rules: Optional[dict] = None,
    detect_every_s: float = 1.0,
) -> dict:
    """Run the full configuration comparison on one synthetic dataset.

    `rules` maps attack_type -> rule objects with the DetectionRule
    attribute interface (as loaded from the database by the detection
    engine); when None, defaults mirroring seed.DEFAULT_RULES apply.

    Every configuration replays the identical packet list, so
    differences in the reported metrics are attributable to the
    configuration alone. Returns an EvaluationRunResponse-shaped
    dict. Synthetic results are not real-world validation - the
    returned report carries the limitations verbatim.
    """
    started_at = datetime.utcnow()

    packets, ground_truth = generate_synthetic_dataset(
        seed=seed, duration_s=duration_s, scenario=scenario,
        benign_pps=benign_pps)
    manifest = build_manifest(
        dataset_id=f"synthetic-{scenario}-{duration_s}s-seed{seed}",
        description=(f"Synthetic '{scenario}' scenario: {duration_s}s, "
                     f"seed={seed}, ~{benign_pps} benign pps"),
        packets=packets, ground_truth=ground_truth, source="synthetic")

    rule_map = rules if rules is not None else default_rules()

    config_results: list = []
    for config in configs:
        if config not in CONFIG_LABELS:
            raise ValueError(
                f"Unknown config '{config}'. Options: {sorted(CONFIG_LABELS)}")
        replay_start = time.perf_counter()
        alerts, info = await _replay_detect(
            packets, config, rule_map, detect_every_s=detect_every_s)
        processing_seconds = time.perf_counter() - replay_start

        incidents = _correlate_alerts(alerts)
        metrics = compute_metrics(
            alerts, ground_truth, incidents=incidents,
            processing_seconds=processing_seconds,
            packet_count=len(packets))
        config_results.append({
            "config": config,
            "label": CONFIG_LABELS[config],
            "metrics": metrics,
            "alerts": [_serialize_alert(a) for a in alerts],
            "incidents": incidents,
            "replay_info": info,
        })

    return {
        "run_id": str(uuid.uuid4()),
        "dataset": manifest,
        "configs": config_results,
        "started_at": started_at,
        "finished_at": datetime.utcnow(),
        "software_version": SOFTWARE_VERSION,
        "rule_config": _rule_config_summary(rule_map),
        "limitations": manifest["limitations"] + [
            "Synthetic dataset: results exercise rule logic "
            "deterministically and are not a substitute for labelled "
            "real-world validation.",
            "Incident correlation is computed in memory with the "
            "production grouping semantics; no incidents are persisted.",
        ],
    }


# ── Report export ───────────────────────────────────────────

_CSV_FIELDS = [
    "config", "true_positives", "false_positives", "true_negatives",
    "false_negatives", "precision", "recall", "f1", "false_positive_rate",
    "mean_detection_latency_s", "throughput_pps", "processing_seconds",
    "raw_alerts", "correlated_incidents", "duplicate_alerts",
    "evidence_completeness",
]


def export_report(run_result: dict,
                  directory: str = "data/eval_reports") -> dict:
    """Persist a run result as JSON plus a CSV metrics table.

    Returns the written file paths.
    """
    os.makedirs(directory, exist_ok=True)
    run_id = str(run_result.get("run_id", "run"))
    json_path = os.path.join(directory, f"{run_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(run_result, f, indent=2, default=str)

    csv_path = os.path.join(directory, f"{run_id}_metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS,
                                extrasaction="ignore")
        writer.writeheader()
        for c in run_result.get("configs", []):
            row = {"config": c.get("config")}
            row.update(c.get("metrics") or {})
            writer.writerow(row)
    return {"json": json_path, "csv": csv_path}


