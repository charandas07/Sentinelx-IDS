"""
Detection Engine Orchestrator
Runs all detectors against packet data and persists alerts to DB.
"""
import asyncio
import logging
from datetime import datetime
from typing import List, Optional, Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.detection import port_scan, brute_force, syn_flood, icmp_flood, traffic_anomaly
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.ip_stats import IPStatistics
from app.services.traffic_processor import TrafficProcessor, traffic_processor
from app.services.flow_tracker import flow_tracker
from app.services import evidence as evidence_service
from app.services.threat_scorer import compute_threat_score

logger = logging.getLogger(__name__)

# Cooldown: don't re-alert same IP + attack_type within N seconds
_alert_cooldowns: dict = {}   # (src_ip, attack_type) -> last_alert_timestamp
COOLDOWN_SECONDS = 30


def _is_on_cooldown(src_ip: str, attack_type: str) -> bool:
    key = (src_ip, attack_type)
    last = _alert_cooldowns.get(key)
    if last is None:
        return False
    return (datetime.utcnow() - last).total_seconds() < COOLDOWN_SECONDS


def _set_cooldown(src_ip: str, attack_type: str):
    _alert_cooldowns[(src_ip, attack_type)] = datetime.utcnow()


def clear_cooldowns(ips: Optional[Set[str]] = None):
    """Clear cooldowns for given IPs (or all if ips is None)."""
    global _alert_cooldowns
    if ips is None:
        _alert_cooldowns.clear()
    else:
        _alert_cooldowns = {k: v for k, v in _alert_cooldowns.items() if k[0] not in ips}


async def _get_rules(db: AsyncSession) -> dict:
    """Load detection rules config from DB keyed by attack_type."""
    result = await db.execute(select(DetectionRule))
    rules = result.scalars().all()
    return {r.attack_type: r for r in rules}


async def run_detection(
    db: AsyncSession,
    processor: TrafficProcessor,
    is_simulation: bool = False,
    broadcast_callback=None,
) -> List[Alert]:
    """Run all detectors across all tracked IPs. Returns new alerts."""
    rules = await _get_rules(db)
    new_alerts: List[Alert] = []

    ips = processor.get_all_ips()
    processor.evict_idle(300)

    # Prune alert cooldowns older than COOLDOWN_SECONDS
    now = datetime.utcnow()
    expired = [k for k, ts in _alert_cooldowns.items() if (now - ts).total_seconds() > COOLDOWN_SECONDS]
    for k in expired:
        del _alert_cooldowns[k]

    # Global spike check
    global_spike_alert = None
    pending_cooldowns: List[tuple] = []   # set only after a successful commit
    if not _is_on_cooldown("MULTIPLE", "DOS_PATTERN"):
        current_pps = sum(processor.get_counter(ip).pps(10) for ip in ips) # Approximation of current pps over 10s
        global_result = traffic_anomaly.check_global_spike(processor, current_pps)
        if global_result:
            pending_cooldowns.append(("MULTIPLE", "DOS_PATTERN"))
            threat_score = 90.0
            _det_time = datetime.utcnow()
            global_spike_alert = Alert(
                timestamp=_det_time,
                attack_type=global_result["attack_type"],
                severity=global_result["severity"],
                src_ip="MULTIPLE",
                protocol=global_result.get("protocol"),
                packet_count=global_result.get("packet_count", 0),
                connection_count=global_result.get("connection_count", 0),
                threat_score=threat_score,
                detection_rule=global_result.get("detection_rule"),
                recommended_action=global_result.get("recommended_action"),
                details=global_result.get("details"),
                is_simulation=is_simulation,
                provenance="simulation" if is_simulation else "live",
                rule_version=evidence_service.RULE_VERSION,
                evidence_json=evidence_service.dumps(evidence_service.build_evidence(
                    attack_type=global_result["attack_type"],
                    observed=global_result.get("observed", {}),
                    threshold=global_result.get("threshold", settings.TRAFFIC_SPIKE_MULTIPLIER * 2),
                    window_seconds=global_result.get("window", 10),
                    detection_time=_det_time,
                    src_ip="MULTIPLE",
                    dst_ip=None,
                    src_port=None,
                    dst_port=None,
                    protocol=global_result.get("protocol"),
                    severity=global_result["severity"],
                    rule_name="dos_pattern",
                    detection_rule_text=global_result.get("detection_rule"),
                    provenance="simulation" if is_simulation else "live",
                    extra=global_result.get("evidence_extra"),
                )),
            )
            db.add(global_spike_alert)
            new_alerts.append(global_spike_alert)

    for src_ip in ips:
        detectors = [
            (port_scan, "PORT_SCAN"),
            (brute_force, "BRUTE_FORCE"),
            (syn_flood, "SYN_FLOOD"),
            (icmp_flood, "ICMP_FLOOD"),
            (traffic_anomaly, "TRAFFIC_SPIKE"),
        ]
        for detector_module, attack_type in detectors:
            rule = rules.get(attack_type)
            if rule and not rule.enabled:
                continue
            if _is_on_cooldown(src_ip, attack_type):
                continue

            try:
                result = detector_module.check(
                    processor,
                    src_ip,
                    rule_threshold=rule.threshold if rule else None,
                    rule_window=int(rule.time_window) if rule and rule.time_window else None,
                )
            except Exception as e:
                logger.debug(f"Detector {attack_type} error for {src_ip}: {e}")
                continue

            if result:
                pending_cooldowns.append((src_ip, attack_type))
                # Override severity from rule if configured
                if rule:
                    result["severity"] = rule.severity
                    result["recommended_action"] = rule.recommended_action or result.get("recommended_action")

                threat_score = await compute_threat_score(db, src_ip, result["attack_type"])

                # ── SentinelX 2.0: link flow evidence ──────────────────
                ev_extra = result.get("evidence_extra") or {}
                try:
                    related_flow_ids = list(ev_extra.get("flow_ids") or [])
                    if not related_flow_ids:
                        related_flow_ids = flow_tracker.associated_flows(
                            src_ip, result.get("dst_ip"))
                    primary_flow_id = related_flow_ids[0] if related_flow_ids else None
                    packet_refs = []
                    flow_stats = None
                    if primary_flow_id:
                        f_rec = flow_tracker.get(primary_flow_id)
                        if f_rec is not None:
                            packet_refs = list(f_rec.packet_refs)
                            flow_stats = f_rec.to_dict()
                except Exception:
                    related_flow_ids, primary_flow_id, packet_refs, flow_stats = [], None, [], None

                _det_time = datetime.utcnow()
                is_sim_alert = src_ip in processor.sim_ips
                evidence_doc = evidence_service.build_evidence(
                    attack_type=result["attack_type"],
                    observed=result.get("observed", {}),
                    threshold=result.get("threshold", 0),
                    window_seconds=result.get("window", 0),
                    detection_time=_det_time,
                    src_ip=src_ip,
                    dst_ip=result.get("dst_ip"),
                    src_port=result.get("src_port"),
                    dst_port=result.get("dst_port"),
                    protocol=result.get("protocol"),
                    flow_ids=related_flow_ids,
                    packet_refs=packet_refs,
                    severity=result["severity"],
                    rule_name=(rule.name if rule else result["attack_type"].lower()),
                    detection_rule_text=result.get("detection_rule"),
                    provenance="simulation" if is_sim_alert else "live",
                    flow_stats=flow_stats,
                    extra={k: v for k, v in ev_extra.items() if k != "flow_ids"},
                )
                alert = Alert(
                    timestamp=_det_time,
                    attack_type=result["attack_type"],
                    severity=result["severity"],
                    src_ip=src_ip,
                    dst_ip=result.get("dst_ip"),
                    src_port=result.get("src_port"),
                    dst_port=result.get("dst_port"),
                    protocol=result.get("protocol"),
                    packet_count=result.get("packet_count", 0),
                    connection_count=result.get("connection_count", 0),
                    threat_score=threat_score,
                    detection_rule=result.get("detection_rule"),
                    recommended_action=result.get("recommended_action"),
                    details=result.get("details"),
                    is_simulation=is_sim_alert,
                    provenance="simulation" if is_sim_alert else "live",
                    flow_id=primary_flow_id,
                    rule_version=evidence_service.RULE_VERSION,
                    evidence_json=evidence_service.dumps(evidence_doc),
                )
                db.add(alert)
                new_alerts.append(alert)

                # Update IP stats
                await _update_ip_stats(db, src_ip, threat_score)

    if new_alerts:
        processor.set_alert_active(True)
        try:
            await db.commit()
        except Exception as e:
            # Failed commit: roll back and do NOT set cooldowns so the
            # detection can be retried on the next cycle instead of being
            # silently suppressed for COOLDOWN_SECONDS.
            logger.error(f"Alert commit failed, will retry next cycle: {e}")
            try:
                await db.rollback()
            except Exception:
                pass
            return []
        # Cooldowns are only armed once the alerts are durably stored.
        for key in pending_cooldowns:
            _set_cooldown(*key)
        # ── SentinelX 2.0: temporal correlation into incidents ─────────
        # Runs after commit so incidents reference durable alert ids.
        try:
            from app.services import correlator
            for a in new_alerts:
                incident = await correlator.correlate_alert(
                    db, a,
                    flow_ids=[a.flow_id] if a.flow_id else [],
                    broadcast_callback=broadcast_callback,
                )
                if incident is not None:
                    # Record the incident id inside the alert's evidence doc.
                    try:
                        import json as _json
                        ev = _json.loads(a.evidence_json) if a.evidence_json else {}
                        ev["incident_id"] = incident.id
                        a.evidence_json = evidence_service.dumps(ev)
                    except Exception:
                        pass
            await db.commit()
        except Exception as e:
            logger.error(f"Incident correlation failed (alerts remain valid): {e}")
            try:
                await db.rollback()
            except Exception:
                pass
        for a in new_alerts:
            await db.refresh(a)
            if broadcast_callback:
                await broadcast_callback("alert", {
                    "id": a.id,
                    "attack_type": a.attack_type,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "protocol": a.protocol,
                    "threat_score": a.threat_score,
                    "timestamp": a.timestamp.isoformat(),
                    "is_simulation": a.is_simulation,
                })
                await broadcast_callback("notification", {
                    "title": f"🚨 {a.severity} ALERT",
                    "message": f"{a.attack_type.replace('_', ' ')} detected from {a.src_ip}",
                    "src_ip": a.src_ip,
                    "threat_score": a.threat_score,
                    "severity": a.severity,
                    "is_simulation": a.is_simulation,
                })
    else:
        processor.set_alert_active(False)

    return new_alerts


async def _update_ip_stats(db: AsyncSession, ip: str, threat_score: float):
    """Upsert IPStatistics record."""
    result = await db.execute(select(IPStatistics).where(IPStatistics.ip == ip))
    stats = result.scalar_one_or_none()
    counter = traffic_processor.get_counter(ip)
    if stats is None:
        stats = IPStatistics(
            ip=ip,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            packet_count=counter.count_in_window(300),
            connection_count=counter.count_in_window(300),
            threat_score=threat_score,
            alert_count=1,
            unique_ports_accessed=counter.unique_ports_in_window(300),
        )
        db.add(stats)
    else:
        stats.last_seen = datetime.utcnow()
        stats.threat_score = max(stats.threat_score, threat_score)
        stats.alert_count = (stats.alert_count or 0) + 1
        stats.unique_ports_accessed = counter.unique_ports_in_window(300)
