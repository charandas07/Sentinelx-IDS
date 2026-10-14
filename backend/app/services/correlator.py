"""
Temporal Alert Correlation Engine (SentinelX 2.0).

Groups related alerts into incidents using source IP, affected service,
time windows and related flow identifiers. Recognizes multi-stage sequences
(e.g. port probing followed by repeated connection attempts) and maintains
an incident timeline.

Documented ambiguity: sharing a source IP does not prove a single attacker.
NAT gateways, shared hosts, dynamic addressing and spoofing can make
unrelated activity appear correlated. Incidents are *candidate* groupings
for investigation, not attribution claims.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.alert import Alert
from app.models.incident import Incident

logger = logging.getLogger(__name__)

# Classification when specific multi-stage sequences are recognized.
_SEQUENCE_RULES = [
    # (earlier_types, later_types, classification, title)
    ({"PORT_SCAN"}, {"BRUTE_FORCE", "SYN_FLOOD"}, "RECON_THEN_ACCESS",
     "Port probing followed by access attempts"),
    ({"PORT_SCAN"}, {"TRAFFIC_SPIKE", "DOS_PATTERN"}, "RECON_THEN_DOS",
     "Port probing followed by volumetric activity"),
]

_ATTACK_LABEL = {
    "PORT_SCAN": "port scanning",
    "BRUTE_FORCE": "repeated authentication attempts",
    "SYN_FLOOD": "SYN flood",
    "ICMP_FLOOD": "ICMP flood",
    "TRAFFIC_SPIKE": "traffic spike",
    "DOS_PATTERN": "global DoS pattern",
}


def _classify(alert_types: set) -> Tuple[str, str]:
    """Return (classification, title) for a set of attack types."""
    for earlier, later, classification, title in _SEQUENCE_RULES:
        if alert_types & earlier and alert_types & later:
            return classification, title
    if len(alert_types) > 1:
        types = ", ".join(sorted(alert_types))
        return "MULTIPLE_ACTIVITY", f"Correlated activity: {types}"
    only = next(iter(alert_types))
    return only, f"{_ATTACK_LABEL.get(only, only).capitalize()} incident"


async def find_open_incident(db: AsyncSession, src_ip: str,
                             alert_time: datetime,
                             window_seconds: Optional[int] = None) -> Optional[Incident]:
    """Find an existing incident for this source within the time window."""
    window = window_seconds if window_seconds is not None else settings.CORRELATION_WINDOW
    cutoff = alert_time - timedelta(seconds=window)
    result = await db.execute(
        select(Incident)
        .where(Incident.src_ip == src_ip)
        .where(Incident.last_seen >= cutoff)
        .where(Incident.status.in_(["OPEN", "INVESTIGATING"]))
        .order_by(Incident.last_seen.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _load_incident_alerts(db: AsyncSession, incident_id: int) -> List[Alert]:
    result = await db.execute(
        select(Alert)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.timestamp.asc())
        .limit(settings.CORRELATION_MAX_ALERTS_PER_INCIDENT)
    )
    return list(result.scalars().all())


def _build_explanation(incident: Incident, alerts: List[Alert]) -> str:
    """Plain-language explanation of why these alerts were grouped."""
    counts: dict = {}
    for a in alerts:
        counts[a.attack_type] = counts.get(a.attack_type, 0) + 1
    breakdown = ", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
    endpoints = sorted({a.dst_ip for a in alerts if a.dst_ip})
    window = settings.CORRELATION_WINDOW
    parts = [
        f"{len(alerts)} alert(s) from source {incident.src_ip} within a "
        f"{window}s inactivity window (first {incident.first_seen.isoformat()}, "
        f"last {incident.last_seen.isoformat()}).",
        f"Activity mix: {breakdown}.",
    ]
    if endpoints:
        shown = ", ".join(endpoints[:8])
        more = f" (+{len(endpoints) - 8} more)" if len(endpoints) > 8 else ""
        parts.append(f"Affected destinations: {shown}{more}.")
    types = {a.attack_type for a in alerts}
    if "PORT_SCAN" in types and types & {"BRUTE_FORCE", "SYN_FLOOD"}:
        parts.append(
            "Sequence recognized: connection probing preceded repeated access "
            "attempts - consistent with reconnaissance followed by exploitation attempts."
        )
    parts.append(
        "Grouping is by source IP and time proximity only; NAT, shared hosts or "
        "dynamic addressing may mean the alerts did not originate from one host."
    )
    return " ".join(parts)


async def correlate_alert(db: AsyncSession, alert: Alert,
                          flow_ids: Optional[List[str]] = None,
                          broadcast_callback=None) -> Optional[Incident]:
    """Attach an alert to an existing incident or create a new one.

    Returns the incident (updated or created), or None when correlation is
    disabled. The alert row must already be committed (alert.id present).
    """
    if not settings.CORRELATION_ENABLED:
        return None
    if alert.src_ip in ("MULTIPLE", "", None):
        # Global alerts have no single source to correlate on; skip rather
        # than group unrelated sources under one incident.
        return None

    incident = await find_open_incident(db, alert.src_ip, alert.timestamp)
    created = False

    if incident is None:
        classification, title = _classify({alert.attack_type})
        incident = Incident(
            title=title,
            classification=classification,
            status="OPEN",
            severity=alert.severity,
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
            src_ip=alert.src_ip,
            affected_endpoints_json=json.dumps(
                [alert.dst_ip] if alert.dst_ip else []),
            flow_ids_json=json.dumps(flow_ids or []),
            alert_count=0,
            correlation_window=settings.CORRELATION_WINDOW,
            is_simulation=alert.is_simulation,
            provenance=alert.provenance or "live",
        )
        db.add(incident)
        await db.flush()
        created = True
    else:
        if alert.timestamp < incident.first_seen:
            incident.first_seen = alert.timestamp
        if alert.timestamp > incident.last_seen:
            incident.last_seen = alert.timestamp
        # Escalate severity if the new alert is more severe.
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if order.index(alert.severity or "LOW") > order.index(incident.severity or "LOW"):
            incident.severity = alert.severity
        if alert.is_simulation:
            incident.is_simulation = True

    alert.incident_id = incident.id
    incident.alert_count = (incident.alert_count or 0) + 1

    # Merge endpoints and flow ids (bounded).
    try:
        endpoints = json.loads(incident.affected_endpoints_json or "[]")
    except Exception:
        endpoints = []
    if alert.dst_ip and alert.dst_ip not in endpoints and len(endpoints) < 64:
        endpoints.append(alert.dst_ip)
    incident.affected_endpoints_json = json.dumps(endpoints)

    try:
        flow_ids_list = json.loads(incident.flow_ids_json or "[]")
    except Exception:
        flow_ids_list = []
    for fid in (flow_ids or []):
        if fid not in flow_ids_list and len(flow_ids_list) < 64:
            flow_ids_list.append(fid)
    incident.flow_ids_json = json.dumps(flow_ids_list)

    incident_alerts = await _load_incident_alerts(db, incident.id)
    if alert not in incident_alerts:
        incident_alerts.append(alert)
    incident.explanation = _build_explanation(incident, incident_alerts)

    if broadcast_callback:
        try:
            await broadcast_callback("incident", {
                "id": incident.id,
                "title": incident.title,
                "classification": incident.classification,
                "status": incident.status,
                "severity": incident.severity,
                "src_ip": incident.src_ip,
                "alert_count": incident.alert_count,
                "first_seen": incident.first_seen.isoformat(),
                "last_seen": incident.last_seen.isoformat(),
                "created": created,
                "is_simulation": incident.is_simulation,
                "provenance": incident.provenance,
            })
        except Exception as e:  # pragma: no cover - broadcast failures are non-fatal
            logger.debug(f"Incident broadcast failed: {e}")

    return incident

