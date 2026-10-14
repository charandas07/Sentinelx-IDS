"""
Threat Scorer
Computes a 0–100 threat score for an IP based on historical activity.
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.alert import Alert
from app.models.ip_stats import IPStatistics

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 1,
}

ATTACK_TYPE_WEIGHTS = {
    "SYN_FLOOD": 1.5,
    "DOS_PATTERN": 1.8,
    "ICMP_FLOOD": 1.2,
    "PORT_SCAN": 1.0,
    "BRUTE_FORCE": 1.3,
    "TRAFFIC_SPIKE": 1.1,
}


async def compute_threat_score(db: AsyncSession, ip: str, current_attack_type: str) -> float:
    """Compute threat score 0–100 for a given IP."""
    try:
        # Count alerts by severity for this IP
        result = await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.src_ip == ip)
            .group_by(Alert.severity)
        )
        severity_counts = dict(result.all())

        score = 0.0
        for severity, count in severity_counts.items():
            w = SEVERITY_WEIGHTS.get(severity, 1)
            score += w * min(count, 10)  # cap at 10 per severity

        # Boost for current attack type
        attack_boost = ATTACK_TYPE_WEIGHTS.get(current_attack_type, 1.0)
        score *= attack_boost

        # Fetch IP stats for port diversity and connection rate
        stats_result = await db.execute(select(IPStatistics).where(IPStatistics.ip == ip))
        stats = stats_result.scalar_one_or_none()
        if stats:
            # Port diversity bonus
            if stats.unique_ports_accessed > 50:
                score += 15
            elif stats.unique_ports_accessed > 20:
                score += 8
            # Repeated alert bonus
            if stats.alert_count > 20:
                score += 10
            elif stats.alert_count > 5:
                score += 5

        return round(min(score, 100.0), 1)
    except Exception as e:
        logger.error(f"Threat scoring error for {ip}: {e}")
        return 0.0


def score_to_level(score: float) -> str:
    if score <= 20:
        return "SAFE"
    elif score <= 40:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"
