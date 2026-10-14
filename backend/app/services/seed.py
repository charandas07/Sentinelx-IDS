"""
Seed default detection rules into the database on first run.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.rule import DetectionRule

DEFAULT_RULES = [
    {
        "name": "port_scan",
        "display_name": "Port Scan Detection",
        "description": "Detects when a single source IP connects to many different destination ports within a short time window.",
        "attack_type": "PORT_SCAN",
        "threshold": 20.0,
        "time_window": 10,
        "severity": "HIGH",
        "enabled": True,
        "recommended_action": "Block source IP, investigate scanning intent. Run reverse DNS lookup.",
    },
    {
        "name": "brute_force",
        "display_name": "Brute Force Detection",
        "description": "Detects repeated login attempts to authentication services (SSH, FTP, RDP, HTTP, VNC).",
        "attack_type": "BRUTE_FORCE",
        "threshold": 10.0,
        "time_window": 30,
        "severity": "HIGH",
        "enabled": True,
        "recommended_action": "Block IP temporarily, enable account lockout, enforce MFA on targeted service.",
    },
    {
        "name": "syn_flood",
        "display_name": "SYN Flood Detection",
        "description": "Detects TCP SYN flooding — a large number of SYN packets without corresponding ACKs.",
        "attack_type": "SYN_FLOOD",
        "threshold": 100.0,
        "time_window": 5,
        "severity": "CRITICAL",
        "enabled": True,
        "recommended_action": "Enable SYN cookies, rate limit source IP, alert NOC team.",
    },
    {
        "name": "icmp_flood",
        "display_name": "ICMP Flood Detection",
        "description": "Detects excessive ICMP echo request traffic (Ping Flood).",
        "attack_type": "ICMP_FLOOD",
        "threshold": 50.0,
        "time_window": 5,
        "severity": "HIGH",
        "enabled": True,
        "recommended_action": "Rate limit ICMP, block persistent offenders, check for amplification.",
    },
    {
        "name": "traffic_spike",
        "display_name": "Traffic Spike / DoS Pattern",
        "description": "Detects abnormal per-IP traffic volume compared to observed baseline.",
        "attack_type": "TRAFFIC_SPIKE",
        "threshold": 3.0,
        "time_window": 10,
        "severity": "MEDIUM",
        "enabled": True,
        "recommended_action": "Monitor IP, apply traffic shaping, escalate if pattern continues.",
    },
    {
        "name": "dos_pattern",
        "display_name": "Global DoS Pattern",
        "description": "Detects volumetric DoS patterns across multiple source IPs.",
        "attack_type": "DOS_PATTERN",
        "threshold": 6.0,
        "time_window": 10,
        "severity": "CRITICAL",
        "enabled": True,
        "recommended_action": "Contact upstream ISP, enable DDoS mitigation, activate incident response.",
    },
]


async def seed_rules(db: AsyncSession):
    """Insert default rules if they don't already exist."""
    for rule_data in DEFAULT_RULES:
        existing = await db.scalar(
            select(DetectionRule).where(DetectionRule.name == rule_data["name"])
        )
        if not existing:
            rule = DetectionRule(**rule_data)
            db.add(rule)
    await db.commit()
