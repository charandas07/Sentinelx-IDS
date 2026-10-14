"""Reports API endpoints."""
import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.alert import Alert
from app.models.traffic import TrafficFlow
from app.models.ip_stats import IPStatistics
from app.schemas import SecurityReport

router = APIRouter(prefix="/api/reports", tags=["reports"])


async def _build_report(db: AsyncSession, days: int = 7) -> dict:
    since = datetime.utcnow() - timedelta(days=days)

    total_packets = await db.scalar(select(func.count(TrafficFlow.id)).where(TrafficFlow.timestamp >= since)) or 0
    total_threats = await db.scalar(select(func.count(Alert.id)).where(Alert.timestamp >= since)) or 0
    critical = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL", Alert.timestamp >= since)
    ) or 0
    suspicious_ips = await db.scalar(
        select(func.count(IPStatistics.id)).where(IPStatistics.threat_score > 40)
    ) or 0

    # Top attacks
    top_attacks_result = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("c"))
        .where(Alert.timestamp >= since)
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    top_attacks = [{"attack_type": r[0], "count": r[1]} for r in top_attacks_result.all()]

    # Top source IPs
    top_ips_result = await db.execute(
        select(Alert.src_ip, func.count(Alert.id).label("c"))
        .where(Alert.timestamp >= since)
        .group_by(Alert.src_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    top_ips = [{"ip": r[0], "count": r[1]} for r in top_ips_result.all()]

    # Top target ports
    top_ports_result = await db.execute(
        select(Alert.dst_port, func.count(Alert.id).label("c"))
        .where(Alert.timestamp >= since, Alert.dst_port.isnot(None))
        .group_by(Alert.dst_port)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    top_ports = [{"port": r[0], "count": r[1]} for r in top_ports_result.all()]

    # Threat distribution
    threat_dist_result = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("c"))
        .where(Alert.timestamp >= since)
        .group_by(Alert.attack_type)
    )
    threat_dist = [{"name": r[0], "value": r[1]} for r in threat_dist_result.all()]

    recommendations = [
        "Enable SYN cookies to mitigate SYN flood attacks.",
        "Implement IP-based rate limiting on all public services.",
        "Review firewall rules for suspicious source IPs.",
        "Enable intrusion prevention mode for high-threat IPs.",
        "Monitor brute-force targets and enforce MFA on critical services.",
        "Segment network to limit lateral movement opportunities.",
    ]

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "period_start": since.isoformat(),
        "period_end": datetime.utcnow().isoformat(),
        "total_packets": total_packets,
        "total_connections": total_packets,
        "threats_detected": total_threats,
        "critical_alerts": critical,
        "suspicious_ips": suspicious_ips,
        "top_attacks": top_attacks,
        "top_source_ips": top_ips,
        "top_target_ports": top_ports,
        "threat_distribution": threat_dist,
        "recommendations": recommendations,
    }


@router.get("")
async def get_report(days: int = Query(7, ge=1, le=90), db: AsyncSession = Depends(get_db)):
    return await _build_report(db, days)


@router.get("/export/json")
async def export_json(days: int = Query(7), db: AsyncSession = Depends(get_db)):
    report = await _build_report(db, days)
    content = json.dumps(report, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinelx_report.json"},
    )


@router.get("/export/csv")
async def export_csv(days: int = Query(7), db: AsyncSession = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(Alert).where(Alert.timestamp >= since).order_by(Alert.timestamp.desc())
    )
    alerts = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "attack_type", "severity", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "threat_score", "status", "is_simulation"])
    for a in alerts:
        writer.writerow([a.id, a.timestamp, a.attack_type, a.severity, a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.protocol, a.threat_score, a.status, a.is_simulation])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.read().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelx_alerts.csv"},
    )
