"""IP Analysis API endpoints."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.alert import Alert
from app.models.traffic import TrafficFlow
from app.models.ip_stats import IPStatistics
from app.schemas import IPStatsResponse
from app.services.threat_scorer import score_to_level

router = APIRouter(prefix="/api/ip", tags=["ip_analysis"])


@router.get("/{ip}")
async def get_ip_analysis(ip: str, db: AsyncSession = Depends(get_db)):
    # IP stats
    stats_result = await db.execute(select(IPStatistics).where(IPStatistics.ip == ip))
    stats = stats_result.scalar_one_or_none()

    # Alert summary
    alert_result = await db.execute(
        select(Alert.attack_type, Alert.severity, func.count(Alert.id).label("count"))
        .where(Alert.src_ip == ip)
        .group_by(Alert.attack_type, Alert.severity)
        .order_by(func.count(Alert.id).desc())
    )
    attack_summary = [{"attack_type": r[0], "severity": r[1], "count": r[2]} for r in alert_result.all()]

    # Recent alerts
    recent_alerts_result = await db.execute(
        select(Alert).where(Alert.src_ip == ip)
        .order_by(Alert.timestamp.desc()).limit(20)
    )
    recent_alerts = recent_alerts_result.scalars().all()

    # Protocol distribution
    proto_result = await db.execute(
        select(TrafficFlow.protocol, func.count(TrafficFlow.id).label("count"))
        .where(TrafficFlow.src_ip == ip)
        .group_by(TrafficFlow.protocol)
    )
    protocols = {r[0]: r[1] for r in proto_result.all()}

    # Top destination ports
    port_result = await db.execute(
        select(TrafficFlow.dst_port, func.count(TrafficFlow.id).label("count"))
        .where(TrafficFlow.src_ip == ip, TrafficFlow.dst_port.isnot(None))
        .group_by(TrafficFlow.dst_port)
        .order_by(func.count(TrafficFlow.id).desc())
        .limit(10)
    )
    top_ports = [{"port": r[0], "count": r[1]} for r in port_result.all()]

    threat_score = stats.threat_score if stats else 0.0

    return {
        "ip": ip,
        "threat_score": threat_score,
        "threat_level": score_to_level(threat_score),
        "stats": {
            "first_seen": stats.first_seen.isoformat() if stats else None,
            "last_seen": stats.last_seen.isoformat() if stats else None,
            "packet_count": stats.packet_count if stats else 0,
            "connection_count": stats.connection_count if stats else 0,
            "alert_count": stats.alert_count if stats else 0,
            "bytes_sent": stats.bytes_sent if stats else 0,
            "bytes_received": stats.bytes_received if stats else 0,
            "unique_ports_accessed": stats.unique_ports_accessed if stats else 0,
        },
        "attack_summary": attack_summary,
        "recent_alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "attack_type": a.attack_type,
                "severity": a.severity,
                "protocol": a.protocol,
                "threat_score": a.threat_score,
            }
            for a in recent_alerts
        ],
        "protocol_distribution": protocols,
        "top_destination_ports": top_ports,
    }


@router.get("")
async def list_suspicious_ips(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(IPStatistics)
        .where(IPStatistics.threat_score > 0)
        .order_by(IPStatistics.threat_score.desc())
        .limit(limit)
    )
    items = result.scalars().all()
    return [
        {
            "ip": s.ip,
            "threat_score": s.threat_score,
            "threat_level": score_to_level(s.threat_score),
            "alert_count": s.alert_count,
            "packet_count": s.packet_count,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in items
    ]
