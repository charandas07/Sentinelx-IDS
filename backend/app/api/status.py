"""Status and Stats API endpoints."""
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.alert import Alert
from app.models.ip_stats import IPStatistics
from app.schemas import StatusResponse, SystemStats
from app.services import capture, demo_simulator, traffic_processor as tp_module
from app.services.traffic_processor import traffic_processor

router = APIRouter(prefix="/api", tags=["status"])

_start_time = time.time()


@router.get("/status", response_model=StatusResponse)
async def get_status():
    stats_dict = capture.get_stats()
    return StatusResponse(
        status="ONLINE",
        version="1.0.0",
        demo_mode=demo_simulator.is_active(),
        is_capturing=capture.is_capturing(),
        capture_error=capture.get_last_error(),
        active_iface=stats_dict.get("active_iface"),
        uptime_seconds=time.time() - _start_time,
        database="sqlite",
    )


@router.get("/stats", response_model=SystemStats)
async def get_stats(db: AsyncSession = Depends(get_db)):
    # Total packets
    total_pkts = traffic_processor.get_total_packets()
    total_bytes = traffic_processor.get_total_bytes()

    # Alert counts
    total_alerts = await db.scalar(select(func.count(Alert.id))) or 0
    critical = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
    ) or 0

    # Suspicious IPs (threat score > 40)
    suspicious = await db.scalar(
        select(func.count(IPStatistics.id)).where(IPStatistics.threat_score > 40)
    ) or 0

    # Alerts last hour
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    alerts_last_hour = await db.scalar(
        select(func.count(Alert.id)).where(Alert.timestamp >= one_hour_ago)
    ) or 0

    # Top attack types
    rows = await db.execute(
        select(Alert.attack_type, func.count(Alert.id).label("count"))
        .group_by(Alert.attack_type)
        .order_by(func.count(Alert.id).desc())
        .limit(6)
    )
    top_attacks = [{"attack_type": r[0], "count": r[1]} for r in rows.all()]

    stats_dict = capture.get_stats()
    return SystemStats(
        packets_analyzed=total_pkts,
        threats_detected=total_alerts,
        critical_alerts=critical,
        suspicious_ips=suspicious,
        traffic_bytes=total_bytes,
        uptime_seconds=time.time() - _start_time,
        is_capturing=capture.is_capturing(),
        capture_error=capture.get_last_error(),
        active_iface=stats_dict.get("active_iface"),
        demo_mode=demo_simulator.is_active(),
        alerts_last_hour=alerts_last_hour,
        top_attack_types=top_attacks,
    )
