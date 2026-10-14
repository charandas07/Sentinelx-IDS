"""Traffic API endpoints."""
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db
from app.models.traffic import TrafficFlow
from app.schemas import TrafficFlowResponse
from app.services.traffic_processor import traffic_processor

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("", response_model=List[TrafficFlowResponse])
async def get_traffic(
    protocol: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    q = select(TrafficFlow).order_by(desc(TrafficFlow.timestamp)).limit(limit).offset(offset)
    filters = []
    if protocol:
        filters.append(TrafficFlow.protocol == protocol.upper())
    if src_ip:
        filters.append(TrafficFlow.src_ip == src_ip)
    if status:
        filters.append(TrafficFlow.status == status.upper())
    if filters:
        from sqlalchemy import and_
        q = q.where(and_(*filters))
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/pps-history")
async def get_pps_history(n: int = Query(60)):
    return traffic_processor.get_pps_history(n)


@router.get("/protocols")
async def get_protocol_counts():
    return traffic_processor.get_protocol_counts()
