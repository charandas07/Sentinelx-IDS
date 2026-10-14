"""Flow Inspector API endpoints (SentinelX 2.0).

Exposes the live bidirectional flow table with filtering, pagination and
detail lookups, plus the tracker's health statistics.
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.database import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas import FlowListResponse, FlowDetailResponse, FlowTrackerStats
from app.services.flow_tracker import flow_tracker

router = APIRouter(prefix="/api/flows", tags=["flows"])


@router.get("", response_model=FlowListResponse)
async def list_flows(
    ip: Optional[str] = Query(None, description="Filter by source OR destination IP"),
    port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by src or dst port"),
    protocol: Optional[str] = Query(None, description="TCP/UDP/ICMP/OTHER"),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    provenance: Optional[str] = Query(None, description="live|pcap|simulation"),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
):
    """Filtered, paginated view of currently tracked flows (newest first)."""
    items, total = flow_tracker.snapshot(
        ip=ip, port=port, protocol=protocol, since=since, until=until,
        provenance=provenance, limit=limit, offset=offset,
    )
    return FlowListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        tracker_stats=flow_tracker.stats(),
    )


@router.get("/stats", response_model=FlowTrackerStats)
async def flow_tracker_stats():
    """Flow table health: size, evictions, expirations, configured bounds."""
    return flow_tracker.stats()


@router.get("/{flow_id:path}", response_model=FlowDetailResponse)
async def flow_detail(flow_id: str, db: AsyncSession = Depends(get_db)):
    """Full detail for one flow, including packet refs and linked alerts."""
    flow = flow_tracker.get(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found (it may have expired from the in-memory table)")
    data = flow.to_dict(include_refs=True)

    # Linked alerts: alerts recorded with this flow_id as primary evidence.
    alert_ids: list = []
    incident_ids: list = []
    try:
        res = await db.execute(
            select(Alert.id, Alert.incident_id).where(Alert.flow_id == flow_id).limit(50)
        )
        for aid, inc_id in res.all():
            alert_ids.append(aid)
            if inc_id is not None and inc_id not in incident_ids:
                incident_ids.append(inc_id)
    except Exception:
        pass

    return FlowDetailResponse(
        **data,
        packet_refs=data.get("packet_refs", []),
        alert_ids=alert_ids,
        incident_ids=incident_ids,
    )
