"""Incident Investigation API endpoints (SentinelX 2.0).

Lists correlated incidents, retrieves investigation timelines and lets an
analyst update status/notes using the same Bearer-token conventions as the
rest of the API.
"""
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from app.database import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas import (
    IncidentResponse, IncidentDetailResponse, IncidentUpdate,
    IncidentTimelineEvent,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

VALID_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}


def _parse_json_list(raw: Optional[str]) -> list:
    try:
        val = json.loads(raw or "[]")
        return val if isinstance(val, list) else []
    except Exception:
        return []


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Query correlated incidents (most recently active first)."""
    filters = []
    if status:
        filters.append(Incident.status == status.upper())
    if severity:
        filters.append(Incident.severity == severity.upper())
    if src_ip:
        filters.append(Incident.src_ip == src_ip)
    if from_date:
        filters.append(Incident.last_seen >= from_date)
    if to_date:
        filters.append(Incident.first_seen <= to_date)

    q = select(Incident).order_by(desc(Incident.last_seen)).limit(limit).offset(offset)
    if filters:
        q = q.where(and_(*filters))
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def incident_detail(incident_id: int, db: AsyncSession = Depends(get_db)):
    """Incident with its chronological alert timeline and evidence."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts_res = await db.execute(
        select(Alert)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.timestamp.asc())
        .limit(500)
    )
    alerts = list(alerts_res.scalars().all())

    timeline = []
    for a in alerts:
        evidence = None
        if a.evidence_json:
            try:
                evidence = json.loads(a.evidence_json)
            except Exception:
                evidence = None
        timeline.append(IncidentTimelineEvent(
            kind="alert",
            timestamp=a.timestamp,
            alert_id=a.id,
            attack_type=a.attack_type,
            severity=a.severity,
            src_ip=a.src_ip,
            dst_ip=a.dst_ip,
            description=a.details or a.detection_rule,
            evidence=evidence,
        ))
    timeline.sort(key=lambda e: e.timestamp)

    data = IncidentDetailResponse.model_validate(incident)
    data.alerts = alerts
    data.timeline = timeline
    data.flow_ids = _parse_json_list(incident.flow_ids_json)
    return data


@router.patch("/{incident_id}", response_model=IncidentDetailResponse)
async def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update investigation status and/or analyst notes."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if update.status is not None:
        status = update.status.upper()
        if status not in VALID_STATUSES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status '{status}'. Must be one of {sorted(VALID_STATUSES)}",
            )
        incident.status = status
    if update.notes is not None:
        incident.notes = update.notes[:4000]
    incident.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(incident)

    data = IncidentDetailResponse.model_validate(incident)
    data.alerts = []
    data.timeline = []
    data.flow_ids = _parse_json_list(incident.flow_ids_json)
    return data
