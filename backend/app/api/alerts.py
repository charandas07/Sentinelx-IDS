"""Alerts API endpoints."""
import json
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from app.database import get_db
from app.models.alert import Alert
from app.schemas import AlertResponse, AlertUpdate, EvidenceResponse
from app.services.flow_tracker import flow_tracker

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    incident_id: Optional[int] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if severity:
        filters.append(Alert.severity == severity.upper())
    if attack_type:
        filters.append(Alert.attack_type == attack_type.upper())
    if src_ip:
        filters.append(Alert.src_ip == src_ip)
    if status:
        filters.append(Alert.status == status.upper())
    if incident_id is not None:
        filters.append(Alert.incident_id == incident_id)
    if from_date:
        filters.append(Alert.timestamp >= from_date)
    if to_date:
        filters.append(Alert.timestamp <= to_date)

    q = select(Alert).order_by(desc(Alert.timestamp)).limit(limit).offset(offset)
    if filters:
        q = q.where(and_(*filters))
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{alert_id}/evidence", response_model=EvidenceResponse)
async def get_alert_evidence(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Structured evidence explaining why the alert was generated."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    evidence = None
    if alert.evidence_json:
        try:
            evidence = json.loads(alert.evidence_json)
        except Exception:
            evidence = {"error": "evidence document could not be parsed"}

    flow_data = None
    if alert.flow_id:
        flow = flow_tracker.get(alert.flow_id)
        if flow is not None:
            flow_data = flow.to_dict(include_refs=True)

    return EvidenceResponse(
        alert_id=alert.id,
        evidence=evidence,
        flow=flow_data,
        incident_id=alert.incident_id,
        provenance=alert.provenance or ("simulation" if alert.is_simulation else "live"),
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(alert_id: int, update: AlertUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if update.status:
        alert.status = update.status.upper()
    await db.commit()
    await db.refresh(alert)
    return alert
