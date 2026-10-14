"""Whitelist API — GET/POST/DELETE /api/whitelist."""
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel

from app.database import get_db
from app.models.whitelist import WhitelistEntry
from app.services.traffic_processor import traffic_processor

router = APIRouter(prefix="/api/whitelist", tags=["whitelist"])


class WhitelistCreate(BaseModel):
    ip: str
    comment: Optional[str] = None


class WhitelistResponse(BaseModel):
    id: int
    ip: str
    comment: Optional[str]
    added_at: datetime

    model_config = {"from_attributes": True}


@router.get("", response_model=List[WhitelistResponse])
async def list_whitelist(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(WhitelistEntry))
    return result.scalars().all()


@router.post("", response_model=WhitelistResponse, status_code=201)
async def add_whitelist(body: WhitelistCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(
        select(WhitelistEntry).where(WhitelistEntry.ip == body.ip)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"IP {body.ip} already whitelisted")
    entry = WhitelistEntry(ip=body.ip, comment=body.comment)
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    # Also update in-memory whitelist in traffic_processor
    traffic_processor._whitelist_ips.add(body.ip)
    return entry


@router.delete("/{ip}", status_code=204)
async def remove_whitelist(ip: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(WhitelistEntry).where(WhitelistEntry.ip == ip)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in whitelist")
    await db.execute(delete(WhitelistEntry).where(WhitelistEntry.ip == ip))
    await db.commit()
    # Remove from in-memory whitelist
    traffic_processor._whitelist_ips.discard(ip)
