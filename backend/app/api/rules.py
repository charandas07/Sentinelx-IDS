"""Detection Rules API endpoints."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.rule import DetectionRule
from app.schemas import DetectionRuleResponse, DetectionRuleCreate, DetectionRuleUpdate

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("", response_model=List[DetectionRuleResponse])
async def get_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.id))
    return result.scalars().all()


@router.post("", response_model=DetectionRuleResponse, status_code=201)
async def create_rule(rule: DetectionRuleCreate, db: AsyncSession = Depends(get_db)):
    db_rule = DetectionRule(**rule.model_dump())
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.put("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(rule_id: int, update: DetectionRuleUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, value in update.model_dump(exclude_none=True).items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.post("/{rule_id}/reset")
async def reset_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    """Reset rule to default values."""
    from app.services.seed import DEFAULT_RULES
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for default in DEFAULT_RULES:
        if default["attack_type"] == rule.attack_type:
            rule.threshold = default["threshold"]
            rule.time_window = default["time_window"]
            rule.severity = default["severity"]
            rule.enabled = True
            break
    await db.commit()
    await db.refresh(rule)
    return rule
