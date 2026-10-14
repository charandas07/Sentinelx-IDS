"""WhitelistEntry ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Index
from app.database import Base


class WhitelistEntry(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), unique=True, nullable=False)
    comment = Column(String(256), nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_whitelist_ip", "ip"),
    )
