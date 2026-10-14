"""SystemEvent ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from app.database import Base


class SystemEvent(Base):
    __tablename__ = "system_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String(64), nullable=False)   # STARTUP/SHUTDOWN/DEMO_START/PCAP_UPLOAD etc.
    message = Column(String(512), nullable=True)
    level = Column(String(16), default="INFO")
    is_simulation = Column(Boolean, default=False)
