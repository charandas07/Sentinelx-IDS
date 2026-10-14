"""TrafficFlow ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Index
from app.database import Base


class TrafficFlow(Base):
    __tablename__ = "traffic"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)
    packet_size = Column(Integer, default=0)
    flags = Column(String(32), nullable=True)
    status = Column(String(16), default="NORMAL")   # NORMAL/SUSPICIOUS/BLOCKED
    is_simulation = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_traffic_timestamp", "timestamp"),
        Index("ix_traffic_src_ip", "src_ip"),
        Index("ix_traffic_dst_ip", "dst_ip"),
    )
