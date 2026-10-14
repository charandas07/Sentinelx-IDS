"""IPStatistics ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Index
from app.database import Base


class IPStatistics(Base):
    __tablename__ = "ip_statistics"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), unique=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    packet_count = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)
    threat_score = Column(Float, default=0.0)
    alert_count = Column(Integer, default=0)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    unique_ports_accessed = Column(Integer, default=0)
    top_protocol = Column(String(16), nullable=True)
    is_internal = Column(Integer, default=1)  # 1=internal, 0=external

    __table_args__ = (
        Index("ix_ip_stats_ip", "ip"),
        Index("ix_ip_stats_threat_score", "threat_score"),
    )
