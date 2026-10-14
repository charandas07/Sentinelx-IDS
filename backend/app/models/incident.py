"""Incident ORM model (SentinelX 2.0 temporal alert correlation)."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Index, Text
from app.database import Base


class Incident(Base):
    """A correlated investigation case grouping related alerts.

    Alerts reference incidents via Alert.incident_id; flow ids and affected
    endpoints are stored as bounded JSON lists on the incident.
    """

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    classification = Column(String(64), nullable=False)   # e.g. RECON_AND_ACCESS
    status = Column(String(16), default="OPEN")           # OPEN/INVESTIGATING/RESOLVED/CLOSED
    severity = Column(String(16), default="HIGH")
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    src_ip = Column(String(45), nullable=True, index=True)
    affected_endpoints_json = Column(Text, nullable=True)  # JSON list of IPs
    flow_ids_json = Column(Text, nullable=True)            # JSON list of flow ids
    alert_count = Column(Integer, default=0)
    correlation_window = Column(Integer, default=300)
    explanation = Column(Text, nullable=True)              # why these alerts were grouped
    notes = Column(Text, nullable=True)                    # analyst notes
    is_simulation = Column(Boolean, default=False)
    provenance = Column(String(16), default="live")        # live | pcap | simulation

    __table_args__ = (
        Index("ix_incidents_last_seen", "last_seen"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
    )
