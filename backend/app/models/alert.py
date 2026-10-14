"""Alert ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Index, Text, ForeignKey
from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    attack_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)   # CRITICAL/HIGH/MEDIUM/LOW/INFO
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    packet_count = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)
    threat_score = Column(Float, default=0.0)
    status = Column(String(16), default="DETECTED")  # DETECTED/INVESTIGATING/RESOLVED
    detection_rule = Column(String(128), nullable=True)
    recommended_action = Column(String(256), nullable=True)
    details = Column(String(1024), nullable=True)
    is_simulation = Column(Boolean, default=False)

    # ── SentinelX 2.0 evidence fields (added via safe schema upgrade) ──
    # Structured JSON explaining why the alert fired: rule id/version,
    # observed values vs thresholds, window, flow ids, packet refs,
    # severity rationale and evidence limitations.
    evidence_json = Column(Text, nullable=True)
    flow_id = Column(String(128), nullable=True)          # primary related flow
    incident_id = Column(Integer, nullable=True, index=True)  # correlated incident
    provenance = Column(String(16), default="live")       # live | pcap | simulation
    rule_version = Column(String(16), nullable=True)

    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_attack_type", "attack_type"),
    )

