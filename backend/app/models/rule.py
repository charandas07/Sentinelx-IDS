"""DetectionRule ORM model."""
from sqlalchemy import Column, Integer, String, Float, Boolean
from app.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False)
    display_name = Column(String(128), nullable=False)
    description = Column(String(512), nullable=True)
    enabled = Column(Boolean, default=True)
    threshold = Column(Float, nullable=True)
    time_window = Column(Integer, nullable=True)   # seconds
    severity = Column(String(16), default="HIGH")
    attack_type = Column(String(64), nullable=False)
    recommended_action = Column(String(256), nullable=True)
