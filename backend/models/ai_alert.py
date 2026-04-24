from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from db.session import Base


class AIAlert(Base):
    __tablename__ = "ai_alerts"

    id = Column(Integer, primary_key=True, index=True)
    ai_event_id = Column(Integer, ForeignKey("ai_events.id", ondelete="CASCADE"), nullable=True, index=True)

    alert_type = Column(String(100), nullable=False, index=True)   # anomaly, correlation, threat, exposure
    severity = Column(String(50), nullable=False, default="medium", index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)

    recommendation = Column(Text, nullable=True)
    confidence = Column(Integer, nullable=False, default=50)  # 0 - 100
    status = Column(String(50), nullable=False, default="new", index=True)  # new, acknowledged, closed

    entities = Column(JSON, nullable=True)  # list of hostnames, IPs, users, CVEs, etc.
    evidence = Column(JSON, nullable=True)  # structured supporting data
    metadata_json = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    ai_event = relationship("AIEvent", backref="alerts")
