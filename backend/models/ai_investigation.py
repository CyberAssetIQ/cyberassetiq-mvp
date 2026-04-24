from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from db.session import Base


class AIInvestigation(Base):
    """
    LLM-generated investigation report for an alert or correlated incident.
    Immutable once created — new investigations create new rows.
    """
    __tablename__ = "ai_investigations"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(128), nullable=False, index=True, default="tenant-001")

    alert_id = Column(Integer, ForeignKey("ai_alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_id = Column(Integer, ForeignKey("ai_correlations.id", ondelete="SET NULL"), nullable=True, index=True)

    # LLM-generated content
    executive_summary = Column(Text, nullable=True)   # 2–3 sentence non-technical summary
    technical_summary = Column(Text, nullable=True)   # Detailed analyst summary
    analyst_notes = Column(Text, nullable=True)       # Additional context and signals

    remediation_steps_json = Column(JSON, nullable=True)  # Ordered list of remediation actions
    timeline_json = Column(JSON, nullable=True)            # Event sequence [{time, event, severity}]

    mitre_tactic = Column(String(64), nullable=True)
    mitre_technique = Column(String(64), nullable=True)

    model_used = Column(String(128), nullable=True)   # e.g. claude-3-5-sonnet-20241022
    prompt_version = Column(String(32), nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    alert = relationship("AIAlert", backref="investigations", foreign_keys=[alert_id])
