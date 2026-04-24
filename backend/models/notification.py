from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id       = Column(String, nullable=False, index=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    name            = Column(String, nullable=False)
    trigger_type    = Column(String, nullable=False)   # new_critical_cve | new_ai_alert | dark_web_exposure | patch_score_low | new_credential_leak | ce_compliance_fail
    threshold       = Column(Integer, nullable=True)   # numeric threshold (e.g. score < 70, count >= 1)
    cooldown_minutes = Column(Integer, default=60)     # minimum minutes between repeat alerts

    channel         = Column(String, nullable=False)   # email | slack | teams | webhook
    destination     = Column(String, nullable=False)   # email address or webhook URL

    is_active       = Column(Boolean, default=True)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id   = Column(String, nullable=False, index=True)
    rule_id     = Column(Integer, nullable=True)
    sent_at     = Column(DateTime(timezone=True), server_default=func.now())

    channel     = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    subject     = Column(String, nullable=True)
    body        = Column(String, nullable=True)
    trigger_type = Column(String, nullable=True)
    status      = Column(String, default="sent")   # sent | failed
    error       = Column(String, nullable=True)
