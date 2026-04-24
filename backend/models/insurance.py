from __future__ import annotations

from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func

from models.mixins import Base


class InsuranceAssessment(Base):
    __tablename__ = "insurance_assessments"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id      = Column(String, nullable=False, index=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())
    readiness_score = Column(Integer, nullable=False)
    risk_band      = Column(String, nullable=False)   # Low / Medium / High / Critical
    factors_json   = Column(JSON, default=list)
    recommendations_json = Column(JSON, default=list)
    snapshot_json  = Column(JSON, default=dict)       # raw counts at time of save


class InsuranceReferral(Base):
    __tablename__ = "insurance_referrals"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id     = Column(String, nullable=False, index=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    partner       = Column(String, default="general")
    assessment_id = Column(Integer, ForeignKey("insurance_assessments.id"), nullable=True)
    notes         = Column(String, nullable=True)
