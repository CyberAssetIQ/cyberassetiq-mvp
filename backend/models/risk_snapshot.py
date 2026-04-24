from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, JSON, String, Float
from sqlalchemy.sql import func

from models.mixins import Base


class RiskSnapshot(Base):
    """
    Periodic snapshot of the platform's overall security posture.
    Created automatically every 6 hours by the cleanup loop.
    Powers the risk timeline graph on the SME Command Centre.
    """
    __tablename__ = "risk_snapshots"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id           = Column(String, nullable=False, index=True)
    captured_at         = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Overall scores
    overall_score       = Column(Integer, default=0)       # 0-100 composite
    ce_score            = Column(Float, nullable=True)     # CE compliance %
    patch_score         = Column(Integer, nullable=True)   # Patch management score
    identity_score      = Column(Integer, nullable=True)   # Identity risk score
    insurance_score     = Column(Integer, nullable=True)   # Insurance readiness

    # Counts
    total_assets        = Column(Integer, default=0)
    managed_assets      = Column(Integer, default=0)
    critical_cves       = Column(Integer, default=0)
    high_cves           = Column(Integer, default=0)
    open_darkweb        = Column(Integer, default=0)
    open_alerts         = Column(Integer, default=0)
    critical_findings   = Column(Integer, default=0)

    # Breakdown JSON for details
    breakdown_json      = Column(JSON, default=dict)
