from __future__ import annotations

"""
SQLAlchemy models for compliance run history.

ComplianceRun      — one immutable header row per "Run Assessment" click
ComplianceRunAsset — one row per asset per run (immutable after creation)

CE v3.2 / IASME requires 12-month retention of compliance evidence.
The cleanup loop in app.py purges runs older than 12 months automatically.
"""

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class ComplianceRun(TimestampMixin, Base):
    """Immutable header created when user clicks 'Run Assessment'.
    Stores tenant-level summary. Never mutated after creation.
    """
    __tablename__ = "compliance_runs"
    __table_args__ = (
        Index("ix_compliance_runs_tenant_epoch", "tenant_id", "run_epoch"),
    )

    id:                     Mapped[int]   = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:              Mapped[str]   = mapped_column(String(128), index=True)
    run_epoch:              Mapped[int]   = mapped_column(Integer)
    assets_assessed:        Mapped[int]   = mapped_column(Integer, default=0)
    agent_assets_assessed:  Mapped[int]   = mapped_column(Integer, default=0)
    network_assets_assessed:Mapped[int]   = mapped_column(Integer, default=0)
    assets_passing:         Mapped[int]   = mapped_column(Integer, default=0)
    assets_partial:         Mapped[int]   = mapped_column(Integer, default=0)
    assets_failing:         Mapped[int]   = mapped_column(Integer, default=0)
    ce_ready:               Mapped[bool]  = mapped_column(Boolean, default=False)
    tenant_overall_score:   Mapped[float] = mapped_column(Float, default=0.0)
    triggered_by:           Mapped[str]   = mapped_column(String(64), default="user")


class ComplianceRunAsset(TimestampMixin, Base):
    """Immutable per-asset snapshot within a compliance run.
    controls_json stores the full A1-A8 control results for this asset at this point in time.
    """
    __tablename__ = "compliance_run_assets"

    id:             Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    run_id:         Mapped[int]        = mapped_column(
        ForeignKey("compliance_runs.id", ondelete="CASCADE"), index=True
    )
    tenant_id:      Mapped[str]        = mapped_column(String(128), index=True)
    agent_id:       Mapped[str]        = mapped_column(String(128))
    hostname:       Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_source:   Mapped[str]        = mapped_column(String(16), default="agent")
    overall_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    overall_score:  Mapped[float]      = mapped_column(Float, default=0.0)
    # Full A1-A8 control results: {A1: {name, status, score, finding_count}, ...}
    controls_json:  Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
