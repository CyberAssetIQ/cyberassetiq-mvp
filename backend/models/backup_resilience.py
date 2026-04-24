from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class BackupProfile(TimestampMixin, Base):
    """Detected backup posture for an asset — inferred from software inventory."""
    __tablename__ = "backup_profiles"
    __table_args__ = (
        Index("ix_backup_profiles_tenant_asset", "tenant_id", "asset_id", unique=True),
        Index("ix_backup_profiles_tenant_coverage", "tenant_id", "has_backup"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    backup_tool: Mapped[str | None] = mapped_column(String(128), nullable=True)
    backup_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # agent | agentless | cloud | unknown
    has_backup: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    immutable_backup: Mapped[bool] = mapped_column(Boolean, default=False)
    offline_backup: Mapped[bool] = mapped_column(Boolean, default=False)
    last_successful_backup: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    backup_frequency: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # daily | weekly | monthly | unknown
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class BackupRiskFinding(TimestampMixin, Base):
    """A specific backup-related risk finding for an asset."""
    __tablename__ = "backup_risk_findings"
    __table_args__ = (
        Index("ix_backup_risk_findings_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_backup_risk_findings_tenant_severity", "tenant_id", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    # no_backup | stale_backup | no_immutable | no_offline | crown_jewel_unprotected
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RecoveryConfidenceScore(TimestampMixin, Base):
    """Computed recovery confidence for an asset or the full tenant estate.

    asset_id=None means the tenant-level aggregate score.
    confidence_band: high | medium | low | critical_gap
    """
    __tablename__ = "recovery_confidence_scores"
    __table_args__ = (
        Index("ix_recovery_confidence_scores_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_recovery_confidence_scores_computed_at", "tenant_id", "computed_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)         # 0-100
    confidence_band: Mapped[str] = mapped_column(String(32), default="critical_gap", index=True)
    reasons_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    computed_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
