from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class RiskFactorScore(TimestampMixin, Base):
    """Individual risk factor contribution for an asset or tenant-wide.

    asset_id=None means tenant-level factor. Allows full drill-down in UI.
    """
    __tablename__ = "risk_factor_scores"
    __table_args__ = (
        Index("ix_risk_factor_scores_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_risk_factor_scores_tenant_factor", "tenant_id", "factor_name"),
        Index("ix_risk_factor_scores_computed_at", "tenant_id", "computed_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    factor_name: Mapped[str] = mapped_column(String(128), index=True)
    # critical_cves | exposure | drift | identity_risk | patch_posture |
    # dark_web | criticality | backup_resilience | attack_exposure | compliance
    factor_weight: Mapped[float] = mapped_column(Float, default=1.0)
    raw_score: Mapped[float] = mapped_column(Float, default=0.0)
    normalized_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RiskSnapshotV2(TimestampMixin, Base):
    """Versioned composite risk snapshot. Replaces the simpler risk_snapshots table.

    entity_type = 'tenant' | 'asset'. entity_id = asset_id when entity_type='asset'.
    severity_band = critical | high | medium | low | minimal
    """
    __tablename__ = "risk_snapshots_v2"
    __table_args__ = (
        Index("ix_risk_snapshots_v2_tenant_entity", "tenant_id", "entity_type", "entity_id"),
        Index("ix_risk_snapshots_v2_computed_at", "tenant_id", "computed_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), default="tenant", index=True)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    total_score: Mapped[int] = mapped_column(Integer, default=0)        # 0-100
    severity_band: Mapped[str] = mapped_column(String(16), default="low", index=True)
    contributing_factors_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    computed_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RiskRecommendation(TimestampMixin, Base):
    """Actionable recommendation to improve a risk score.

    priority_rank 1 = highest impact action. expected_score_gain is the
    estimated point improvement from resolving this item.
    """
    __tablename__ = "risk_recommendations"
    __table_args__ = (
        Index("ix_risk_recommendations_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_risk_recommendations_tenant_status", "tenant_id", "status"),
        Index("ix_risk_recommendations_tenant_priority", "tenant_id", "priority_rank"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    recommendation_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    expected_score_gain: Mapped[int] = mapped_column(Integer, default=0)
    priority_rank: Mapped[int] = mapped_column(Integer, default=99, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # open | in_progress | resolved | dismissed
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RiskScoreExplanation(TimestampMixin, Base):
    """AI-generated plain-English explanation for a risk snapshot.

    Linked to a RiskSnapshotV2 row. Cached so we don't regenerate on every request.
    """
    __tablename__ = "risk_score_explanations"
    __table_args__ = (
        Index("ix_risk_score_explanations_snapshot", "snapshot_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    snapshot_id: Mapped[int] = mapped_column(Integer, index=True)
    explanation_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    breakdown_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    generated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
