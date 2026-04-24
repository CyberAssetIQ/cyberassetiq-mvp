from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class BlastRadiusResult(TimestampMixin, Base):
    """Computed blast radius starting from a given source asset.

    Answers: if this asset is compromised, what else gets hit?
    impacted_assets_json: list of {asset_id, hostname, criticality_score, hop_distance, reach_method}
    """
    __tablename__ = "blast_radius_results"
    __table_args__ = (
        Index("ix_blast_radius_results_tenant_source", "tenant_id", "source_asset_id"),
        Index("ix_blast_radius_results_computed_at", "tenant_id", "computed_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_asset_id: Mapped[int] = mapped_column(Integer, index=True)
    impacted_assets_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    impacted_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    impacted_critical_count: Mapped[int] = mapped_column(Integer, default=0)
    estimated_spread_score: Mapped[float] = mapped_column(Float, default=0.0)
    # 0-100 — how dangerous this starting point is for lateral spread
    computed_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RansomwareScenario(TimestampMixin, Base):
    """A simulated ransomware scenario — what would be encrypted if asset X is hit first."""
    __tablename__ = "ransomware_scenarios"
    __table_args__ = (
        Index("ix_ransomware_scenarios_tenant_source", "tenant_id", "source_asset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_asset_id: Mapped[int] = mapped_column(Integer, index=True)
    scenario_name: Mapped[str] = mapped_column(String(255))
    scenario_result_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # {total_impacted, crown_jewels_hit, estimated_recovery_days, spread_path}
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
