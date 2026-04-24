from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class AssetStateSnapshot(TimestampMixin, Base):
    """Point-in-time hash of an asset's key security-relevant state fields.

    Created each time an agent submits a full snapshot. The hash allows fast
    drift detection without loading the full payload.
    """
    __tablename__ = "asset_state_snapshots"
    __table_args__ = (
        Index("ix_asset_state_snapshots_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_asset_state_snapshots_tenant_collected", "tenant_id", "collected_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)          # FK → canonical_assets.id (soft ref)
    snapshot_type: Mapped[str] = mapped_column(String(64), default="full")  # full | software | ports | security
    snapshot_hash: Mapped[str] = mapped_column(String(64), index=True)  # SHA-256 of canonical state fields
    state_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    collected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class AssetDriftEvent(TimestampMixin, Base):
    """A single detected change in an asset's state vs the previous snapshot.

    One event per changed field / category (e.g. new_admin, new_port, etc.).
    Status moves from open → reviewed → approved/suppressed.
    """
    __tablename__ = "asset_drift_events"
    __table_args__ = (
        Index("ix_asset_drift_events_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_asset_drift_events_tenant_status", "tenant_id", "status"),
        Index("ix_asset_drift_events_tenant_severity", "tenant_id", "severity"),
        Index("ix_asset_drift_events_detected_at", "tenant_id", "detected_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    drift_type: Mapped[str] = mapped_column(String(64), index=True)
    # new_admin | new_port | removed_backup | new_software | asset_disappeared |
    # firewall_change | patch_regression | exposure_change
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    # critical | high | medium | low
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # open | reviewed | approved | suppressed
    approved_change_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ApprovedChange(TimestampMixin, Base):
    """A pre-authorised change window that suppresses drift events automatically."""
    __tablename__ = "approved_changes"
    __table_args__ = (
        Index("ix_approved_changes_tenant_asset", "tenant_id", "asset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)   # None = all assets
    change_type: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    valid_from: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class DriftBaseline(TimestampMixin, Base):
    """The agreed-upon reference state for an asset. Drift is measured against this."""
    __tablename__ = "drift_baselines"
    __table_args__ = (
        Index("ix_drift_baselines_tenant_asset", "tenant_id", "asset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    baseline_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    baseline_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
