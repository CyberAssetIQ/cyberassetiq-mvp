from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, Text, String
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class CanonicalAsset(TimestampMixin, Base):
    __tablename__ = "canonical_assets"
    __table_args__ = (
        Index("ix_canonical_assets_tenant_agent", "tenant_id", "agent_id", unique=True),
        Index("ix_canonical_assets_tenant_asset_uid", "tenant_id", "asset_uid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ips: Mapped[list[str] | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    macs: Mapped[list[str] | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    last_snapshot_epoch: Mapped[int | None] = mapped_column(nullable=True)
    security_posture_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    raw_metadata_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)

    # Discovery spine fields: all nullable for safe drop-in rollout.
    asset_uid: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    primary_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    management_state: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True, default="unmanaged")
    source_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True, default=100)
    last_seen_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_types_json: Mapped[list[str] | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    network_asset_ids_json: Mapped[list[int] | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    last_network_scan_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_network_seen_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_heartbeat_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    
    # Asset governance fields
    asset_state: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True, default="observed_unknown")
    ownership_status: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True, default="unknown")
    compliance_scope: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True, default="pending_review")
    source_of_truth: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True, default="network_scan")
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    agent_installed: Mapped[bool | None] = mapped_column(Boolean, nullable=True, index=True, default=False)
    agent_last_seen_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

class ManualAsset(TimestampMixin, Base):
    """
    Assets created manually by a user (not discovered by agent or network scan).
    Stored separately so they can be edited/deleted freely without disrupting
    agent-reported CanonicalAssets.
    """
    __tablename__ = "manual_assets"
    __table_args__ = (
        Index("ix_manual_assets_tenant_id", "tenant_id"),
    )

    id:           Mapped[int]       = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:    Mapped[str]       = mapped_column(String(128), index=True)
    hostname:     Mapped[str]       = mapped_column(String(255))
    ip:           Mapped[str | None]= mapped_column(String(64), nullable=True)
    os_family:    Mapped[str | None]= mapped_column(String(64), nullable=True)
    os_version:   Mapped[str | None]= mapped_column(String(255), nullable=True)
    notes:        Mapped[str | None]= mapped_column(Text, nullable=True)
    created_by:   Mapped[str | None]= mapped_column(String(255), nullable=True)
    is_deleted:   Mapped[bool]      = mapped_column(default=False)
