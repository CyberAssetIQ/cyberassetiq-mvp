from __future__ import annotations

from sqlalchemy import ForeignKey, Index, String, Text, Float, Integer
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class AssetSnapshotEvent(TimestampMixin, Base):
    __tablename__ = "asset_snapshot_events"
    __table_args__ = (Index("ix_asset_snapshot_events_tenant_agent", "tenant_id", "agent_id"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_epoch: Mapped[int | None] = mapped_column(nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class SoftwareInventoryEvent(TimestampMixin, Base):
    __tablename__ = "software_inventory_events"
    __table_args__ = (Index("ix_software_inventory_events_tenant_agent", "tenant_id", "agent_id"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_epoch: Mapped[int | None] = mapped_column(nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class SecurityPostureEvent(TimestampMixin, Base):
    __tablename__ = "security_posture_events"
    __table_args__ = (Index("ix_security_posture_events_tenant_agent", "tenant_id", "agent_id"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_epoch: Mapped[int | None] = mapped_column(nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class LocalFindingsEvent(TimestampMixin, Base):
    __tablename__ = "local_findings_events"
    __table_args__ = (Index("ix_local_findings_events_tenant_agent", "tenant_id", "agent_id"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    payload_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class HeartbeatEvent(TimestampMixin, Base):
    __tablename__ = "heartbeat_events"
    __table_args__ = (Index("ix_heartbeat_events_tenant_agent", "tenant_id", "agent_id"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp_epoch: Mapped[int | None] = mapped_column(nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))


class CanonicalSoftware(TimestampMixin, Base):
    __tablename__ = "canonical_software"
    __table_args__ = (
        Index("ix_canonical_software_tenant_agent_name", "tenant_id", "agent_id", "name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("canonical_assets.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    install_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class VulnerabilityFinding(TimestampMixin, Base):
    """CVE findings correlated against software inventory via NVD API.

    IMMUTABLE after creation — one row per (scan_run_id, agent_id, cve_id, software_name).
    User actions are stored in vuln_annotations, not here.
    Status field is set to 'open' at creation and never updated.
    """
    __tablename__ = "vulnerability_findings"
    # Old unique index ix_vuln_findings_tenant_agent_cve was DROPPED by migration.
    # Replaced with non-unique indexes below to allow same CVE across multiple scan runs.
    __table_args__ = (
        Index("ix_vuln_findings_scan_run", "scan_run_id"),
        Index("ix_vuln_findings_tenant_cve", "tenant_id", "cve_id"),
    )

    id:               Mapped[int]       = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:        Mapped[str]       = mapped_column(String(128), index=True)
    agent_id:         Mapped[str]       = mapped_column(String(128), index=True)

    # FK to vuln_scan_runs — nullable for rows created before this migration
    scan_run_id:      Mapped[int | None] = mapped_column(
        ForeignKey("vuln_scan_runs.id", ondelete="CASCADE"), nullable=True, index=True
    )

    software_name:    Mapped[str]       = mapped_column(String(255), index=True)
    software_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cve_id:           Mapped[str]       = mapped_column(String(32), index=True)
    severity:         Mapped[str]       = mapped_column(String(16), index=True)
    cvss_score:       Mapped[float | None] = mapped_column(Float, nullable=True)
    description:      Mapped[str | None] = mapped_column(Text, nullable=True)
    published:        Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Set to 'open' at creation. Do NOT update — use vuln_annotations instead.
    status:           Mapped[str]       = mapped_column(String(32), default="open")

    # agent = from CanonicalSoftware | network = from NetworkDiscoveredAsset
    source:           Mapped[str | None] = mapped_column(String(16), default="agent", nullable=True)

    # Legacy columns — kept for backwards compatibility with pre-migration rows
    scan_epoch:       Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_epoch:   Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolution_note:  Mapped[str | None] = mapped_column(Text, nullable=True)
