from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class CanonicalAsset(TimestampMixin, Base):
    __tablename__ = "canonical_assets"
    __table_args__ = (
        Index("ix_canonical_assets_tenant_agent", "tenant_id", "agent_id", unique=True),
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
