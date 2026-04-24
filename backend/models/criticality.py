from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class AssetCriticalityProfile(TimestampMixin, Base):
    """AI-inferred criticality profile for a canonical asset.

    Scores are 0-100. confidence is 0.0-1.0. reasoning_json stores the
    factors used so the UI can show a plain-English explanation.
    """
    __tablename__ = "asset_criticality_profiles"
    __table_args__ = (
        Index("ix_asset_criticality_profiles_tenant_asset", "tenant_id", "asset_id", unique=True),
        Index("ix_asset_criticality_profiles_tenant_score", "tenant_id", "criticality_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    asset_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # domain_controller | database_server | web_server | workstation | network_device | etc.
    criticality_score: Mapped[int] = mapped_column(Integer, default=0, index=True)   # 0-100
    confidentiality_score: Mapped[int] = mapped_column(Integer, default=0)
    integrity_score: Mapped[int] = mapped_column(Integer, default=0)
    availability_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    reasoning_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class BusinessService(TimestampMixin, Base):
    """A business service that depends on one or more assets.

    Used to elevate criticality scores of assets that underpin important services.
    """
    __tablename__ = "business_services"
    __table_args__ = (
        Index("ix_business_services_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    service_name: Mapped[str] = mapped_column(String(255))
    owner_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    impact_level: Mapped[str] = mapped_column(String(16), default="medium")
    # critical | high | medium | low
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class AssetServiceMap(TimestampMixin, Base):
    """Maps an asset to a business service with a dependency type."""
    __tablename__ = "asset_service_map"
    __table_args__ = (
        Index("ix_asset_service_map_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_asset_service_map_tenant_service", "tenant_id", "service_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    service_id: Mapped[int] = mapped_column(Integer, index=True)
    dependency_type: Mapped[str] = mapped_column(String(64), default="hosts")
    # hosts | depends_on | backup_for | part_of


class CrownJewelAsset(TimestampMixin, Base):
    """Explicitly designated crown jewel — triggers elevated alert thresholds."""
    __tablename__ = "crown_jewel_assets"
    __table_args__ = (
        Index("ix_crown_jewel_assets_tenant_asset", "tenant_id", "asset_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    designated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
