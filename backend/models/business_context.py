"""business_context.py

Business context enrichment tables — allows assets to be mapped to
business services, data classifications, and owner information.
Cross-cutting model referenced by criticality, risk engine, and MSP modules.
"""
from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class DataClassification(TimestampMixin, Base):
    """Data classification labels that can be assigned to assets."""
    __tablename__ = "data_classifications"
    __table_args__ = (
        Index("ix_data_classifications_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    label: Mapped[str] = mapped_column(String(64))
    # PII | PHI | PCI | Confidential | Internal | Public | Trade_Secret

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensitivity_level: Mapped[int] = mapped_column(Integer, default=1)
    # 1=Public, 2=Internal, 3=Confidential, 4=Highly Confidential, 5=Restricted

    applicable_frameworks: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AssetBusinessContext(TimestampMixin, Base):
    """Business context enrichment for a canonical or network-discovered asset."""
    __tablename__ = "asset_business_context"
    __table_args__ = (
        Index("ix_asset_business_context_tenant_asset", "tenant_id", "asset_id", unique=True),
        Index("ix_asset_business_context_owner", "tenant_id", "owner_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)

    asset_type_override: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # workstation | server | domain_controller | database | file_server | print_server
    # web_server | build_server | backup_server | network_device | iot | unknown

    owner_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str | None] = mapped_column(String(128), nullable=True)

    data_classifications: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # ["PII", "PHI"]

    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    is_in_dmz: Mapped[bool] = mapped_column(Boolean, default=False)
    is_production: Mapped[bool] = mapped_column(Boolean, default=True)

    sla_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # gold | silver | bronze

    custom_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_tags_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
