from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class DarkWebWatchlist(TimestampMixin, Base):
    __tablename__ = "darkweb_watchlists"
    __table_args__ = (
        Index("ix_darkweb_watchlists_tenant_type_value", "tenant_id", "watch_type", "watch_value", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    watch_type: Mapped[str] = mapped_column(String(32), index=True)
    watch_value: Mapped[str] = mapped_column(String(255), index=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    is_active: Mapped[bool] = mapped_column(default=True)


class DarkWebSourceItem(TimestampMixin, Base):
    __tablename__ = "darkweb_source_items"
    __table_args__ = (
        Index("ix_darkweb_source_items_tenant_source_ref", "tenant_id", "source_ref", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_ref: Mapped[str] = mapped_column(String(255), index=True)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_text: Mapped[str] = mapped_column(Text)
    raw_metadata_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)


class DarkWebFinding(TimestampMixin, Base):
    __tablename__ = "darkweb_findings"
    __table_args__ = (
        Index("ix_darkweb_findings_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    watchlist_id: Mapped[int | None] = mapped_column(nullable=True)
    source_item_id: Mapped[int | None] = mapped_column(nullable=True)
    finding_type: Mapped[str] = mapped_column(String(32), index=True)
    matched_value: Mapped[str] = mapped_column(String(255), index=True)
    context_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="open")
    raw_metadata_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
