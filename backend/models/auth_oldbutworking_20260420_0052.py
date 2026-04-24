from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class TenantAPIKey(TimestampMixin, Base):
    """
    Per-tenant API keys used to authenticate all backend requests.
    Keys are stored as SHA-256 hashes; plaintext is shown once at creation.
    """
    __tablename__ = "tenant_api_keys"
    __table_args__ = (
        Index("ix_tenant_api_keys_tenant_key", "tenant_id", "key_hash"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="agent")
    # role values: "agent" (telemetry only), "read" (assets/compliance read),
    #              "admin" (full access including key management)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_epoch: Mapped[int | None] = mapped_column(nullable=True)
    # Soft-delete / audit trail — never hard-delete keys
    revoked_at:        Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_key_id: Mapped[int | None]      = mapped_column(nullable=True)
    revocation_reason: Mapped[str | None]      = mapped_column(String(255), nullable=True)
