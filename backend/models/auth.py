from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String
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


class RevokedToken(Base):
    """
    JWT token blacklist — allows immediate logout.
    The jti (JWT ID) claim is stored on revocation; the decode path checks
    this table so compromised or logged-out tokens are rejected instantly.
    Expired-by-time tokens are cleaned up by the nightly schedule job.
    """
    __tablename__ = "revoked_tokens"

    id:           Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    jti:          Mapped[str]      = mapped_column(String(128), unique=True, index=True)
    tenant_id:    Mapped[str]      = mapped_column(String(128), index=True)
    revoked_at:   Mapped[int]      = mapped_column()   # epoch
    expires_at:   Mapped[int]      = mapped_column()   # epoch — for cleanup


class PasswordResetToken(Base):
    """
    Short-lived single-use tokens for password reset emails.
    """
    __tablename__ = "password_reset_tokens"

    id:           Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:    Mapped[str]      = mapped_column(String(128), index=True)
    user_id:      Mapped[int]      = mapped_column()
    token_hash:   Mapped[str]      = mapped_column(String(255), unique=True, index=True)
    used:         Mapped[bool]     = mapped_column(default=False)
    created_at:   Mapped[int]      = mapped_column()   # epoch
    expires_at:   Mapped[int]      = mapped_column()   # epoch  (15 min)
