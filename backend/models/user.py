"""models/user.py

Named user management for CyberAssetIQ tenants.

Architecture:
  - TenantUser: named user with email + hashed password + role
  - UserInvitation: invite token for new user onboarding
  - AuthenticatedRequest is extended to carry user_id alongside tenant_id

This coexists with the existing API key system (TenantAPIKey):
  - Human users log in with email + password → receive JWT
  - Programmatic clients (agents, integrations) continue to use API keys
  - Both resolve to the same AuthenticatedRequest interface
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class TenantUser(TimestampMixin, Base):
    """
    A named user account within a tenant.
    Users authenticate with email + password and receive a JWT.
    """

    __tablename__ = "tenant_users"
    __table_args__ = (
        Index("ix_tenant_users_tenant_email", "tenant_id", "email", unique=True),
        Index("ix_tenant_users_email", "email"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    # Identity
    email: Mapped[str] = mapped_column(String(256), index=True)
    full_name: Mapped[str] = mapped_column(String(256), default="")
    password_hash: Mapped[str] = mapped_column(String(256))
    # bcrypt hash — never store plaintext

    # Role — mirrors existing API key roles
    role: Mapped[str] = mapped_column(String(32), default="read")
    # admin | read
    # Note: 'agent' role is reserved for API keys only, not human users

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Provenance
    invited_by_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # NULL = first admin (created via bootstrap or migration)

    # Activity
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    login_count: Mapped[int] = mapped_column(Integer, default=0)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Optional: profile
    job_title: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserInvitation(Base):
    """
    Invitation token sent to a new user.
    Invitee follows the link → sets password → TenantUser record is created.
    Tokens expire after 72 hours and are single-use.
    """

    __tablename__ = "user_invitations"
    __table_args__ = (
        Index("ix_user_invitations_token", "token_hash", unique=True),
        Index("ix_user_invitations_tenant_email", "tenant_id", "email"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    email: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="read")

    # Token (SHA-256 of the plaintext token — plaintext sent in email link)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)

    # Who sent the invite
    invited_by_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    invited_by_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Lifecycle
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)

    # Optional personal message
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
