from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.mixins import Base, TimestampMixin


class Agent(TimestampMixin, Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    last_seen_epoch: Mapped[int | None] = mapped_column(nullable=True)

    # ── Per-agent trust key ──────────────────────────────────────────────────
    # A rotating secret scoped to this agent only. Distinct from the
    # tenant-level API keys in tenant_api_keys — rotating this does NOT
    # affect other agents or tenant authentication.
    # The plaintext is returned once on creation/rotation and never stored.
    # Only the hex value (effectively a hash-equivalent secret) is stored here.
    trust_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    trust_key_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trust_key_rotated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    policies = relationship("AgentPolicy", back_populates="agent", cascade="all, delete-orphan")


class AgentEnrollmentToken(TimestampMixin, Base):
    __tablename__ = "agent_enrollment_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    token_value: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Soft-delete / audit trail
    revoked_at:        Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_key_id: Mapped[int | None]      = mapped_column(nullable=True)
    revocation_reason: Mapped[str | None]      = mapped_column(String(255), nullable=True)


class AgentPolicy(TimestampMixin, Base):
    __tablename__ = "agent_policies"
    __table_args__ = (
        Index("ix_agent_policy_agent_id_active", "agent_id", "is_active"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_fk: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    policy_json: Mapped[dict] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    agent = relationship("Agent", back_populates="policies")
