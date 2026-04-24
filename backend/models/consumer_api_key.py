"""consumer_api_key.py — SQLAlchemy model for external consumer API keys."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base


class ConsumerAPIKey(Base):
    """
    API key issued to an external posture consumer (broker, buyer, auditor).
    Separate from tenant TenantAPIKey — consumers get read-only scoped access.
    """
    __tablename__ = "consumer_api_keys"

    id:               Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    consumer_id:      Mapped[int]      = mapped_column(Integer, index=True, nullable=False)
    key_hash:         Mapped[str]      = mapped_column(String(128), unique=True, nullable=False)
    label:            Mapped[str]      = mapped_column(String(255), nullable=False, default="")
    permitted_tenants: Mapped[list]    = mapped_column(JSON, nullable=False, default=list)
    is_active:        Mapped[bool]     = mapped_column(Boolean, nullable=False, default=True)
    issued_at:        Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at:       Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    use_count:        Mapped[int]      = mapped_column(Integer, default=0)
