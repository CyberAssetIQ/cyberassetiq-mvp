from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Index, String
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class ScanJob(TimestampMixin, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_type: Mapped[str] = mapped_column(String(64), default="run_scan_full")
    status: Mapped[str] = mapped_column(String(32), default="queued")
    target_count: Mapped[int] = mapped_column(default=1)
    completed_count: Mapped[int] = mapped_column(default=0)
    failed_count: Mapped[int] = mapped_column(default=0)
    arguments_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)


class AgentCommand(TimestampMixin, Base):
    __tablename__ = "agent_commands"
    __table_args__ = (
        Index("ix_agent_commands_agent_status", "tenant_id", "agent_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    command_uuid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    command_type: Mapped[str] = mapped_column(String(64), index=True)
    arguments_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    priority: Mapped[str] = mapped_column(String(16), default="normal")
    expires_epoch: Mapped[int | None] = mapped_column(nullable=True)
    acked_epoch: Mapped[int | None] = mapped_column(nullable=True)
    started_epoch: Mapped[int | None] = mapped_column(nullable=True)
    completed_epoch: Mapped[int | None] = mapped_column(nullable=True)
    delivery_count: Mapped[int] = mapped_column(default=0)
    result_json: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
