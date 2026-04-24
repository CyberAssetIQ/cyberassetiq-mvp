"""remediation.py

Tables for Remediation Automation Expansion (Phase 3).

remediation_actions   — individual executable actions with safety classification
remediation_playbooks — multi-step automated response playbooks
remediation_runs      — execution log for every triggered action/playbook
remediation_approvals — approval workflow for high-risk or manual-only actions
"""
from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text, DateTime, Float
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class RemediationAction(TimestampMixin, Base):
    """A discrete remediation action targeting one asset."""
    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("ix_remediation_actions_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_remediation_actions_tenant_status", "tenant_id", "status"),
        Index("ix_remediation_actions_action_type", "tenant_id", "action_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    action_type: Mapped[str] = mapped_column(String(64), index=True)
    # disable_rdp | disable_smbv1 | stop_service | isolate_host | remove_local_admin
    # rotate_secret | uninstall_software | patch_now | enable_firewall | enable_av
    # create_investigation | trigger_rescan | send_webhook | manual_only

    parameters_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    safety_level: Mapped[str] = mapped_column(String(32), default="informational", index=True)
    # informational | auto_safe | approval_required | manual_only

    source: Mapped[str] = mapped_column(String(64), default="manual", index=True)
    # manual | ai_recommendation | drift_trigger | risk_engine | playbook

    trigger_finding_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trigger_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    created_by: Mapped[str] = mapped_column(String(128), default="system")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | approved | running | completed | failed | rejected | cancelled

    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_score_gain: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    executed_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemediationPlaybook(TimestampMixin, Base):
    """A reusable multi-step automated response playbook."""
    __tablename__ = "remediation_playbooks"
    __table_args__ = (
        Index("ix_remediation_playbooks_tenant", "tenant_id"),
        Index("ix_remediation_playbooks_trigger", "tenant_id", "trigger_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    playbook_name: Mapped[str] = mapped_column(String(128))

    trigger_type: Mapped[str] = mapped_column(String(64), index=True)
    # drift_new_admin | drift_new_port | high_cvss_cve | ransomware_indicator
    # credential_leak | critical_exposure | manual

    trigger_condition_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    steps_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # [ { "action_type": "disable_rdp", "parameters": {}, "safety_level": "auto_safe" }, ... ]

    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class RemediationRun(TimestampMixin, Base):
    """Execution log for a playbook or individual action run."""
    __tablename__ = "remediation_runs"
    __table_args__ = (
        Index("ix_remediation_runs_tenant", "tenant_id"),
        Index("ix_remediation_runs_playbook", "tenant_id", "playbook_id"),
        Index("ix_remediation_runs_action", "tenant_id", "action_id"),
        Index("ix_remediation_runs_status", "tenant_id", "result_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    playbook_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    result_status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    # running | completed | failed | partial | cancelled

    execution_log_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    triggered_by: Mapped[str] = mapped_column(String(128), default="system")
    started_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    ended_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RemediationApproval(TimestampMixin, Base):
    """Approval record for actions requiring human sign-off."""
    __tablename__ = "remediation_approvals"
    __table_args__ = (
        Index("ix_remediation_approvals_tenant", "tenant_id"),
        Index("ix_remediation_approvals_action", "tenant_id", "action_id"),
        Index("ix_remediation_approvals_status", "tenant_id", "approval_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    action_id: Mapped[int] = mapped_column(Integer, index=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="system")
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approval_status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | approved | rejected | expired
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
