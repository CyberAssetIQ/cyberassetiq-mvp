"""models/agentic_loop.py

Supervised Agentic AI Loop — CyberAssetIQ

Architecture:
  AgentLoopRun   — one execution of the full context-gather + decision-brief cycle
  AgentLoopAction — individual actions the loop recommends, each with a tier and status

Action Tiers:
  tier_0 (automatic)   — safe, non-destructive: create investigation, notify team,
                          create incident, trigger rescan, send webhook
  tier_1 (one-click)   — reversible but impactful: isolate asset, force password reset,
                          disable user account, block IP
  tier_2 (deliberate)  — high-risk, requires typed confirmation: bulk account actions,
                          firewall rule changes, network segment changes

Philosophy:
  The agentic loop gathers context from ALL platform modules autonomously.
  It generates a structured decision brief using the AI provider.
  Tier 0 actions execute immediately.
  Tier 1/2 actions wait for explicit human approval.
  Every action — approved or rejected — is recorded immutably.
  The human is always in the loop for any destructive action.
"""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class AgentLoopRun(TimestampMixin, Base):
    """
    One complete execution of the supervised agentic loop.

    Triggered by: ai_alert, vuln_scan, darkweb_hit, drift_event,
                  incident_created, manual
    Lifecycle: pending → gathering → briefing → awaiting_approval →
               executing → completed | failed
    """

    __tablename__ = "agent_loop_runs"
    __table_args__ = (
        Index("ix_agent_loop_runs_tenant_status", "tenant_id", "status"),
        Index("ix_agent_loop_runs_trigger", "tenant_id", "trigger_type"),
        Index("ix_agent_loop_runs_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    # ── Trigger ───────────────────────────────────────────────────────────────
    trigger_type: Mapped[str] = mapped_column(String(64), default="manual")
    # ai_alert | vuln_scan | darkweb_hit | drift_event | incident_created | manual

    trigger_ref_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # ID of triggering record (alert_id, finding_id, etc.)

    trigger_ref_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "ai_alert" | "vuln_finding" | "darkweb_finding" | "drift_event"

    trigger_asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Primary asset the loop is investigating

    trigger_summary: Mapped[str] = mapped_column(Text, default="")
    # Human-readable description of what triggered this run

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | gathering | briefing | awaiting_approval | executing | completed | failed

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Context gathered ──────────────────────────────────────────────────────
    context_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Structured context gathered from all modules:
    # {
    #   "blast_radius": {...},
    #   "attack_graph": {...},
    #   "dark_web": {...},
    #   "identity_risk": {...},
    #   "open_cves": [...],
    #   "asset_criticality": {...},
    #   "external_exposure": {...}
    # }

    context_gathered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── AI Decision Brief ─────────────────────────────────────────────────────
    brief_title: Mapped[str | None] = mapped_column(String(256), nullable=True)
    brief_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # critical | high | medium | low

    brief_confidence: Mapped[int] = mapped_column(Integer, default=0)
    # 0-100 — AI confidence in its assessment

    brief_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # AI-generated plain-English summary of what is happening and why it matters

    brief_technical: Mapped[str | None] = mapped_column(Text, nullable=True)
    # AI-generated technical detail for security analysts

    brief_mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    brief_mitre_technique: Mapped[str | None] = mapped_column(String(64), nullable=True)

    brief_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    ai_model_used: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── Risk impact ───────────────────────────────────────────────────────────
    assessed_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    # AI-assessed risk score for this specific event (0-100)

    affected_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    crown_jewels_at_risk: Mapped[int] = mapped_column(Integer, default=0)

    # ── Actions summary ───────────────────────────────────────────────────────
    total_actions: Mapped[int] = mapped_column(Integer, default=0)
    auto_executed: Mapped[int] = mapped_column(Integer, default=0)
    # Tier 0 — executed automatically

    pending_approval: Mapped[int] = mapped_column(Integer, default=0)
    # Tier 1/2 — waiting for human

    approved_actions: Mapped[int] = mapped_column(Integer, default=0)
    rejected_actions: Mapped[int] = mapped_column(Integer, default=0)

    # ── Linked records ────────────────────────────────────────────────────────
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Incident created or linked by this run

    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # AIInvestigation created by this run

    # ── Approver ──────────────────────────────────────────────────────────────
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentLoopAction(Base):
    """
    A single recommended action from an agentic loop run.

    Tier 0: Auto-executed immediately — no approval required.
    Tier 1: One-click approval — reversible actions.
    Tier 2: Deliberate approval — requires typed confirmation string.

    Every action is recorded regardless of approval outcome.
    This provides a complete audit trail of what the AI recommended
    and what the human decided.
    """

    __tablename__ = "agent_loop_actions"
    __table_args__ = (
        Index("ix_agent_loop_actions_run", "run_id"),
        Index("ix_agent_loop_actions_tenant_status", "tenant_id", "status"),
        Index("ix_agent_loop_actions_tenant_tier", "tenant_id", "tier"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    run_id: Mapped[int] = mapped_column(Integer, index=True)
    # FK to agent_loop_runs.id — not enforced to avoid coupling

    # ── Action identity ───────────────────────────────────────────────────────
    action_type: Mapped[str] = mapped_column(String(64))
    # Tier 0: create_investigation | create_incident | notify_team | trigger_rescan | send_webhook
    # Tier 1: isolate_asset | force_password_reset | disable_account | block_ip
    # Tier 2: bulk_account_action | firewall_rule_change | network_segment_change

    tier: Mapped[int] = mapped_column(Integer, default=0)
    # 0 = automatic | 1 = one-click | 2 = deliberate

    title: Mapped[str] = mapped_column(String(256))
    # Human-readable action title: "Isolate WORKSTATION-04 from network"

    rationale: Mapped[str] = mapped_column(Text, default="")
    # Why the AI recommends this action

    expected_outcome: Mapped[str] = mapped_column(Text, default="")
    # What will happen if this action is approved and executed

    risk_reduction_estimate: Mapped[float] = mapped_column(Float, default=0.0)
    # Estimated risk score reduction (0-100) if this action is taken

    # ── Target ────────────────────────────────────────────────────────────────
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "asset" | "user" | "ip" | "account" | "service" | "network"

    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ID or identifier of the target

    target_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Display name: "WORKSTATION-04" or "john.smith@company.co.uk"

    action_params: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Execution parameters passed to the action handler

    # ── Status ────────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | auto_executed | approved | rejected | executing | completed | failed

    # ── Execution ─────────────────────────────────────────────────────────────
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Success message or error detail

    execution_ref_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ID of the created/triggered record (command_uuid, incident_id, etc.)

    # ── Human decision (Tier 1/2 only) ───────────────────────────────────────
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
