"""models/incident_response.py

Incident Response Lifecycle Module — C3

Tables:
  incidents             — master incident record with 7-phase state machine
  incident_timeline     — immutable audit log of every phase transition and action
  incident_assets       — assets linked to an incident (many-to-many with metadata)
  incident_reports      — generated IR reports (PDF path + structured content)

Phase state machine (linear with optional loops back for re-investigation):
  detected → triaged → investigating → containing → eradicating → recovering → closed

Allowed transitions:
  detected      → triaged
  triaged       → investigating
  investigating → containing
  containing    → eradicating
  eradicating   → recovering
  recovering    → closed
  any phase     → investigating  (re-open for further investigation)
  any phase     → closed         (admin force-close)
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


# ── Valid phase transitions ───────────────────────────────────────────────────

INCIDENT_PHASES = [
    "detected",
    "triaged",
    "investigating",
    "containing",
    "eradicating",
    "recovering",
    "closed",
]

ALLOWED_TRANSITIONS: dict[str, list[str]] = {
    "detected": ["triaged", "investigating", "closed"],
    "triaged": ["investigating", "closed"],
    "investigating": ["containing", "closed"],
    "containing": ["eradicating", "investigating", "closed"],
    "eradicating": ["recovering", "investigating", "closed"],
    "recovering": ["closed", "investigating"],
    "closed": ["investigating"],  # re-open
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]

INCIDENT_SOURCES = [
    "ai_alert",       # Triggered by AI detection engine
    "drift_trigger",  # Triggered by drift detection
    "vuln_scan",      # Triggered by vulnerability scan
    "darkweb_hit",    # Triggered by dark web credential exposure
    "manual",         # Manually created by analyst
    "integration",    # Triggered by Rapid7 / CrowdStrike / Qualys ingest
    "network_scan",   # Triggered by network anomaly
]


class Incident(TimestampMixin, Base):
    """
    Master incident record.

    Tracks an incident from first detection through to closure and reporting.
    Each phase transition is logged in IncidentTimeline.
    Assets involved are linked via IncidentAsset.
    AI investigation output is stored inline (summary fields) and linked by
    ai_investigation_id for the full structured report.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_tenant_phase", "tenant_id", "phase"),
        Index("ix_incidents_tenant_severity", "tenant_id", "severity"),
        Index("ix_incidents_tenant_assigned", "tenant_id", "assigned_to_user_id"),
        Index("ix_incidents_source", "tenant_id", "source"),
        Index("ix_incidents_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    # ── Identity ──────────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="high", index=True)
    # critical | high | medium | low | informational

    # ── Phase state machine ───────────────────────────────────────────────────
    phase: Mapped[str] = mapped_column(String(32), default="detected", index=True)
    # detected | triaged | investigating | containing | eradicating | recovering | closed

    phase_entered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # When the current phase was entered — used for SLA tracking

    # ── Source / trigger ─────────────────────────────────────────────────────
    source: Mapped[str] = mapped_column(String(64), default="manual", index=True)
    # ai_alert | drift_trigger | vuln_scan | darkweb_hit | manual | integration | network_scan

    source_ref_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # FK to the triggering record (alert id, drift id, etc.) — not enforced at DB level
    # to avoid cross-module coupling

    source_ref_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "ai_alert" | "drift_finding" | "vuln_scan" | "darkweb_finding" | …

    # ── Assignment ────────────────────────────────────────────────────────────
    assigned_to_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    assigned_to_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── AI Investigation linkage ──────────────────────────────────────────────
    ai_investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    # Points to ai_investigations.id — not FK-enforced to avoid coupling

    ai_executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Cached from AIInvestigation for fast list views

    ai_mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ai_mitre_technique: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Containment / Eradication ─────────────────────────────────────────────
    contain_command_ids: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # List of command IDs issued during containment phase

    remediation_action_ids: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # List of remediation_actions.id records linked to this incident

    # ── Rescan / Recovery verification ───────────────────────────────────────
    rescan_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rescan_verified_clean: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    rescan_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Reporting ─────────────────────────────────────────────────────────────
    report_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    # Points to incident_reports.id once generated

    # ── Risk impact ───────────────────────────────────────────────────────────
    estimated_risk_score_impact: Mapped[float] = mapped_column(Float, default=0.0)
    affected_asset_count: Mapped[int] = mapped_column(Integer, default=0)

    # ── Closure ───────────────────────────────────────────────────────────────
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    closure_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Provenance ────────────────────────────────────────────────────────────
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    # "system" | email of creating user

    # ── MITRE tags (summary level) ────────────────────────────────────────────
    mitre_tags_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # [{"tactic": "...", "technique": "...", "technique_id": "T1078"}]

    # ── Extra context ─────────────────────────────────────────────────────────
    tags_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Free-form tags ["ransomware", "lateral-movement", "supply-chain"]

    extra_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class IncidentTimeline(Base):
    """
    Immutable audit log for an incident.

    Every phase transition, AI action, command, assignment change, and
    analyst note appends a row here. Never updated — append only.
    """

    __tablename__ = "incident_timeline"
    __table_args__ = (
        Index("ix_incident_timeline_incident", "incident_id"),
        Index("ix_incident_timeline_tenant", "tenant_id"),
        Index("ix_incident_timeline_event_type", "tenant_id", "event_type"),
        Index("ix_incident_timeline_created", "incident_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )

    # ── Event classification ──────────────────────────────────────────────────
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    # phase_transition | ai_investigation | containment_command | remediation_applied
    # rescan_triggered | rescan_completed | report_generated | analyst_note
    # assignment_changed | severity_changed | asset_linked | asset_unlinked

    # ── Phase context (for phase_transition events) ───────────────────────────
    from_phase: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_phase: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ── Human-readable summary ────────────────────────────────────────────────
    summary: Mapped[str] = mapped_column(Text)
    # e.g. "Phase advanced to containing. Isolation command issued to ASSET-042."

    # ── Actor ─────────────────────────────────────────────────────────────────
    actor: Mapped[str] = mapped_column(String(128), default="system")
    # "system" | user email | "ai-engine"

    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Linked reference ─────────────────────────────────────────────────────
    ref_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "command" | "remediation_action" | "ai_investigation" | "rescan_job" | "report"

    ref_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ID of the linked record (string to accommodate UUIDs and ints)

    # ── Structured payload ────────────────────────────────────────────────────
    detail_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Arbitrary structured data for the event type

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class IncidentAsset(Base):
    """
    Join table linking assets to an incident.

    Stores the role the asset played (e.g. initial_vector, lateral_hop,
    crown_jewel) and whether it has been confirmed clean post-recovery.
    """

    __tablename__ = "incident_assets"
    __table_args__ = (
        Index("ix_incident_assets_incident", "incident_id"),
        Index("ix_incident_assets_asset", "asset_id"),
        Index("ix_incident_assets_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[int] = mapped_column(Integer, index=True)

    # ── Role of this asset in the incident ───────────────────────────────────
    asset_role: Mapped[str] = mapped_column(String(64), default="affected")
    # initial_vector | lateral_hop | crown_jewel | c2_target | affected | data_exfil

    # ── Containment state ────────────────────────────────────────────────────
    is_contained: Mapped[bool] = mapped_column(Boolean, default=False)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contain_command_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── Recovery state ────────────────────────────────────────────────────────
    is_clean: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # None = not yet rescanned; True = confirmed clean; False = still dirty

    verified_clean_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Notes ─────────────────────────────────────────────────────────────────
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    added_by: Mapped[str] = mapped_column(String(128), default="system")


class IncidentReport(Base):
    """
    Generated IR report for a closed (or in-progress) incident.

    Stores both the PDF path and the structured JSON content so the
    report can be re-rendered without re-running the AI.
    """

    __tablename__ = "incident_reports"
    __table_args__ = (
        Index("ix_incident_reports_incident", "incident_id"),
        Index("ix_incident_reports_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )

    # ── Report metadata ───────────────────────────────────────────────────────
    report_type: Mapped[str] = mapped_column(String(32), default="full")
    # full | executive | technical

    generated_by: Mapped[str] = mapped_column(String(128), default="system")
    # "system" | user email

    # ── File storage ─────────────────────────────────────────────────────────
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Relative path under /app/reports/ e.g. "incidents/tenant-001/IR-42-full.pdf"

    # ── Structured content ────────────────────────────────────────────────────
    report_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Full structured report content:
    # {
    #   "executive_summary": "...",
    #   "timeline": [...],
    #   "affected_assets": [...],
    #   "mitre_mapping": [...],
    #   "containment_actions": [...],
    #   "remediation_applied": [...],
    #   "root_cause": "...",
    #   "recommendations": [...],
    #   "lessons_learned": "..."
    # }

    # ── AI generation metadata ────────────────────────────────────────────────
    model_used: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )