from __future__ import annotations

"""
SQLAlchemy models for the immutable scan history architecture.

  VulnScanRun    — one row per scan execution (immutable header)
  VulnAnnotation — user actions on CVEs (mutable, audit trail)

vulnerability_findings rows are immutable after creation and linked
to a VulnScanRun via scan_run_id. Annotations are a separate concern
and never block findings from appearing — they only add context badges.
"""

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class VulnScanRun(TimestampMixin, Base):
    """Immutable header row created at the start of each NVD scan.
    Updated once at completion with final CVE counts.
    Never mutated again after status='complete'.
    """
    __tablename__ = "vuln_scan_runs"
    __table_args__ = (
        Index("ix_vuln_scan_runs_tenant_epoch", "tenant_id", "scan_epoch"),
    )

    id:               Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:        Mapped[str]      = mapped_column(String(128), index=True)
    scan_epoch:       Mapped[int]      = mapped_column(Integer)
    packages_scanned: Mapped[int]      = mapped_column(Integer, default=0)
    total_packages:   Mapped[int]      = mapped_column(Integer, default=0)
    total_cves:       Mapped[int]      = mapped_column(Integer, default=0)
    critical_count:   Mapped[int]      = mapped_column(Integer, default=0)
    high_count:       Mapped[int]      = mapped_column(Integer, default=0)
    medium_count:     Mapped[int]      = mapped_column(Integer, default=0)
    low_count:        Mapped[int]      = mapped_column(Integer, default=0)
    status:           Mapped[str]      = mapped_column(String(32), default="complete")
    warning:          Mapped[str|None] = mapped_column(Text, nullable=True)


class VulnAnnotation(TimestampMixin, Base):
    """Mutable user annotation on a specific CVE/agent combination.
    One annotation per (tenant_id, cve_id, agent_id) — upserted on change.
    Provides the full audit trail for all user actions across all scan runs.

    status values: resolved | accepted_risk | false_positive | open
    """
    __tablename__ = "vuln_annotations"
    __table_args__ = (
        Index("ix_vuln_annotations_tenant_cve", "tenant_id", "cve_id"),
    )

    id:              Mapped[int]      = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:       Mapped[str]      = mapped_column(String(128), index=True)
    cve_id:          Mapped[str]      = mapped_column(String(32), index=True)
    agent_id:        Mapped[str|None] = mapped_column(String(128), nullable=True)
    software_name:   Mapped[str|None] = mapped_column(String(255), nullable=True)
    status:          Mapped[str]      = mapped_column(String(32))
    annotated_by:    Mapped[str|None] = mapped_column(String(255), nullable=True)
    annotated_epoch: Mapped[int]      = mapped_column(Integer)
    note:            Mapped[str|None] = mapped_column(Text, nullable=True)
