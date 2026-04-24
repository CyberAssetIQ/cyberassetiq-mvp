from __future__ import annotations

"""
CyberAssetIQ — Scan Schedules Model
Stores recurring scan schedules for network discovery, CVE scans,
and threat intelligence scans. Background loop in app.py executes
them when due.
"""

from sqlalchemy import Boolean, Index, Integer, String, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class ScanSchedule(TimestampMixin, Base):
    """
    Recurring scan schedule. Supported scan types:
      - network_scan   : Run nmap + mDNS + SSDP discovery
      - vuln_scan      : Run CVE correlation against software inventory
      - threat_intel   : Run Shodan + CISA KEV + HIBP checks
      - agent_scan     : Trigger full agent collection on all enrolled agents
    """
    __tablename__ = "scan_schedules"
    __table_args__ = (
        Index("ix_scan_schedules_tenant_active", "tenant_id", "is_active"),
    )

    id:           Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:    Mapped[str]        = mapped_column(String(128), index=True)
    name:         Mapped[str]        = mapped_column(String(255))
    scan_type:    Mapped[str]        = mapped_column(String(64))   # network_scan | vuln_scan | threat_intel | agent_scan
    target:       Mapped[str | None] = mapped_column(String(255), nullable=True)  # CIDR for network scans
    interval_hours: Mapped[int]      = mapped_column(Integer, default=24)         # how often to run
    is_active:    Mapped[bool]       = mapped_column(Boolean, default=True)
    last_run_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)    # unix timestamp of last run
    next_run_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)    # unix timestamp of next run
    last_status:  Mapped[str | None] = mapped_column(String(64), nullable=True)   # completed | failed | running
    last_result:  Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    config:       Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # extra config (e.g. agent_ids for agent scans)
