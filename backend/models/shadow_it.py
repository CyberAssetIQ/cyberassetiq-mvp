"""shadow_it.py

Tables for Shadow IT Detection (Phase 3).

shadow_it_findings        — general unapproved/unknown entities
rogue_software_findings   — unapproved software installed on managed assets
unknown_device_findings   — devices seen on the network not in the asset register
"""
from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, Float, DateTime, Boolean
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class ShadowITFinding(TimestampMixin, Base):
    """General shadow IT finding — unapproved SaaS, unknown tools, rogue accounts."""
    __tablename__ = "shadow_it_findings"
    __table_args__ = (
        Index("ix_shadow_it_findings_tenant", "tenant_id"),
        Index("ix_shadow_it_findings_type", "tenant_id", "finding_type"),
        Index("ix_shadow_it_findings_status", "tenant_id", "status"),
        Index("ix_shadow_it_findings_risk", "tenant_id", "risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    # unapproved_saas | rogue_software | unknown_device | shadow_admin
    # unauthorized_cloud_storage | personal_email_in_use | vpn_bypass

    entity_name: Mapped[str] = mapped_column(String(256))
    entity_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # productivity | communication | storage | development | ai_tool | social | vpn | other

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # open | approved | remediated | false_positive | under_review

    is_data_exfil_risk: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_compliance_risk: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RogueSoftwareFinding(TimestampMixin, Base):
    """Software installed on a managed asset that is not on the approved list."""
    __tablename__ = "rogue_software_findings"
    __table_args__ = (
        Index("ix_rogue_software_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_rogue_software_tenant_name", "tenant_id", "software_name"),
        Index("ix_rogue_software_status", "tenant_id", "approved_status"),
        Index("ix_rogue_software_risk", "tenant_id", "risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int] = mapped_column(Integer, index=True)

    software_name: Mapped[str] = mapped_column(String(256), index=True)
    software_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(256), nullable=True)
    install_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # remote_access | vpn | p2p | cryptocurrency | hacking_tool | ai_tool
    # productivity | media | game | browser_extension | unknown

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_flags: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # ["known_data_exfil", "remote_access_capable", "no_vendor", "eol_software"]

    approved_status: Mapped[str] = mapped_column(String(32), default="unapproved", index=True)
    # unapproved | approved | blacklisted | under_review

    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    has_known_cves: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UnknownDeviceFinding(TimestampMixin, Base):
    """Network-visible device not found in the managed asset register."""
    __tablename__ = "unknown_device_findings"
    __table_args__ = (
        Index("ix_unknown_device_tenant", "tenant_id"),
        Index("ix_unknown_device_ip", "tenant_id", "ip_address"),
        Index("ix_unknown_device_risk", "tenant_id", "risk_score"),
        Index("ix_unknown_device_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    network_segment: Mapped[str | None] = mapped_column(String(64), nullable=True)

    device_type_guess: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # workstation | server | printer | iot | mobile | router | switch | unknown

    open_ports: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    vendor_oui: Mapped[str | None] = mapped_column(String(128), nullable=True)

    risk_score: Mapped[float] = mapped_column(Float, default=5.0, index=True)
    risk_flags: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # ["admin_port_open", "no_hostname", "non_standard_subnet", "mac_spoofing_indicator"]

    status: Mapped[str] = mapped_column(String(32), default="unresolved", index=True)
    # unresolved | registered | approved_guest | false_positive | remediated

    source_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
