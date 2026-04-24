from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, String
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class NetworkScanJob(TimestampMixin, Base):
    __tablename__ = "network_scan_jobs"
    __table_args__ = (
        Index("ix_network_scan_jobs_tenant_status", "tenant_id", "status"),
    )
    id:           Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:    Mapped[str]        = mapped_column(String(128), index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target:       Mapped[str]        = mapped_column(String(255), index=True)
    status:       Mapped[str]        = mapped_column(String(32), default="queued")
    engine:       Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class NetworkDiscoveredAsset(TimestampMixin, Base):
    """
    Enterprise-grade unmanaged asset record.
    Matches the data model of Qualys / Rapid7 / Tenable agentless discovery.
    """
    __tablename__ = "network_discovered_assets"
    __table_args__ = (
        Index("ix_network_discovered_assets_tenant_ip",     "tenant_id", "ip_address"),
        Index("ix_network_discovered_assets_tenant_risk",   "tenant_id", "risk_level"),
        Index("ix_network_discovered_assets_tenant_type",   "tenant_id", "device_type"),
        Index("ix_network_discovered_assets_tenant_active", "tenant_id", "is_active"),
    )

    id:           Mapped[int]        = mapped_column(primary_key=True, autoincrement=True)
    tenant_id:    Mapped[str]        = mapped_column(String(128), index=True)
    scan_job_id:  Mapped[int | None] = mapped_column(nullable=True)

    # ── Identity ────────────────────────────────────────────────────────
    ip_address:   Mapped[str]        = mapped_column(String(64), index=True)
    hostname:     Mapped[str | None] = mapped_column(String(255), nullable=True)
    netbios_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mdns_name:    Mapped[str | None] = mapped_column(String(255), nullable=True)
    fqdn:         Mapped[str | None] = mapped_column(String(512), nullable=True)
    mac_address:  Mapped[str | None] = mapped_column(String(64), nullable=True)
    vendor:       Mapped[str | None] = mapped_column(String(255), nullable=True)  # OUI vendor
    device_type:  Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_family:Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── OS & Firmware ────────────────────────────────────────────────────
    os_guess:         Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version:       Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_cpe:           Mapped[str | None] = mapped_column(String(512), nullable=True)  # CPE string
    os_confidence:    Mapped[int | None] = mapped_column(Integer, nullable=True)       # 0-100
    firmware_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ttl:              Mapped[int | None] = mapped_column(Integer, nullable=True)       # TTL hint for OS

    # ── Network ──────────────────────────────────────────────────────────
    network_segment:  Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan:             Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway:          Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_internet_facing: Mapped[bool]     = mapped_column(Boolean, default=False)

    # ── Ports & Services ─────────────────────────────────────────────────
    open_ports:   Mapped[list[dict] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Enriched service list: [{port, service, product, version, banner, cpe}]
    services:     Mapped[list[dict] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # ── Protocol Intelligence ────────────────────────────────────────────
    snmp_data:    Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    http_headers: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    tls_info:     Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    banner_data:  Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    smb_info:     Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # ── Vulnerability Intelligence ────────────────────────────────────────
    # [{cve_id, cvss_score, cvss_vector, severity, title, description, solution, published}]
    vulnerabilities:      Mapped[list[dict] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    cve_count:            Mapped[int]   = mapped_column(Integer, default=0)
    critical_cve_count:   Mapped[int]   = mapped_column(Integer, default=0)
    high_cve_count:       Mapped[int]   = mapped_column(Integer, default=0)
    medium_cve_count:     Mapped[int]   = mapped_column(Integer, default=0)

    # ── Risk Scoring ──────────────────────────────────────────────────────
    risk_score:   Mapped[float | None] = mapped_column(Float, nullable=True)   # 0.0 - 10.0
    risk_level:   Mapped[str | None]   = mapped_column(String(16), nullable=True)  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    risk_hint:    Mapped[str | None]   = mapped_column(String(64), nullable=True)  # kept for compatibility
    risk_factors: Mapped[list | None]  = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # ["telnet_enabled", "default_creds_suspected", "rdp_exposed", ...]

    # ── Asset Lifecycle ───────────────────────────────────────────────────
    first_seen:       Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen:        Mapped[str | None] = mapped_column(String(64), nullable=True)
    managed:          Mapped[bool]       = mapped_column(Boolean, default=False)
    agent_installed:  Mapped[bool]       = mapped_column(Boolean, default=False)
    is_rogue:         Mapped[bool]       = mapped_column(Boolean, default=False)
    # Active inventory flag — True = found in latest scan, False = historical
    # This is the Qualys/Rapid7/Nessus active inventory pattern:
    # each scan marks all assets inactive, then marks discovered ones active.
    is_active:        Mapped[bool]       = mapped_column(Boolean, default=True, index=True)
    # Asset confidence level: confirmed_asset = has MAC/hostname/ports,
    # observed_host = ping-only, no identity signals
    asset_confidence: Mapped[str | None] = mapped_column(String(32), nullable=True, default="observed_host")

    # ── Raw Scan Data ─────────────────────────────────────────────────────
    raw_metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # ── CE v3.2 Compliance Flags ──────────────────────────────────────────
    ce_asset_registered:  Mapped[bool] = mapped_column(Boolean, default=False)
    ce_issues:            Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )  # ["unpatched_os", "telnet_enabled", "snmp_public", "rdp_exposed"]
