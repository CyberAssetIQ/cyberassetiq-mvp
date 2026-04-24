"""msp.py

Tables for MSP Portfolio Management (Phase 5).

msp_accounts        — MSP-level account records
msp_tenant_map      — links an MSP to the tenants it manages
tenant_health_scores — pre-computed per-tenant health snapshots for the portfolio view
portfolio_alerts    — MSP-level alerts aggregated across all managed tenants
"""
from __future__ import annotations

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class MSPAccount(TimestampMixin, Base):
    """An MSP organisation that manages multiple client tenants."""
    __tablename__ = "msp_accounts"
    __table_args__ = (
        Index("ix_msp_accounts_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True, unique=True)
    # The MSP's own tenant_id in the platform

    name: Mapped[str] = mapped_column(String(256))
    contact_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    website: Mapped[str | None] = mapped_column(String(256), nullable=True)

    role: Mapped[str] = mapped_column(String(32), default="msp")
    # msp | mssp | reseller

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    managed_tenants_count: Mapped[int] = mapped_column(Integer, default=0)

    plan: Mapped[str] = mapped_column(String(64), default="msp_standard")
    # msp_standard | msp_pro | msp_enterprise

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MSPTenantMap(TimestampMixin, Base):
    """Maps an MSP account to a client tenant it manages."""
    __tablename__ = "msp_tenant_map"
    __table_args__ = (
        Index("ix_msp_tenant_map_msp", "msp_account_id"),
        Index("ix_msp_tenant_map_managed", "managed_tenant_id"),
        Index("ix_msp_tenant_map_pair", "msp_account_id", "managed_tenant_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    msp_account_id: Mapped[int] = mapped_column(Integer, index=True)
    managed_tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    client_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    client_industry: Mapped[str | None] = mapped_column(String(64), nullable=True)

    relationship_type: Mapped[str] = mapped_column(String(32), default="managed")
    # managed | monitored | reseller | white_label

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    monthly_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    contract_start: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contract_end: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class TenantHealthScore(TimestampMixin, Base):
    """Pre-computed health snapshot for one managed tenant — used in MSP portfolio grid."""
    __tablename__ = "tenant_health_scores"
    __table_args__ = (
        Index("ix_tenant_health_scores_tenant", "tenant_id"),
        Index("ix_tenant_health_scores_updated", "tenant_id", "updated_at"),
        Index("ix_tenant_health_scores_overall", "tenant_id", "overall_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    msp_account_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    overall_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    # 0-100; higher = better

    exposure_score: Mapped[float] = mapped_column(Float, default=0.0)
    resilience_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    identity_score: Mapped[float] = mapped_column(Float, default=0.0)
    patch_score: Mapped[float] = mapped_column(Float, default=0.0)
    drift_score: Mapped[float] = mapped_column(Float, default=0.0)

    severity_band: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    # critical | high | medium | low | healthy

    # Headline stats for the portfolio grid (cached to avoid expensive JOINs)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    open_cves_count: Mapped[int] = mapped_column(Integer, default=0)
    unresolved_drift_count: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ce_compliance_pct: Mapped[float] = mapped_column(Float, default=0.0)

    delta_7d: Mapped[float] = mapped_column(Float, default=0.0)
    # score change over last 7 days; positive = improving

    score_breakdown_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    top_risks_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), index=True
    )


class PortfolioAlert(TimestampMixin, Base):
    """An alert aggregated at MSP level — visible in the MSP portfolio console."""
    __tablename__ = "portfolio_alerts"
    __table_args__ = (
        Index("ix_portfolio_alerts_msp", "msp_account_id"),
        Index("ix_portfolio_alerts_tenant", "tenant_id"),
        Index("ix_portfolio_alerts_severity", "msp_account_id", "severity"),
        Index("ix_portfolio_alerts_status", "msp_account_id", "status"),
        Index("ix_portfolio_alerts_created", "msp_account_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    msp_account_id: Mapped[int] = mapped_column(Integer, index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    # critical_exposure | ransomware_indicator | score_drop | compliance_failure
    # new_critical_cve | mass_drift | cloud_breach_indicator | crown_jewel_at_risk

    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    title: Mapped[str] = mapped_column(String(256))
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # open | acknowledged | resolved | suppressed

    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    acknowledged_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    resolved_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
