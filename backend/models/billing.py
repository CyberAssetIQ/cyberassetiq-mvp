"""billing.py

Subscription tier management and usage tracking.

Tiers:
  trial       — 14 days, up to 50 assets, free
  starter     — up to 50 assets,   £1,490/year
  growth      — up to 150 assets,  £1,990/year
  professional— up to 500 assets,  £2,990/year
  enterprise  — up to 1,000 assets,£3,990/year
  msp_starter — up to 10 clients,  £990/month
  msp_growth  — up to 25 clients,  £1,990/month
  msp_scale   — unlimited,         £3,490/month
  unlimited   — internal/dev/demo, no limits
"""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class TenantSubscription(TimestampMixin, Base):
    """One subscription record per tenant. Controls feature limits."""

    __tablename__ = "tenant_subscriptions"
    __table_args__ = (
        Index("ix_tenant_subscriptions_tenant", "tenant_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)

    # Plan / tier
    tier: Mapped[str] = mapped_column(String(32), default="trial")
    # trial | starter | growth | professional | enterprise | msp_starter | msp_growth | msp_scale | unlimited

    status: Mapped[str] = mapped_column(String(32), default="active")
    # active | trialing | past_due | cancelled | suspended

    # Billing period
    billing_period: Mapped[str] = mapped_column(String(16), default="annual")
    # annual | monthly

    # Dates
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Pricing (stored for audit trail — actual charge is in Stripe)
    price_gbp_pence: Mapped[int] = mapped_column(Integer, default=0)
    # Stored in pence: 149000 = £1,490

    # Stripe integration (populated when Stripe is connected)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stripe_price_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Override limits (for custom enterprise deals)
    custom_asset_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    custom_msp_client_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Notes (sales/support context)
    internal_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Cancellation
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageRecord(Base):
    """
    Daily usage snapshot per tenant.
    Recorded automatically by the background loop every 6 hours.
    Used for overage detection, analytics, and billing disputes.
    """

    __tablename__ = "usage_records"
    __table_args__ = (
        Index("ix_usage_records_tenant_date", "tenant_id", "recorded_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    # Asset counts
    managed_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    # CanonicalAsset rows (agent-enrolled devices)

    network_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    # NetworkDiscoveredAsset rows (agentless discovered devices)

    total_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    # managed + network (this is what tier limits are enforced on)

    # Module usage
    vuln_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    compliance_runs_count: Mapped[int] = mapped_column(Integer, default=0)
    darkweb_findings_count: Mapped[int] = mapped_column(Integer, default=0)
    api_calls_count: Mapped[int] = mapped_column(Integer, default=0)

    # Tier at time of recording (for audit)
    tier_at_record: Mapped[str] = mapped_column(String(32), default="trial")

    # Was over limit at time of recording?
    was_over_limit: Mapped[bool] = mapped_column(Boolean, default=False)
    over_limit_by: Mapped[int] = mapped_column(Integer, default=0)
