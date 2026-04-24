"""billing_service.py

Business logic for subscription tier management and usage enforcement.

Key responsibilities:
  - get_or_create_subscription  — returns subscription, creates trial if none exists
  - get_plan_limits             — returns the limits dict for a given tier
  - check_asset_limit           — raises HTTP 402 if tenant is over limit
  - record_usage_snapshot       — saves current usage to usage_records
  - get_usage_summary           — returns current usage vs limits
  - upgrade_tier                — changes tier (admin action)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from models.billing import TenantSubscription, UsageRecord
from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset

logger = logging.getLogger("cyberassetiq.billing")

# ---------------------------------------------------------------------------
# Plan catalogue
# ---------------------------------------------------------------------------

PLANS: dict[str, dict[str, Any]] = {
    "trial": {
        "name":              "Free Trial",
        "description":       "14-day full-feature trial. No credit card required.",
        "asset_limit":       50,
        "msp_client_limit":  0,
        "price_gbp_pence":   0,
        "billing_period":    "trial",
        "trial_days":        14,
        "features": [
            "All 46 platform modules",
            "Up to 50 assets",
            "1 Windows agent",
            "CE v4 Danzell assessment",
            "AI Security Intelligence",
            "Email support",
        ],
    },
    "starter": {
        "name":              "Starter",
        "description":       "For micro-SMEs and single-site organisations.",
        "asset_limit":       50,
        "msp_client_limit":  0,
        "price_gbp_pence":   149000,   # £1,490
        "billing_period":    "annual",
        "features": [
            "All 46 platform modules",
            "Up to 50 assets",
            "Unlimited Windows agents",
            "CE v4 Danzell + NCSC CAF",
            "AI Security Intelligence",
            "Dark web monitoring",
            "Email support",
        ],
    },
    "growth": {
        "name":              "Growth",
        "description":       "For small SMEs with multiple sites or departments.",
        "asset_limit":       150,
        "msp_client_limit":  0,
        "price_gbp_pence":   199000,   # £1,990
        "billing_period":    "annual",
        "features": [
            "All Starter features",
            "Up to 150 assets",
            "Attack Graph + Blast Radius",
            "Supply Chain portal",
            "Insurance Broker API",
            "Priority email support",
        ],
    },
    "professional": {
        "name":              "Professional",
        "description":       "For mid-size SMEs with complex IT estates.",
        "asset_limit":       500,
        "msp_client_limit":  0,
        "price_gbp_pence":   299000,   # £2,990
        "billing_period":    "annual",
        "features": [
            "All Growth features",
            "Up to 500 assets",
            "All 25 integration connectors",
            "AI Compliance Intelligence (ISO 27001 + GDPR)",
            "Executive Reporting",
            "MSP Portfolio (up to 5 clients)",
            "Phone + email support",
        ],
    },
    "enterprise": {
        "name":              "Enterprise",
        "description":       "For large SMEs approaching enterprise scale.",
        "asset_limit":       1000,
        "msp_client_limit":  0,
        "price_gbp_pence":   399000,   # £3,990
        "billing_period":    "annual",
        "features": [
            "All Professional features",
            "Up to 1,000 assets",
            "Custom integration development",
            "Dedicated account manager",
            "SLA: 4-hour response",
            "Custom compliance framework mapping",
        ],
    },
    "msp_starter": {
        "name":              "MSP Starter",
        "description":       "For managed service providers with up to 10 SME clients.",
        "asset_limit":       50,       # per client
        "msp_client_limit":  10,
        "price_gbp_pence":   99000,    # £990/month
        "billing_period":    "monthly",
        "features": [
            "Up to 10 managed clients",
            "Portfolio dashboard",
            "Aggregated alerts",
            "Per-client posture records",
            "CE v4 + CAF for all clients",
            "White-label ready",
        ],
    },
    "msp_growth": {
        "name":              "MSP Growth",
        "description":       "For MSPs with up to 25 SME clients.",
        "asset_limit":       150,      # per client
        "msp_client_limit":  25,
        "price_gbp_pence":   199000,   # £1,990/month
        "billing_period":    "monthly",
        "features": [
            "All MSP Starter features",
            "Up to 25 managed clients",
            "Bulk posture refresh",
            "Aggregated threat intelligence",
            "Co-managed SOC tools",
        ],
    },
    "msp_scale": {
        "name":              "MSP Scale",
        "description":       "Unlimited clients. White-label branding.",
        "asset_limit":       500,      # per client
        "msp_client_limit":  -1,       # unlimited
        "price_gbp_pence":   349000,   # £3,490/month
        "billing_period":    "monthly",
        "features": [
            "All MSP Growth features",
            "Unlimited managed clients",
            "White-label branding",
            "Custom domain",
            "API access for RMM integration",
            "Dedicated technical account manager",
        ],
    },
    "unlimited": {
        "name":              "Unlimited (Internal)",
        "description":       "Development, demo, and internal accounts. No limits enforced.",
        "asset_limit":       -1,       # unlimited
        "msp_client_limit":  -1,
        "price_gbp_pence":   0,
        "billing_period":    "none",
        "features":          ["No limits — internal/demo use only"],
    },
}

PLAN_ORDER = ["trial", "starter", "growth", "professional", "enterprise"]


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def get_plan_limits(tier: str) -> dict[str, Any]:
    """Return the limits and pricing for a given tier."""
    return PLANS.get(tier, PLANS["trial"])


def get_or_create_subscription(db: Session, tenant_id: str) -> TenantSubscription:
    """
    Return the existing subscription for a tenant.
    If none exists, create a 14-day trial automatically.
    """
    sub = (
        db.query(TenantSubscription)
        .filter(TenantSubscription.tenant_id == tenant_id)
        .first()
    )
    if sub:
        return sub

    # Auto-create trial
    now = datetime.now(timezone.utc)
    sub = TenantSubscription(
        tenant_id=tenant_id,
        tier="trial",
        status="trialing",
        billing_period="trial",
        price_gbp_pence=0,
        trial_ends_at=now + timedelta(days=14),
        current_period_start=now,
        current_period_end=now + timedelta(days=14),
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    logger.info("Created trial subscription for tenant %s", tenant_id)
    return sub


def _get_asset_count(db: Session, tenant_id: str) -> dict[str, int]:
    """Count managed and network-discovered assets for a tenant."""
    managed = (
        db.query(func.count(CanonicalAsset.id))
        .filter(CanonicalAsset.tenant_id == tenant_id)
        .scalar() or 0
    )
    network = (
        db.query(func.count(NetworkDiscoveredAsset.id))
        .filter(NetworkDiscoveredAsset.tenant_id == tenant_id)
        .scalar() or 0
    )
    return {
        "managed": managed,
        "network": network,
        "total": managed + network,
    }


def check_asset_limit(db: Session, tenant_id: str, adding: int = 0) -> None:
    """
    Check if the tenant is within their asset limit.
    Call this before enrolling a new agent or importing assets.
    Raises HTTP 402 if over limit.

    adding: how many new assets are about to be added (default 0 = just check current state)
    """
    sub = get_or_create_subscription(db, tenant_id)

    # Check trial expiry
    if sub.tier == "trial" and sub.status == "trialing":
        now = datetime.now(timezone.utc)
        trial_end = sub.trial_ends_at
        if trial_end and trial_end.replace(tzinfo=timezone.utc) < now:
            sub.status = "cancelled"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "error": "trial_expired",
                    "message": "Your 14-day trial has expired. Upgrade to a paid plan to continue.",
                    "upgrade_url": "/api/billing/plans",
                    "tenant_id": tenant_id,
                },
            )

    # unlimited tier — no enforcement
    limits = get_plan_limits(sub.tier)
    asset_limit = sub.custom_asset_limit if sub.custom_asset_limit else limits["asset_limit"]

    if asset_limit == -1:
        return  # unlimited

    counts = _get_asset_count(db, tenant_id)
    current_total = counts["total"] + adding

    if current_total > asset_limit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "asset_limit_exceeded",
                "message": (
                    f"Your {limits['name']} plan allows up to {asset_limit} assets. "
                    f"You currently have {counts['total']} assets"
                    + (f" and are attempting to add {adding} more." if adding else ".")
                    + " Upgrade your plan to add more assets."
                ),
                "current_count": counts["total"],
                "limit": asset_limit,
                "tier": sub.tier,
                "upgrade_url": "/api/billing/plans",
            },
        )


def get_usage_summary(db: Session, tenant_id: str) -> dict[str, Any]:
    """Return current usage vs limits for the tenant."""
    sub = get_or_create_subscription(db, tenant_id)
    limits = get_plan_limits(sub.tier)
    counts = _get_asset_count(db, tenant_id)

    asset_limit = sub.custom_asset_limit if sub.custom_asset_limit else limits["asset_limit"]
    usage_pct = (
        round((counts["total"] / asset_limit) * 100, 1)
        if asset_limit > 0 else 0.0
    )
    at_limit = asset_limit != -1 and counts["total"] >= asset_limit

    # Trial days remaining
    trial_days_remaining = None
    if sub.tier == "trial" and sub.trial_ends_at:
        now = datetime.now(timezone.utc)
        delta = sub.trial_ends_at.replace(tzinfo=timezone.utc) - now
        trial_days_remaining = max(0, delta.days)

    return {
        "tenant_id": tenant_id,
        "tier": sub.tier,
        "tier_name": limits["name"],
        "status": sub.status,
        "billing_period": sub.billing_period,
        "price_gbp": limits["price_gbp_pence"] / 100,
        "assets": {
            "managed": counts["managed"],
            "network": counts["network"],
            "total": counts["total"],
            "limit": asset_limit,
            "usage_percent": usage_pct,
            "at_limit": at_limit,
            "unlimited": asset_limit == -1,
        },
        "trial_days_remaining": trial_days_remaining,
        "current_period_start": sub.current_period_start.isoformat() if sub.current_period_start else None,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "cancel_at_period_end": sub.cancel_at_period_end,
        "stripe_customer_id": sub.stripe_customer_id,
        "stripe_subscription_id": sub.stripe_subscription_id,
        "features": limits["features"],
        "upgrade_available": _get_upgrade_options(sub.tier),
    }


def _get_upgrade_options(current_tier: str) -> list[dict]:
    """Return available upgrade plans above the current tier."""
    if current_tier not in PLAN_ORDER:
        return []
    current_idx = PLAN_ORDER.index(current_tier)
    upgrades = []
    for tier in PLAN_ORDER[current_idx + 1:]:
        plan = PLANS[tier]
        upgrades.append({
            "tier": tier,
            "name": plan["name"],
            "asset_limit": plan["asset_limit"],
            "price_gbp": plan["price_gbp_pence"] / 100,
            "billing_period": plan["billing_period"],
        })
    return upgrades


def upgrade_tier(db: Session, tenant_id: str, new_tier: str, notes: str = "") -> TenantSubscription:
    """
    Change a tenant's subscription tier.
    In production this would also update Stripe — for now it updates the DB record.
    """
    if new_tier not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown tier '{new_tier}'. Valid tiers: {list(PLANS.keys())}",
        )

    sub = get_or_create_subscription(db, tenant_id)
    old_tier = sub.tier

    plan = PLANS[new_tier]
    now = datetime.now(timezone.utc)

    sub.tier = new_tier
    sub.price_gbp_pence = plan["price_gbp_pence"]
    sub.billing_period = plan["billing_period"]
    sub.status = "active"
    sub.current_period_start = now

    if plan["billing_period"] == "annual":
        sub.current_period_end = now.replace(year=now.year + 1)
    elif plan["billing_period"] == "monthly":
        sub.current_period_end = now + timedelta(days=30)
    else:
        sub.current_period_end = None

    if notes:
        existing_notes = sub.internal_notes or ""
        sub.internal_notes = (
            f"{existing_notes}\n[{now.isoformat()}] Tier changed: {old_tier} → {new_tier}. {notes}".strip()
        )

    db.commit()
    db.refresh(sub)
    logger.info("Tenant %s upgraded: %s → %s", tenant_id, old_tier, new_tier)
    return sub


def record_usage_snapshot(db: Session, tenant_id: str) -> UsageRecord:
    """Save a usage snapshot. Called by the background loop every 6 hours."""
    from models.vuln_scan import VulnAnnotation
    from models.compliance_run import ComplianceRun
    from models.darkweb import DarkWebFinding

    sub = get_or_create_subscription(db, tenant_id)
    limits = get_plan_limits(sub.tier)
    counts = _get_asset_count(db, tenant_id)
    asset_limit = sub.custom_asset_limit if sub.custom_asset_limit else limits["asset_limit"]

    vuln_count = db.query(func.count()).select_from(
        __import__('models.telemetry', fromlist=['VulnerabilityFinding']).VulnerabilityFinding
    ).filter_by(tenant_id=tenant_id).scalar() or 0

    compliance_count = (
        db.query(func.count(ComplianceRun.id))
        .filter(ComplianceRun.tenant_id == tenant_id)
        .scalar() or 0
    )
    darkweb_count = (
        db.query(func.count(DarkWebFinding.id))
        .filter(DarkWebFinding.tenant_id == tenant_id)
        .scalar() or 0
    )

    over = asset_limit != -1 and counts["total"] > asset_limit

    record = UsageRecord(
        tenant_id=tenant_id,
        managed_asset_count=counts["managed"],
        network_asset_count=counts["network"],
        total_asset_count=counts["total"],
        vuln_findings_count=vuln_count,
        compliance_runs_count=compliance_count,
        darkweb_findings_count=darkweb_count,
        tier_at_record=sub.tier,
        was_over_limit=over,
        over_limit_by=max(0, counts["total"] - asset_limit) if asset_limit != -1 else 0,
    )
    db.add(record)
    db.commit()
    return record


def get_usage_history(db: Session, tenant_id: str, days: int = 30) -> list[dict]:
    """Return usage history for the last N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    records = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.recorded_at >= cutoff,
        )
        .order_by(desc(UsageRecord.recorded_at))
        .limit(200)
        .all()
    )
    return [
        {
            "recorded_at": r.recorded_at.isoformat(),
            "total_assets": r.total_asset_count,
            "managed_assets": r.managed_asset_count,
            "network_assets": r.network_asset_count,
            "tier": r.tier_at_record,
            "was_over_limit": r.was_over_limit,
            "over_limit_by": r.over_limit_by,
        }
        for r in records
    ]
