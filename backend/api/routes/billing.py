"""api/routes/billing.py

Subscription tier management and usage tracking endpoints.

Routes:
  GET  /api/billing/plans          — All available plans and pricing
  GET  /api/billing/subscription   — Current subscription for tenant
  POST /api/billing/subscription   — Create/set subscription (admin)
  GET  /api/billing/usage          — Current usage vs limits
  GET  /api/billing/usage/history  — Usage history (last 30 days)
  POST /api/billing/upgrade        — Upgrade to a higher tier
  POST /api/billing/cancel         — Cancel at period end
  POST /api/billing/reactivate     — Reactivate a cancelled subscription
  GET  /api/billing/trial-status   — Trial status and days remaining
  POST /api/billing/webhook        — Stripe webhook (stub)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.billing_service import (
    PLANS,
    get_or_create_subscription,
    get_usage_summary,
    get_usage_history,
    upgrade_tier,
    get_plan_limits,
)

router = APIRouter(prefix="/api/billing", tags=["billing"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class SetSubscriptionRequest(BaseModel):
    tier: str
    billing_period: str = "annual"
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    notes: str = ""


class UpgradeRequest(BaseModel):
    tier: str
    notes: str = ""


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/plans")
def list_plans() -> dict:
    """
    Return all available subscription plans with pricing and features.
    Public endpoint — no authentication required.
    """
    plans = []
    for tier_key, plan in PLANS.items():
        if tier_key == "unlimited":
            continue  # internal only — don't expose
        plans.append({
            "tier":            tier_key,
            "name":            plan["name"],
            "description":     plan["description"],
            "asset_limit":     plan["asset_limit"],
            "msp_client_limit":plan["msp_client_limit"],
            "price_gbp":       plan["price_gbp_pence"] / 100,
            "billing_period":  plan["billing_period"],
            "features":        plan["features"],
        })
    return {"plans": plans, "currency": "GBP"}


@router.get("/subscription")
def get_subscription(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Return the current subscription details for this tenant."""
    sub = get_or_create_subscription(db, auth.tenant_id)
    limits = get_plan_limits(sub.tier)
    return {
        "tenant_id":             auth.tenant_id,
        "tier":                  sub.tier,
        "tier_name":             limits["name"],
        "status":                sub.status,
        "billing_period":        sub.billing_period,
        "price_gbp":             sub.price_gbp_pence / 100,
        "asset_limit":           sub.custom_asset_limit or limits["asset_limit"],
        "features":              limits["features"],
        "trial_ends_at":         sub.trial_ends_at.isoformat() if sub.trial_ends_at else None,
        "current_period_start":  sub.current_period_start.isoformat() if sub.current_period_start else None,
        "current_period_end":    sub.current_period_end.isoformat() if sub.current_period_end else None,
        "cancel_at_period_end":  sub.cancel_at_period_end,
        "stripe_customer_id":    sub.stripe_customer_id,
        "stripe_subscription_id":sub.stripe_subscription_id,
    }


@router.post("/subscription")
def set_subscription(
    payload: SetSubscriptionRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Set or update the subscription for this tenant.
    Admin only. Used for manual provisioning, internal accounts, and Stripe webhook sync.
    """
    sub = upgrade_tier(db, auth.tenant_id, payload.tier, notes=payload.notes)

    if payload.stripe_customer_id:
        sub.stripe_customer_id = payload.stripe_customer_id
    if payload.stripe_subscription_id:
        sub.stripe_subscription_id = payload.stripe_subscription_id
    if payload.billing_period:
        sub.billing_period = payload.billing_period

    db.commit()
    db.refresh(sub)

    return {
        "message": f"Subscription set to '{payload.tier}' successfully.",
        "tier": sub.tier,
        "status": sub.status,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
    }


@router.get("/usage")
def get_usage(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    Return current usage vs limits for this tenant.
    Includes asset counts, usage percentage, and upgrade options.
    """
    return get_usage_summary(db, auth.tenant_id)


@router.get("/usage/history")
def get_usage_history_endpoint(
    days: int = 30,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Return usage history for the last N days (max 90)."""
    days = min(days, 90)
    history = get_usage_history(db, auth.tenant_id, days=days)
    return {
        "tenant_id": auth.tenant_id,
        "days": days,
        "records": history,
    }


@router.post("/upgrade")
def upgrade_subscription(
    payload: UpgradeRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Upgrade to a higher tier.
    Admin only. In production, this would initiate Stripe checkout.
    For self-serve, direct customer to the billing portal.
    """
    from services.billing_service import PLAN_ORDER

    sub = get_or_create_subscription(db, auth.tenant_id)
    new_tier = payload.tier

    if new_tier not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {new_tier}")

    # Validate it's actually an upgrade (not a downgrade)
    current_in_order = PLAN_ORDER.index(sub.tier) if sub.tier in PLAN_ORDER else -1
    new_in_order = PLAN_ORDER.index(new_tier) if new_tier in PLAN_ORDER else -1

    if new_in_order <= current_in_order and sub.tier != "trial":
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{new_tier}' is not an upgrade from your current plan '{sub.tier}'. "
                "Use the downgrade endpoint for tier reductions."
            ),
        )

    sub = upgrade_tier(db, auth.tenant_id, new_tier, notes=payload.notes or "Self-serve upgrade")

    plan = PLANS[new_tier]
    return {
        "message": f"Successfully upgraded to {plan['name']}.",
        "tier": sub.tier,
        "asset_limit": plan["asset_limit"],
        "price_gbp": plan["price_gbp_pence"] / 100,
        "billing_period": plan["billing_period"],
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "note": "In production: Stripe checkout will be initiated. Payment required to activate.",
    }


@router.post("/cancel")
def cancel_subscription(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Mark subscription to cancel at end of current period.
    Platform remains active until period_end.
    """
    sub = get_or_create_subscription(db, auth.tenant_id)
    sub.cancel_at_period_end = True
    db.commit()
    return {
        "message": "Subscription will be cancelled at end of current period.",
        "access_until": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "cancel_at_period_end": True,
    }


@router.post("/reactivate")
def reactivate_subscription(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Remove a scheduled cancellation."""
    sub = get_or_create_subscription(db, auth.tenant_id)
    sub.cancel_at_period_end = False
    sub.status = "active"
    db.commit()
    return {
        "message": "Subscription reactivated. Cancellation removed.",
        "tier": sub.tier,
        "status": sub.status,
    }


@router.get("/trial-status")
def get_trial_status(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Return trial status and days remaining."""
    from datetime import datetime, timezone

    sub = get_or_create_subscription(db, auth.tenant_id)
    if sub.tier != "trial":
        return {
            "on_trial": False,
            "tier": sub.tier,
            "message": "This account is on a paid plan.",
        }

    now = datetime.now(timezone.utc)
    trial_end = sub.trial_ends_at.replace(tzinfo=timezone.utc) if sub.trial_ends_at else None
    days_remaining = max(0, (trial_end - now).days) if trial_end else 0
    expired = trial_end < now if trial_end else True

    return {
        "on_trial": True,
        "expired": expired,
        "days_remaining": days_remaining,
        "trial_ends_at": sub.trial_ends_at.isoformat() if sub.trial_ends_at else None,
        "message": (
            "Trial expired. Upgrade to a paid plan to continue."
            if expired
            else f"Trial active. {days_remaining} day(s) remaining."
        ),
        "upgrade_url": "/api/billing/plans",
    }


@router.post("/webhook")
async def stripe_webhook(request: Request) -> dict:
    """
    Stripe webhook endpoint.
    Handles: checkout.session.completed, invoice.payment_succeeded,
             invoice.payment_failed, customer.subscription.deleted.

    In production: validate Stripe-Signature header, parse event, update subscription.
    Currently: stub that logs the event and returns 200.
    """
    try:
        body = await request.json()
        event_type = body.get("type", "unknown")
        event_id = body.get("id", "unknown")
    except Exception:
        body = {}
        event_type = "parse_error"
        event_id = "unknown"

    import logging
    logging.getLogger("cyberassetiq.billing").info(
        "Stripe webhook received: event_type=%s id=%s", event_type, event_id
    )

    # TODO: implement full Stripe webhook handling
    # 1. Validate: stripe.Webhook.construct_event(body, sig, STRIPE_WEBHOOK_SECRET)
    # 2. Handle checkout.session.completed → upgrade_tier()
    # 3. Handle invoice.payment_failed → set status='past_due'
    # 4. Handle customer.subscription.deleted → set status='cancelled'

    return {
        "received": True,
        "event_type": event_type,
        "note": "Stripe webhook processing is in development. Manual subscription management is available via POST /api/billing/subscription.",
    }
