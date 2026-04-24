"""api/routes/agentic.py

Supervised Agentic AI Loop — API Endpoints

Routes:
  POST /api/agentic/trigger              — Manually trigger the agentic loop
  GET  /api/agentic/runs                 — List all loop runs
  GET  /api/agentic/runs/{run_id}        — Full run detail with context + actions
  GET  /api/agentic/pending              — All actions waiting for approval
  POST /api/agentic/actions/{id}/approve — Approve a tier 1/2 action
  POST /api/agentic/actions/{id}/reject  — Reject a tier 1/2 action
  GET  /api/agentic/summary              — Dashboard summary
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.agentic_loop_service import (
    trigger_loop,
    list_runs,
    get_run_detail,
    get_pending_approvals,
    approve_action,
    reject_action,
)

router = APIRouter(prefix="/api/agentic", tags=["agentic-loop"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class TriggerRequest(BaseModel):
    trigger_type: str = "manual"
    # manual | ai_alert | vuln_scan | darkweb_hit | drift_event | incident_created
    trigger_ref_id: int | None = None
    trigger_ref_type: str | None = None
    trigger_asset_id: int | None = None
    trigger_summary: str = ""


class ApproveRequest(BaseModel):
    decided_by: str = "analyst"
    decision_note: str = ""


class RejectRequest(BaseModel):
    decided_by: str = "analyst"
    decision_note: str = ""


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/trigger", status_code=201)
def trigger_agentic_loop(
    payload: TriggerRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Trigger the supervised agentic loop.

    The loop will:
    1. Gather context from blast radius, attack graph, dark web, identity,
       CVEs, and asset criticality
    2. Generate an AI decision brief
    3. Execute tier 0 actions automatically (create incident, notify, rescan)
    4. Queue tier 1/2 actions for human approval

    Returns the completed run record immediately (synchronous execution).
    """
    run = trigger_loop(
        db=db,
        tenant_id=auth.tenant_id,
        trigger_type=payload.trigger_type,
        trigger_ref_id=payload.trigger_ref_id,
        trigger_ref_type=payload.trigger_ref_type,
        trigger_asset_id=payload.trigger_asset_id,
        trigger_summary=payload.trigger_summary or f"Manual trigger by {auth.role}",
    )

    from services.agentic_loop_service import _run_to_dict
    result = _run_to_dict(run)
    result["message"] = (
        f"Agentic loop completed. Severity: {run.brief_severity}. "
        f"{run.auto_executed} action(s) executed automatically. "
        f"{run.pending_approval} action(s) awaiting your approval."
    )
    return result


@router.get("/runs")
def get_runs(
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """List all agentic loop runs for this tenant."""
    runs = list_runs(db, auth.tenant_id, status=status, limit=limit)
    return {
        "tenant_id": auth.tenant_id,
        "total": len(runs),
        "runs": runs,
    }


@router.get("/runs/{run_id}")
def get_run(
    run_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    Full run detail including gathered context, decision brief, and all actions.
    This is the primary view for analysts reviewing what the AI found and recommended.
    """
    return get_run_detail(db, auth.tenant_id, run_id)


@router.get("/pending")
def get_pending(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    All actions currently awaiting human approval across all runs.
    Sorted by tier (tier 1 before tier 2) then by age (oldest first).
    This is the analyst's approval queue.
    """
    actions = get_pending_approvals(db, auth.tenant_id)
    tier1 = [a for a in actions if a["tier"] == 1]
    tier2 = [a for a in actions if a["tier"] == 2]
    return {
        "tenant_id": auth.tenant_id,
        "total_pending": len(actions),
        "tier1_count": len(tier1),
        "tier2_count": len(tier2),
        "actions": actions,
    }


@router.post("/actions/{action_id}/approve")
def approve(
    action_id: int,
    payload: ApproveRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Approve a tier 1 or tier 2 action. The action executes immediately after approval.
    Admin only — actions have real impact on managed assets.

    Tier 1 examples: isolate_asset, force_password_reset, disable_account
    Tier 2 examples: firewall_rule_change, bulk_account_action
    """
    result = approve_action(
        db=db,
        tenant_id=auth.tenant_id,
        action_id=action_id,
        decided_by=payload.decided_by,
        decision_note=payload.decision_note,
    )
    result["message"] = f"Action approved and executed: {result.get('execution_result', 'completed')}"
    return result


@router.post("/actions/{action_id}/reject")
def reject(
    action_id: int,
    payload: RejectRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Reject a pending action. The action will not be executed.
    A rejection note is recorded for the audit trail.
    Admin only.
    """
    result = reject_action(
        db=db,
        tenant_id=auth.tenant_id,
        action_id=action_id,
        decided_by=payload.decided_by,
        decision_note=payload.decision_note,
    )
    result["message"] = "Action rejected. Recorded in audit trail."
    return result


@router.get("/summary")
def get_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    Dashboard summary of agentic loop activity.
    Shows recent runs, pending approvals, and action statistics.
    """
    from models.agentic_loop import AgentLoopRun, AgentLoopAction
    from sqlalchemy import func

    tenant_id = auth.tenant_id

    total_runs = db.query(func.count(AgentLoopRun.id)).filter(
        AgentLoopRun.tenant_id == tenant_id
    ).scalar() or 0

    pending_count = db.query(func.count(AgentLoopAction.id)).filter(
        AgentLoopAction.tenant_id == tenant_id,
        AgentLoopAction.status == "pending",
        AgentLoopAction.tier > 0,
    ).scalar() or 0

    auto_executed = db.query(func.count(AgentLoopAction.id)).filter(
        AgentLoopAction.tenant_id == tenant_id,
        AgentLoopAction.status.in_(["auto_executed", "completed"]),
        AgentLoopAction.tier == 0,
    ).scalar() or 0

    approved = db.query(func.count(AgentLoopAction.id)).filter(
        AgentLoopAction.tenant_id == tenant_id,
        AgentLoopAction.status == "completed",
        AgentLoopAction.tier > 0,
    ).scalar() or 0

    rejected = db.query(func.count(AgentLoopAction.id)).filter(
        AgentLoopAction.tenant_id == tenant_id,
        AgentLoopAction.status == "rejected",
    ).scalar() or 0

    # Recent runs
    recent = list_runs(db, tenant_id, limit=5)

    # Severity distribution of recent runs
    sev_dist = db.query(
        AgentLoopRun.brief_severity,
        func.count(AgentLoopRun.id).label("count"),
    ).filter(
        AgentLoopRun.tenant_id == tenant_id,
        AgentLoopRun.brief_severity.isnot(None),
    ).group_by(AgentLoopRun.brief_severity).all()

    return {
        "tenant_id": tenant_id,
        "total_runs": total_runs,
        "pending_approvals": pending_count,
        "auto_executed_actions": auto_executed,
        "approved_actions": approved,
        "rejected_actions": rejected,
        "severity_distribution": {row.brief_severity: row.count for row in sev_dist},
        "recent_runs": recent,
        "human_approval_rate": (
            round(approved / (approved + rejected) * 100, 1)
            if (approved + rejected) > 0 else None
        ),
    }
