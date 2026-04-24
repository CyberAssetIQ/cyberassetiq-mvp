from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_agent, require_read, require_admin
import asyncio as _asyncio
from integrations.dispatcher import dispatch_critical_finding as _dispatch_patch

from db.session import get_db

router = APIRouter(prefix="/api/patch", tags=["patch"])


# ── Ingest (agent → backend) ──────────────────────────────────────────────

class PatchIngestBody(BaseModel):
    agent_id:          str
    os_name:           str = "Unknown"
    os_version:        str = ""
    os_build:          int = 0
    os_supported:      bool = True
    os_arch:           str = ""
    patch_score:       int = 100
    pending_total:     int = 0
    pending_critical:  int = 0
    pending_important: int = 0
    outdated_count:    int = 0
    windows_updates:   list[Any] = []
    outdated_software: list[Any] = []


@router.post("/ingest")
def ingest_patch_report(
    body: PatchIngestBody,
    auth: AuthenticatedRequest = Depends(require_agent),
    db: Session = Depends(get_db),
):
    from services.patch_service import ingest_patch_report
    result = ingest_patch_report(db, auth.tenant_id, body.dict())
    try:
        if body.pending_critical > 0 or body.pending_important > 0:
            _event = {
                "event_type": "patch_pending",
                "severity": 9 if body.pending_critical > 0 else 6,
                "asset_name": body.agent_id,
                "description": f"Patch report: {body.pending_critical} critical, {body.pending_important} important patches pending on {body.agent_id}. Score: {body.patch_score}/100.",
                "remediation_class": "approval_required" if body.pending_critical > 0 else "auto_safe",
                "remediation_action": f"Apply {body.pending_critical} critical and {body.pending_important} important patches via patch management module.",
                "ce_control": "A5",
                "ce_compliant": body.patch_score >= 80,
                "tenant_id": auth.tenant_id,
                "patch_score": body.patch_score,
            }
            _asyncio.run(_dispatch_patch(db, auth.tenant_id, _event))
    except Exception as _exc:
        import logging as _l; _l.getLogger(__name__).warning("Patch dispatch failed: %s", _exc)
    return result


# ── Dashboard (UI → backend) ──────────────────────────────────────────────

@router.get("/dashboard")
def patch_dashboard(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.patch_service import get_patch_dashboard
    return get_patch_dashboard(db, auth.tenant_id)


# ── Per-agent detail ──────────────────────────────────────────────────────

@router.get("/agents/{agent_id}")
def agent_patch_detail(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.patch_service import get_agent_patch_detail
    detail = get_agent_patch_detail(db, auth.tenant_id, agent_id)
    if not detail:
        raise HTTPException(status_code=404, detail="No patch report found for this agent")
    return detail


# ── Approve patch ─────────────────────────────────────────────────────────

class ApprovePatchBody(BaseModel):
    agent_id:      str
    software_name: str
    winget_id:     str = ""
    patch_type:    str = "software"


@router.post("/approve")
def approve_patch(
    body: ApprovePatchBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.patch_service import approve_patch
    return approve_patch(
        db, auth.tenant_id,
        body.agent_id, body.software_name,
        body.winget_id or None, body.patch_type,
    )


# ── List approvals ────────────────────────────────────────────────────────

@router.get("/approvals")
def list_approvals(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.patch_service import list_approvals
    return list_approvals(db, auth.tenant_id)
