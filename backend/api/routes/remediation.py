from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.remediation_service import (
    approve_action,
    create_action,
    generate_ai_recommendations,
    get_remediation_summary,
    list_actions,
    list_playbooks,
    list_runs,
    seed_default_playbooks,
)

router = APIRouter()

class CreateActionRequest(BaseModel):
    action_type: str
    asset_id: int | None = None
    parameters: dict | None = None
    created_by: str = "admin"
    trigger_finding_type: str | None = None
    trigger_severity: str | None = None
    expected_score_gain: float = 0.0

class ApproveActionRequest(BaseModel):
    approved_by: str = "admin"
    notes: str | None = None
    decision: str = "approved"

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_remediation_summary(db, auth.tenant_id)

@router.get("/actions")
def actions(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return list_actions(db, auth.tenant_id, status=status, limit=limit)

@router.post("/action")
def create(body: CreateActionRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return create_action(
        db, auth.tenant_id,
        action_type=body.action_type, asset_id=body.asset_id,
        parameters=body.parameters, created_by=body.created_by,
        source="manual", trigger_finding_type=body.trigger_finding_type,
        trigger_severity=body.trigger_severity, expected_score_gain=body.expected_score_gain,
    )

@router.post("/approve/{action_id}")
def approve(action_id: int, body: ApproveActionRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = approve_action(db, auth.tenant_id, action_id, approved_by=body.approved_by, notes=body.notes, decision=body.decision)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/playbooks")
def playbooks(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_playbooks(db, auth.tenant_id)

@router.post("/playbooks/seed")
def seed_playbooks(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    count = seed_default_playbooks(db, auth.tenant_id)
    return {"seeded": count}

@router.get("/runs")
def runs(limit: int = Query(30, ge=1, le=100), db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_runs(db, auth.tenant_id, limit=limit)

@router.post("/ai-recommendations")
def ai_recommendations(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    created = generate_ai_recommendations(db, auth.tenant_id)
    return {"created": len(created), "actions": created}
