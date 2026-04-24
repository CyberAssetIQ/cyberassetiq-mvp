from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.drift_detection_service import (
    get_drift_summary,
    get_drift_events,
    get_asset_drift,
    rebuild_baseline,
    approve_change,
    run_drift_detection_for_tenant,
)

router = APIRouter()

class ApproveChangeRequest(BaseModel):
    asset_id: int | None = None
    change_type: str
    requested_by: str = "admin"
    notes: str | None = None

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_drift_summary(db, auth.tenant_id)

@router.get("/events")
def events(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    evts = get_drift_events(db, auth.tenant_id, severity=severity, status=status, limit=limit)
    return {"events": evts, "count": len(evts)}

@router.get("/assets/{asset_id}")
def asset_drift(asset_id: int, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_asset_drift(db, auth.tenant_id, asset_id)

@router.post("/baseline/rebuild")
def rebuild_baseline_route(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = run_drift_detection_for_tenant(db, auth.tenant_id)
    return {"ok": True, **result}

@router.post("/approve-change")
def approve_change_route(body: ApproveChangeRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = approve_change(db, auth.tenant_id, body.dict())
    return {"ok": True, **result}
