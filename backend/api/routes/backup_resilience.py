from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.backup_resilience_service import (
    get_backup_summary,
    get_backup_assets,
    get_backup_findings,
    recalculate,
)

router = APIRouter()

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_backup_summary(db, auth.tenant_id)

@router.get("/assets")
def assets(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"assets": get_backup_assets(db, auth.tenant_id, limit=limit)}

@router.get("/findings")
def findings(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"findings": get_backup_findings(db, auth.tenant_id)}

@router.post("/recalculate")
def recalculate_route(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = recalculate(db, auth.tenant_id)
    return {"ok": True, **result}
