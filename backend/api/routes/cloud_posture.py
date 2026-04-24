from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.cloud_posture_service import (
    get_cloud_posture_summary,
    list_accounts,
    list_findings,
    list_identity_findings,
    list_saas_apps,
    list_sync_logs,
    register_account,
    run_heuristic_posture_scan,
)

router = APIRouter()

class RegisterAccountRequest(BaseModel):
    provider: str
    account_name: str
    account_identifier: str | None = None

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_cloud_posture_summary(db, auth.tenant_id)

@router.get("/accounts")
def accounts(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_accounts(db, auth.tenant_id)

@router.post("/accounts/register")
def register(body: RegisterAccountRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return register_account(db, auth.tenant_id, provider=body.provider, account_name=body.account_name, account_identifier=body.account_identifier)

@router.get("/findings")
def findings(
    provider: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return list_findings(db, auth.tenant_id, provider=provider, severity=severity, limit=limit)

@router.get("/identity-findings")
def identity_findings(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_identity_findings(db, auth.tenant_id, limit=limit)

@router.get("/saas-apps")
def saas_apps(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_saas_apps(db, auth.tenant_id, limit=limit)

@router.post("/scan")
def heuristic_scan(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    try:
        return run_heuristic_posture_scan(db, auth.tenant_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/sync-logs")
def sync_logs(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return list_sync_logs(db, auth.tenant_id, limit=limit)

@router.post("/connect/{provider}")
def connect_provider(provider: str, body: RegisterAccountRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = register_account(db, auth.tenant_id, provider, body.account_name, body.account_identifier)
    return {**result, "next_step": f"Configure {provider} connector credentials via settings"}
