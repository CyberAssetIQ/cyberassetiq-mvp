from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.msp_portfolio_service import (
    acknowledge_alert,
    add_managed_tenant,
    get_portfolio_summary,
    get_tenant_summary,
    list_portfolio_alerts,
    refresh_all_tenants,
    refresh_tenant_health,
    register_msp,
)

router = APIRouter()

class RegisterMSPRequest(BaseModel):
    name: str
    contact_email: str | None = None
    plan: str = "msp_standard"

class AddTenantRequest(BaseModel):
    managed_tenant_id: str
    client_name: str | None = None
    client_industry: str | None = None
    relationship_type: str = "managed"

class AcknowledgeAlertRequest(BaseModel):
    acknowledged_by: str = "admin"

@router.get("/portfolio")
def portfolio(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    summary = get_portfolio_summary(db, auth.tenant_id)
    if "error" in summary:
        raise HTTPException(status_code=404, detail=summary["error"])
    return summary

@router.post("/register")
def register(body: RegisterMSPRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return register_msp(db, auth.tenant_id, name=body.name, contact_email=body.contact_email, plan=body.plan)

@router.post("/tenants")
def add_tenant(body: AddTenantRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = add_managed_tenant(db, auth.tenant_id, managed_tenant_id=body.managed_tenant_id, client_name=body.client_name, client_industry=body.client_industry, relationship_type=body.relationship_type)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/tenants")
def list_tenants(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    summary = get_portfolio_summary(db, auth.tenant_id)
    if "error" in summary:
        raise HTTPException(status_code=404, detail=summary["error"])
    return summary.get("tenants", [])

@router.get("/tenants/{managed_tenant_id}/summary")
def tenant_detail(managed_tenant_id: str, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_tenant_summary(db, auth.tenant_id, managed_tenant_id)

@router.post("/tenants/{managed_tenant_id}/refresh")
def refresh_tenant(managed_tenant_id: str, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = refresh_tenant_health(db, auth.tenant_id, managed_tenant_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/refresh-all")
def refresh_all(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = refresh_all_tenants(db, auth.tenant_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/alerts")
def alerts(
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return list_portfolio_alerts(db, auth.tenant_id, severity=severity, limit=limit)

@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int, body: AcknowledgeAlertRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = acknowledge_alert(db, auth.tenant_id, alert_id, acknowledged_by=body.acknowledged_by)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
