from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.asset_criticality_service import (
    get_criticality_summary,
    get_criticality_assets,
    recalculate_all,
    assign_service,
    get_crown_jewels,
    get_business_services,
)

router = APIRouter()

class AssignServiceRequest(BaseModel):
    asset_id: int
    service_id: int
    dependency_type: str = "hosts"

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_criticality_summary(db, auth.tenant_id)

@router.get("/assets")
def assets(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"assets": get_criticality_assets(db, auth.tenant_id)}

@router.get("/crown-jewels")
def crown_jewels(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return {"crown_jewels": get_crown_jewels(db, auth.tenant_id)}

@router.get("/services")
def services(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return {"services": get_business_services(db, auth.tenant_id)}

@router.post("/recalculate")
def recalculate(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = recalculate_all(db, auth.tenant_id)
    return {"ok": True, **result}

@router.post("/assign-service")
def assign_service_route(body: AssignServiceRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = assign_service(db, auth.tenant_id, body.asset_id, body.service_id, body.dependency_type)
    return {"ok": True, **result}
