from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.shadow_it_service import (
    get_shadow_it_summary,
    list_rogue_software,
    list_unknown_devices,
    run_full_scan,
    scan_rogue_software,
    scan_unknown_devices,
    update_finding_status,
)

router = APIRouter()

class UpdateStatusRequest(BaseModel):
    finding_table: str
    new_status: str

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_shadow_it_summary(db, auth.tenant_id)

@router.get("/rogue-software")
def rogue_software(
    min_risk: float = Query(0.0, ge=0.0, le=10.0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return list_rogue_software(db, auth.tenant_id, min_risk=min_risk, limit=limit)

@router.get("/unknown-devices")
def unknown_devices(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return list_unknown_devices(db, auth.tenant_id, limit=limit)

@router.post("/scan")
def scan_all(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return run_full_scan(db, auth.tenant_id)

@router.post("/scan/software")
def scan_software(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return scan_rogue_software(db, auth.tenant_id)

@router.post("/scan/devices")
def scan_devices(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return scan_unknown_devices(db, auth.tenant_id)

@router.patch("/findings/{finding_id}/status")
def update_status(finding_id: int, body: UpdateStatusRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = update_finding_status(db, auth.tenant_id, finding_id, finding_table=body.finding_table, new_status=body.new_status)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
