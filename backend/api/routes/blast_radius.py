from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.blast_radius_service import (
    get_blast_radius_summary,
    get_asset_blast_radius,
    simulate,
    simulate_all,
)

router = APIRouter()

class SimulateRequest(BaseModel):
    asset_id: int

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_blast_radius_summary(db, auth.tenant_id)

@router.get("/asset/{asset_id}")
def asset_blast(asset_id: int, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = get_asset_blast_radius(db, auth.tenant_id, asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="No blast radius data for this asset")
    return result

@router.post("/simulate")
def simulate_route(body: SimulateRequest, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return simulate(db, auth.tenant_id, body.asset_id)

@router.post("/simulate-all")
def simulate_all_route(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = simulate_all(db, auth.tenant_id)
    return {"ok": True, **result}
