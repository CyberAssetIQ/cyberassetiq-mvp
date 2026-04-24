from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.risk_engine_service import (
    get_risk_summary,
    get_risk_factors,
    get_risk_recommendations,
    get_risk_timeline,
    recalculate,
)

router = APIRouter()

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_risk_summary(db, auth.tenant_id)

@router.get("/factors")
def factors(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return {"factors": get_risk_factors(db, auth.tenant_id)}

@router.get("/recommendations")
def recommendations(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"recommendations": get_risk_recommendations(db, auth.tenant_id, limit=limit)}

@router.get("/timeline")
def timeline(
    days: int = Query(30, ge=1, le=90),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"timeline": get_risk_timeline(db, auth.tenant_id, days=days)}

@router.post("/recalculate")
def recalculate_route(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = recalculate(db, auth.tenant_id)
    return {"ok": True, **result}
