from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.session import get_db
from api.deps import require_auth, AuthenticatedRequest
from services.attack_graph_service import (
    get_attack_graph_summary,
    get_attack_paths,
    get_asset_attack_routes,
    rebuild_graph,
    get_crown_jewel_paths,
    get_graph_data,
)

router = APIRouter()

@router.get("/summary")
def summary(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_attack_graph_summary(db, auth.tenant_id)

@router.get("/paths")
def paths(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    auth: AuthenticatedRequest = Depends(require_auth),
):
    return {"paths": get_attack_paths(db, auth.tenant_id, limit=limit)}

@router.get("/asset/{asset_id}")
def asset_routes(asset_id: int, db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_asset_attack_routes(db, auth.tenant_id, asset_id)

@router.post("/rebuild")
def rebuild(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    result = rebuild_graph(db, auth.tenant_id)
    return {"ok": True, **result}

@router.get("/crown-jewels")
def crown_jewel_paths(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return {"crown_jewel_paths": get_crown_jewel_paths(db, auth.tenant_id)}

@router.get("/graph-data")
def graph_data(db: Session = Depends(get_db), auth: AuthenticatedRequest = Depends(require_auth)):
    return get_graph_data(db, auth.tenant_id)
