"""api/routes/assets_write.py - Asset CRUD, search, deduplication"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.asset import CanonicalAsset, ManualAsset
from services.asset_classification_service import backfill_asset_states

router = APIRouter()

class ManualAssetCreate(BaseModel):
    hostname:   str
    ip:         str | None = None
    os_family:  str | None = None
    os_version: str | None = None
    notes:      str | None = None

class ManualAssetUpdate(BaseModel):
    hostname:   str | None = None
    ip:         str | None = None
    os_family:  str | None = None
    os_version: str | None = None
    notes:      str | None = None

class DeduplicateRequest(BaseModel):
    hostname: str | None = None
    ip:       str | None = None

def _to_dict(a: ManualAsset) -> dict:
    return {"id": a.id, "tenant_id": a.tenant_id, "hostname": a.hostname,
            "ip": a.ip, "os_family": a.os_family, "os_version": a.os_version,
            "notes": a.notes, "created_by": a.created_by, "source": "manual"}

@router.post("/manual", status_code=201)
def create_manual_asset(payload: ManualAssetCreate,
    auth: AuthenticatedRequest = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Create a manually-entered asset. Returns 409 on duplicate hostname or IP."""
    if not payload.hostname and not payload.ip:
        raise HTTPException(status_code=400, detail="hostname or ip required.")
    dup = db.query(ManualAsset).filter(
        ManualAsset.tenant_id == auth.tenant_id, ManualAsset.is_deleted.is_(False),
        (ManualAsset.hostname == payload.hostname) | (ManualAsset.ip == payload.ip)
    ).first()
    if dup:
        raise HTTPException(status_code=409, detail={"error":"duplicate_asset","existing_id":dup.id})
    if payload.hostname:
        ca = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id==auth.tenant_id,
            CanonicalAsset.hostname==payload.hostname).first()
        if ca:
            raise HTTPException(status_code=409, detail={"error":"duplicate_agent_asset","agent_id":ca.agent_id})
    a = ManualAsset(tenant_id=auth.tenant_id, hostname=payload.hostname or "",
        ip=payload.ip, os_family=payload.os_family, os_version=payload.os_version,
        notes=payload.notes, created_by=f"api_key:{auth.key_id}", is_deleted=False)
    db.add(a); db.commit(); db.refresh(a)
    return {"message": "Manual asset created.", "asset": _to_dict(a)}

@router.get("/manual")
def list_manual_assets(limit: int = Query(100,ge=1,le=500), offset: int = Query(0,ge=0),
    auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> dict:
    q = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
        ManualAsset.is_deleted.is_(False)).order_by(ManualAsset.id.desc())
    return {"total":q.count(),"offset":offset,"limit":limit,"items":[_to_dict(a) for a in q.offset(offset).limit(limit).all()]}

@router.patch("/manual/{asset_id}")
def update_manual_asset(asset_id: int, payload: ManualAssetUpdate,
    auth: AuthenticatedRequest = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    a = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
        ManualAsset.id==asset_id, ManualAsset.is_deleted.is_(False)).first()
    if not a: raise HTTPException(status_code=404, detail="Manual asset not found.")
    if payload.hostname   is not None: a.hostname   = payload.hostname
    if payload.ip         is not None: a.ip         = payload.ip
    if payload.os_family  is not None: a.os_family  = payload.os_family
    if payload.os_version is not None: a.os_version = payload.os_version
    if payload.notes      is not None: a.notes      = payload.notes
    db.commit(); db.refresh(a)
    return {"message": "Asset updated.", "asset": _to_dict(a)}

@router.delete("/manual/{asset_id}")
def delete_manual_asset(asset_id: int,
    auth: AuthenticatedRequest = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Soft-delete. Agent-managed assets cannot be deleted via this endpoint."""
    a = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
        ManualAsset.id==asset_id, ManualAsset.is_deleted.is_(False)).first()
    if not a: raise HTTPException(status_code=404, detail="Not found or already deleted.")
    a.is_deleted = True; db.commit()
    return {"message": "Asset deleted.", "asset_id": asset_id}

@router.get("/search")
def search_assets(q: str = Query(...,min_length=1), os_family: str|None = Query(None),
    limit: int = Query(50,ge=1,le=200),
    auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> dict:
    """Server-side search across agent-managed and manual assets."""
    t = f"%{q}%"
    cq = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id==auth.tenant_id,
        CanonicalAsset.hostname.ilike(t) | CanonicalAsset.fqdn.ilike(t))
    if os_family: cq = cq.filter(CanonicalAsset.os_family==os_family)
    mq = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
        ManualAsset.is_deleted.is_(False), ManualAsset.hostname.ilike(t)|ManualAsset.ip.ilike(t))
    if os_family: mq = mq.filter(ManualAsset.os_family==os_family)
    canon = cq.limit(limit).all(); manual = mq.limit(limit).all()
    return {"query":q,"total":len(canon)+len(manual),
        "agent":[{"source":"agent","agent_id":a.agent_id,"hostname":a.hostname,"fqdn":a.fqdn,"os_family":a.os_family,"ips":a.ips or []} for a in canon],
        "manual":[_to_dict(a) for a in manual]}

@router.post("/manual/deduplicate")
def check_duplicate(payload: DeduplicateRequest,
    auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> dict:
    """Pre-flight duplicate check before creating a manual asset."""
    if not payload.hostname and not payload.ip:
        raise HTTPException(status_code=400, detail="Provide hostname and/or ip.")
    matches: list[dict] = []
    if payload.hostname:
        c = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id==auth.tenant_id,
            CanonicalAsset.hostname==payload.hostname).first()
        if c: matches.append({"source":"agent","agent_id":c.agent_id,"hostname":c.hostname})
        m = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
            ManualAsset.is_deleted.is_(False), ManualAsset.hostname==payload.hostname).first()
        if m: matches.append(_to_dict(m))
    if payload.ip:
        m = db.query(ManualAsset).filter(ManualAsset.tenant_id==auth.tenant_id,
            ManualAsset.is_deleted.is_(False), ManualAsset.ip==payload.ip).first()
        if m and not any(x.get("id")==m.id for x in matches): matches.append(_to_dict(m))
    return {"duplicate_found": bool(matches), "matches": matches}
    
@router.post("/admin/backfill-asset-states")
def admin_backfill_asset_states(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Backfill canonical asset governance fields based on current evidence.
    Managed means real agent-installed and recently reporting.
    Observed is never treated as managed.
    """
    return backfill_asset_states(db)
