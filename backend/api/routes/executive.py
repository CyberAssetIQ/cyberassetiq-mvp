from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read, require_admin
from db.session import get_db

router = APIRouter(prefix="/api/executive", tags=["executive"])


@router.get("/summary")
def get_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.executive_service import get_executive_summary
    return get_executive_summary(db, auth.tenant_id)


@router.get("/timeline")
def get_timeline(
    days: int = 30,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.executive_service import get_timeline
    return get_timeline(db, auth.tenant_id, days)


@router.post("/snapshot")
def take_snapshot(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.executive_service import create_snapshot
    return create_snapshot(db, auth.tenant_id)
