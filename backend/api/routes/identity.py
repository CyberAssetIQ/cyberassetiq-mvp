from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db

router = APIRouter(prefix="/api/identity", tags=["identity"])


@router.get("/risk")
def get_identity_risk(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.identity_service import analyse_identity_risk
    return analyse_identity_risk(db, auth.tenant_id)
