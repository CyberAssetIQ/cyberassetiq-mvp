from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db

router = APIRouter(prefix="/api/insurance", tags=["insurance"])


class SaveAssessmentBody(BaseModel):
    readiness_score: int
    risk_band: str
    factors: list[Any] = []
    recommendations: list[str] = []
    snapshot: dict[str, Any] = {}


class ReferralBody(BaseModel):
    partner: str = "general"
    assessment_id: Optional[int] = None


@router.get("/readiness")
def get_readiness(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.insurance_service import calculate_readiness
    try:
        return calculate_readiness(db, auth.tenant_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/assessments")
def create_assessment(
    body: SaveAssessmentBody,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.insurance_service import save_assessment
    return save_assessment(db, auth.tenant_id, body.dict())


@router.get("/assessments")
def get_assessments(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.insurance_service import list_assessments
    return list_assessments(db, auth.tenant_id)


@router.post("/referral")
def record_referral(
    body: ReferralBody,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.insurance_service import log_referral
    return log_referral(db, auth.tenant_id, body.partner, body.assessment_id)
