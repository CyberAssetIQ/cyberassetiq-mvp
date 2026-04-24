"""api/routes/caf.py — NCSC Cyber Assessment Framework assessment endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db

router = APIRouter(prefix="/api/compliance/caf", tags=["NCSC CAF"])


@router.get("/assessment")
def get_caf_assessment(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Run a full NCSC Cyber Assessment Framework (CAF) assessment.
    Returns all 14 principles across 4 objectives with scores, gaps, and guidance.
    """
    from services.caf_mapping_service import assess_caf

    report = assess_caf(db, auth.tenant_id)
    return {
        "tenant_id": report.tenant_id,
        "framework": report.framework,
        "assessed_at": report.assessed_at,
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "principle_summary": {
            "total": report.principle_count,
            "achieved": report.achieved_count,
            "partially_achieved": report.partial_count,
            "not_achieved": report.not_achieved_count,
        },
        "objectives": report.objectives,
        "top_gaps": report.top_gaps,
        "posture_domain": report.as_posture_domains[0] if report.as_posture_domains else {},
    }


@router.get("/objectives/{objective_id}")
def get_caf_objective(
    objective_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Get detailed CAF assessment for a single objective (A, B, C, or D)."""
    from services.caf_mapping_service import assess_caf

    valid = {"A", "B", "C", "D"}
    if objective_id.upper() not in valid:
        from fastapi import HTTPException
        raise HTTPException(400, detail=f"Objective must be one of: {sorted(valid)}")

    report = assess_caf(db, auth.tenant_id)
    obj = report.objectives.get(objective_id.upper())
    if not obj:
        from fastapi import HTTPException
        raise HTTPException(404, detail="Objective not found in report.")

    return {
        "tenant_id": auth.tenant_id,
        "framework": report.framework,
        "objective": obj,
    }


@router.get("/summary")
def get_caf_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Compact CAF summary suitable for posture record and investor presentation."""
    from services.caf_mapping_service import assess_caf

    report = assess_caf(db, auth.tenant_id)
    return {
        "framework": "NCSC Cyber Assessment Framework (CAF)",
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "objective_scores": {
            obj_id: {
                "name": data["objective_name"],
                "score": data["score"],
                "status": data["status"],
            }
            for obj_id, data in report.objectives.items()
        },
        "top_3_gaps": report.top_gaps[:3],
        "achieved_of_14": f"{report.achieved_count}/14 principles achieved",
    }
