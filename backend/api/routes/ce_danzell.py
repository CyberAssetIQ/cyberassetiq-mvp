"""api/routes/ce_danzell.py — CE v4 Danzell compliance assessment endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read, require_admin
from db.session import get_db

router = APIRouter(prefix="/api/compliance/danzell", tags=["CE v4 Danzell"])


@router.get("/tenant")
def get_danzell_tenant_assessment(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Run a live CE v4 Danzell compliance assessment across all enrolled agents.
    Returns per-control scores, findings, and the v4 gap list (new controls vs CE v3.2).
    """
    from services.ce_danzell_service import assess_tenant_danzell

    report = assess_tenant_danzell(db, auth.tenant_id)
    return {
        "tenant_id": report.tenant_id,
        "framework": report.framework,
        "assessed_at": report.assessed_at_epoch,
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "controls": [
            {
                "id": c.control_id,
                "name": c.control_name,
                "status": c.status,
                "score": round(c.score * 100),
                "is_new_in_v4": c.is_new_in_v4,
                "findings": c.findings,
                "remediation": c.remediation,
                "evidence": c.evidence,
            }
            for c in report.tenant_controls
        ],
        "v4_new_gaps": report.v4_new_gaps,
        "supply_chain_score": round(report.supply_chain_score * 100),
        "remote_working_score": round(report.remote_working_score * 100),
        "incident_readiness_score": round(report.incident_readiness_score * 100),
        "asset_count": len(report.asset_reports),
        "comparison_note": (
            "CE v4 Danzell (April 2026) adds three new controls vs v3.2 Willow: "
            "CE-D7 Supply Chain Security, CE-D8 Home/Remote Working, CE-D9 Incident Response Readiness. "
            "MFA is now mandatory for ALL cloud accounts (not just privileged accounts)."
        ),
    }


@router.get("/asset/{agent_id}")
def get_danzell_asset_assessment(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Run CE v4 Danzell assessment for a single enrolled agent/asset."""
    from models.asset import CanonicalAsset
    from services.ce_danzell_service import assess_asset_danzell

    asset = db.query(CanonicalAsset).filter(
        CanonicalAsset.agent_id == agent_id,
        CanonicalAsset.tenant_id == auth.tenant_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {agent_id} not found.")

    report = assess_asset_danzell(db, asset)
    return {
        "agent_id": report.agent_id,
        "hostname": report.hostname,
        "framework": report.framework,
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "controls": [
            {
                "id": c.control_id,
                "name": c.control_name,
                "status": c.status,
                "score": round(c.score * 100),
                "is_new_in_v4": c.is_new_in_v4,
                "findings": c.findings,
                "remediation": c.remediation,
            }
            for c in report.controls
        ],
        "danzell_gaps": report.danzell_gaps,
    }


@router.get("/compare")
def compare_v3_vs_v4(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Compare CE v3.2 (Willow) score vs CE v4 (Danzell) score for the same tenant.
    Shows exactly where the organisation's gaps are under the new framework.
    """
    from services.compliance_service import assess_tenant
    from services.ce_danzell_service import assess_tenant_danzell

    v3_report = assess_tenant(db, auth.tenant_id)
    v4_report = assess_tenant_danzell(db, auth.tenant_id)

    # assess_tenant returns a dict with tenant_overall_score (0.0-1.0)
    v3_score = round((v3_report.get("tenant_overall_score") or 0) * 100)
    v4_score = round(v4_report.overall_score * 100)

    return {
        "tenant_id": auth.tenant_id,
        "comparison": {
            "v3_2_willow": {
                "framework": "CE v3.2 Willow (NCSC, April 2025)",
                "overall_score": v3_score,
                "overall_status": "PASS" if v3_report.get("ce_ready") else ("FAIL" if v3_report.get("assets_failing", 0) > 0 else "PARTIAL"),
                "control_count": 8,
            },
            "v4_danzell": {
                "framework": "CE v4 Danzell (NCSC, April 2026)",
                "overall_score": v4_score,
                "overall_status": v4_report.overall_status,
                "control_count": 9,
            },
            "score_delta": v4_score - v3_score,
            "regression": v4_score < v3_score,
        },
        "new_controls_in_v4": [
            {
                "id": c.control_id,
                "name": c.control_name,
                "status": c.status,
                "score": round(c.score * 100),
                "findings": c.findings[:2],
            }
            for c in v4_report.tenant_controls
            if c.is_new_in_v4
        ],
        "v4_specific_gaps": v4_report.v4_new_gaps,
        "readiness_summary": (
            f"Your CE v3.2 score ({v3_score}%) vs CE v4 Danzell score ({v4_score}%). "
            f"{'Score improved under v4 framework.' if v4_score >= v3_score else 'New Danzell controls create additional gaps to address.'} "
            f"Supply chain security (CE-D7), remote working (CE-D8), and incident readiness (CE-D9) "
            f"are new requirements that did not exist under CE v3.2."
        ),
    }
