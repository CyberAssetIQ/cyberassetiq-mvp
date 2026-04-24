"""api/routes/csr_assessment.py — CS&R Bill compliance assessment endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db

router = APIRouter(prefix="/api/compliance/csr-bill", tags=["CS&R Bill"])


@router.get("/assessment")
def get_csr_assessment(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Run a full UK Cyber Security and Resilience (CS&R) Bill compliance assessment.
    Covers all 5 domains: supply chain, incident reporting, NIS security,
    MSP obligations, and security governance.
    """
    from services.csr_bill_service import assess_csr_bill

    report = assess_csr_bill(db, auth.tenant_id)
    return {
        "tenant_id": report.tenant_id,
        "framework": report.framework,
        "assessed_at": report.assessed_at,
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "supply_chain_obligation_met": report.supply_chain_obligation_met,
        "incident_reporting_ready": report.incident_reporting_ready,
        "domains": [
            {
                "id": d.domain_id,
                "name": d.domain_name,
                "status": d.status,
                "score": round(d.score * 100),
                "is_new_obligation": d.is_new_obligation,
                "bill_ref": d.bill_ref,
                "obligations": d.obligations,
                "gaps": d.gaps,
                "remediation": d.remediation,
            }
            for d in report.domains
        ],
        "nis_upgrade_gaps": report.nis_upgrade_gaps,
        "top_obligations_to_address": report.top_obligations_to_address,
        "posture_controls": report.as_posture_controls,
        "context": (
            "The CS&R Bill (expected Royal Assent mid-2026) is the first major update to UK cyber "
            "legislation since NIS Regulations 2018. It creates new supply chain security obligations, "
            "72-hour incident reporting requirements, and expands regulated entity scope to include MSPs. "
            "This assessment maps your current CyberAssetIQ platform data to the Bill's key obligations."
        ),
    }


@router.get("/supply-chain-readiness")
def get_supply_chain_readiness(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Focused assessment of supply chain readiness under the CS&R Bill.
    Enterprise buyers use this to assess whether an SME supplier meets
    the Bill's supply chain security obligations.
    """
    from services.csr_bill_service import assess_csr_bill

    report = assess_csr_bill(db, auth.tenant_id)
    sc_domain = next((d for d in report.domains if d.domain_id == "CSR-1"), None)

    return {
        "tenant_id": auth.tenant_id,
        "supply_chain_status": sc_domain.status if sc_domain else "NOT_ASSESSED",
        "supply_chain_score": round((sc_domain.score if sc_domain else 0) * 100),
        "obligations": sc_domain.obligations if sc_domain else [],
        "gaps": sc_domain.gaps if sc_domain else [],
        "remediation": sc_domain.remediation if sc_domain else [],
        "suitable_for_enterprise_buyer": (
            sc_domain.status in ("COMPLIANT", "PARTIALLY_COMPLIANT") if sc_domain else False
        ),
        "bill_ref": "CS&R Bill — Part 3 (Supply Chain Provisions)",
    }


@router.get("/summary")
def get_csr_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Compact CS&R Bill summary for posture records and investor presentations."""
    from services.csr_bill_service import assess_csr_bill

    report = assess_csr_bill(db, auth.tenant_id)
    return {
        "framework": report.framework,
        "overall_score": round(report.overall_score * 100),
        "overall_status": report.overall_status,
        "domain_scores": {
            d.domain_id: {"name": d.domain_name, "score": round(d.score * 100), "status": d.status}
            for d in report.domains
        },
        "supply_chain_ready": report.supply_chain_obligation_met,
        "incident_reporting_ready": report.incident_reporting_ready,
        "new_obligations_count": sum(1 for d in report.domains if d.is_new_obligation),
        "top_gap": report.top_obligations_to_address[0] if report.top_obligations_to_address else None,
    }
