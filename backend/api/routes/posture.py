from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from models.posture_record import PostureRecordVersion

from api.deps import AuthenticatedRequest, require_read, require_admin
from db.session import get_db
from services.posture_record_service import (
    create_posture_version,
    get_current_posture_version,
    get_posture_domains,
    get_posture_evidence,
    list_posture_versions,
)

router = APIRouter(prefix="/api/posture", tags=["posture"])


@router.get("/current")
def get_current_posture(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    version = get_current_posture_version(db, auth.tenant_id)
    if not version:
        created = create_posture_version(db, auth.tenant_id, generated_by="posture_current")
        version = created["version"]
    return {
        "tenant_id": version.tenant_id,
        "version_id": version.id,
        "version_no": version.version_no,
        "schema_version": version.schema_version,
        "generated_at": version.generated_at,
        "generated_by": version.generated_by,
        "overall_score": version.overall_score,
        "risk_band": version.risk_band,
        "insurance_readiness_score": version.insurance_readiness_score,
        "supply_chain_score": version.supply_chain_score,
        "compliance_score": version.compliance_score,
        "identity_score": version.identity_score,
        "exposure_score": version.exposure_score,
        "resilience_score": version.resilience_score,
        "patch_score": version.patch_score,
        "drift_score": version.drift_score,
        "asset_count": version.asset_count,
        "critical_findings_count": version.critical_findings_count,
        "open_cves_count": version.open_cves_count,
        "darkweb_findings_count": version.darkweb_findings_count,
        "attack_path_count": version.attack_path_count,
        "crown_jewel_assets_count": version.crown_jewel_assets_count,
        "credential_exposure_count": version.credential_exposure_count,
        "summary": version.summary_json,
        "score_breakdown": version.score_breakdown_json,
        "top_risks": version.top_risks_json,
        "evidence_summary": version.evidence_summary_json,
        "controls": version.controls_json,
        "metadata": version.metadata_json,
        "signed_hash": version.signed_hash,
    }


@router.post("/rebuild")
def rebuild_posture(
    issue_credential: bool = Query(True),
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    created = create_posture_version(
        db,
        auth.tenant_id,
        generated_by=f"api:{auth.role}",
        issue_default_credential=issue_credential,
    )
    version = created["version"]
    credential = created["credential"]
    return {
        "status": "rebuilt",
        "tenant_id": auth.tenant_id,
        "version_id": version.id,
        "version_no": version.version_no,
        "overall_score": version.overall_score,
        "risk_band": version.risk_band,
        "credential": {
            "credential_uuid": getattr(credential, "credential_uuid", None),
            "verification_token": getattr(credential, "verification_token", None),
            "expires_at": getattr(credential, "expires_at", None),
        },
    }


@router.get("/history")
def posture_history(
    limit: int = Query(20, ge=1, le=100),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    versions = list_posture_versions(db, auth.tenant_id, limit=limit)
    return [{
        "version_id": v.id,
        "version_no": v.version_no,
        "generated_at": v.generated_at,
        "overall_score": v.overall_score,
        "risk_band": v.risk_band,
        "insurance_readiness_score": v.insurance_readiness_score,
        "supply_chain_score": v.supply_chain_score,
        "critical_findings_count": v.critical_findings_count,
        "signed_hash": v.signed_hash,
        "is_current": v.is_current,
    } for v in versions]


@router.get("/history/{version_id}")
def posture_detail(
    version_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    v = db.query(PostureRecordVersion).filter(
        PostureRecordVersion.id == version_id,
        PostureRecordVersion.tenant_id == auth.tenant_id,
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Posture version not found")
    return {
        "version_id": v.id,
        "version_no": v.version_no,
        "generated_at": v.generated_at,
        "overall_score": v.overall_score,
        "risk_band": v.risk_band,
        "summary": v.summary_json,
        "score_breakdown": v.score_breakdown_json,
        "top_risks": v.top_risks_json,
        "controls": v.controls_json,
        "metadata": v.metadata_json,
    }


@router.get("/domains")
def posture_domains(
    version_id: int | None = None,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    version = get_current_posture_version(db, auth.tenant_id)
    if version_id is not None:
        version = db.query(PostureRecordVersion).filter(
            PostureRecordVersion.id == version_id,
            PostureRecordVersion.tenant_id == auth.tenant_id,
        ).first()
    if not version:
        raise HTTPException(status_code=404, detail="No posture version found")
    rows = get_posture_domains(db, version.id)
    return [{
        "id": d.id,
        "domain_name": d.domain_name,
        "score": d.score,
        "risk_band": d.risk_band,
        "summary": d.summary,
        "evidence_count": d.evidence_count,
        "details": d.details_json,
    } for d in rows]


@router.get("/evidence")
def posture_evidence(
    version_id: int | None = None,
    severity: str | None = None,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    version = get_current_posture_version(db, auth.tenant_id)
    if version_id is not None:
        version = db.query(PostureRecordVersion).filter(
            PostureRecordVersion.id == version_id,
            PostureRecordVersion.tenant_id == auth.tenant_id,
        ).first()
    if not version:
        raise HTTPException(status_code=404, detail="No posture version found")
    items = get_posture_evidence(db, version.id, severity=severity)
    return [{
        "id": e.id,
        "evidence_type": e.evidence_type,
        "source_module": e.source_module,
        "title": e.title,
        "description": e.description,
        "severity": e.severity,
        "asset_ref": e.asset_ref,
        "control_ref": e.control_ref,
        "external_ref": e.external_ref,
        "raw": e.raw_json,
        "created_at": e.created_at,
    } for e in items]
