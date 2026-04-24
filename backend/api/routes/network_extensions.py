from __future__ import annotations

import logging
from threading import Thread

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import SessionLocal, get_db
from models.network_extensions import (
    AttackPathFinding,
    ExposureFinding,
    ExtensionServiceJob,
    PassiveDiscoveryResult,
)
from schemas.network_extensions import ExtensionServiceRequest, ExtensionServiceResponse
from services.attack_path_service import run_attack_path_job
from services.exposure_analysis_service import run_exposure_analysis_job
from services.passive_discovery_service import run_passive_discovery_job

logger = logging.getLogger(__name__)
router = APIRouter()

SERVICE_LABELS = {
    "passive_discovery": "Passive Discovery",
    "exposure_analysis": "Exposure Check",
    "attack_path_insight": "Attack Path Insight",
}


@router.post("/jobs", response_model=ExtensionServiceResponse)
def run_extension_service(
    payload: ExtensionServiceRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ExtensionServiceResponse:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    job_type = (payload.job_type or "").strip().lower()
    if job_type not in SERVICE_LABELS:
        raise HTTPException(status_code=400, detail="Unsupported extension job type.")
    job = ExtensionServiceJob(
        tenant_id=payload.tenant_id, requested_by=payload.requested_by, target=payload.target,
        job_type=job_type, service_name=SERVICE_LABELS[job_type], status="queued",
        progress_percent=0, current_stage="queued", current_target=None, findings_count=0,
        summary_json={"service": SERVICE_LABELS[job_type], "progress": {"phase": "Queued", "pct": 0}},
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    def _worker(jid, tenant_id, target, requested_by, job_type):
        worker_db = SessionLocal()
        try:
            if job_type == "passive_discovery":
                run_passive_discovery_job(worker_db, tenant_id=tenant_id, target=target, requested_by=requested_by, job_id=jid)
            elif job_type == "exposure_analysis":
                run_exposure_analysis_job(worker_db, tenant_id=tenant_id, target=target, requested_by=requested_by, job_id=jid)
            elif job_type == "attack_path_insight":
                run_attack_path_job(worker_db, tenant_id=tenant_id, target=target, requested_by=requested_by, job_id=jid)
        except Exception as exc:
            logger.exception("Extension job %s failed: %s", jid, exc)
            failed = worker_db.query(ExtensionServiceJob).filter(ExtensionServiceJob.id == jid).first()
            if failed:
                failed.status = "failed"
                failed.progress_percent = 100
                failed.current_stage = "failed"
                failed.summary_json = {**(failed.summary_json or {}), "error": str(exc)}
                worker_db.commit()
        finally:
            worker_db.close()

    Thread(target=_worker, args=(job.id, payload.tenant_id, payload.target, payload.requested_by, job_type), daemon=True).start()
    return ExtensionServiceResponse(job_id=job.id, tenant_id=job.tenant_id, status=job.status, target=job.target, job_type=job.job_type, service_name=job.service_name)


@router.get("/jobs")
def list_extension_jobs(auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(ExtensionServiceJob).filter(ExtensionServiceJob.tenant_id == auth.tenant_id).order_by(ExtensionServiceJob.id.desc()).limit(200).all()
    return [{"job_id": r.id, "target": r.target, "status": r.status, "job_type": r.job_type, "service_name": r.service_name,
             "progress_percent": r.progress_percent, "current_stage": r.current_stage, "current_target": r.current_target,
             "findings_count": r.findings_count, "summary": r.summary_json or {}, "created_at": str(r.created_at)} for r in rows]


@router.get("/jobs/{job_id}/progress")
def get_extension_job_progress(job_id: int, auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> dict:
    job = db.query(ExtensionServiceJob).filter(ExtensionServiceJob.id == job_id, ExtensionServiceJob.tenant_id == auth.tenant_id).first()
    if not job: raise HTTPException(status_code=404, detail="Job not found.")
    summary = job.summary_json or {}
    return {"job_id": job.id, "status": job.status, "service_name": job.service_name, "job_type": job.job_type,
            "progress_percent": job.progress_percent, "current_stage": job.current_stage, "current_target": job.current_target,
            "findings_count": job.findings_count, "progress": summary.get("progress") or {}, "summary": summary}


@router.get("/passive-results")
def list_passive_results(auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(PassiveDiscoveryResult).filter(PassiveDiscoveryResult.tenant_id == auth.tenant_id).order_by(PassiveDiscoveryResult.id.desc()).limit(200).all()
    return [{"id": r.id, "job_id": r.job_id, "ip_address": r.ip_address, "mac_address": r.mac_address,
             "hostname": r.hostname, "vendor": r.vendor, "source_method": r.source_method,
             "confidence": r.confidence, "created_at": str(r.created_at)} for r in rows]


@router.get("/exposure-findings")
def list_exposure_findings(auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(ExposureFinding).filter(ExposureFinding.tenant_id == auth.tenant_id).order_by(ExposureFinding.id.desc()).limit(200).all()
    return [{"id": r.id, "job_id": r.job_id, "asset_id": r.asset_id, "ip_address": r.ip_address,
             "finding_type": r.finding_type, "severity": r.severity, "title": r.title,
             "description": r.description, "remediation": r.remediation, "created_at": str(r.created_at)} for r in rows]


@router.get("/attack-path-findings")
def list_attack_path_findings(auth: AuthenticatedRequest = Depends(require_read), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(AttackPathFinding).filter(AttackPathFinding.tenant_id == auth.tenant_id).order_by(AttackPathFinding.id.desc()).limit(200).all()
    return [{"id": r.id, "job_id": r.job_id, "asset_id": r.asset_id, "ip_address": r.ip_address,
             "path_type": r.path_type, "risk_score": r.risk_score, "narrative": r.narrative,
             "created_at": str(r.created_at)} for r in rows]
