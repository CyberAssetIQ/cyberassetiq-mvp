from __future__ import annotations

import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import SessionLocal, get_db
from models.telemetry import VulnerabilityFinding
from models.vuln_scan import VulnAnnotation, VulnScanRun
from services.nvd_service import (
    create_or_update_annotation,
    get_all_annotations,
    get_effective_findings_across_history,
    get_latest_findings_with_annotations,
    get_scan_run_findings,
    get_scan_runs,
    get_vuln_summary,
    run_vuln_scan_for_tenant,
)

router = APIRouter()

# Tracks in-progress background scans per tenant
_scan_in_progress: set[str] = set()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary")
def vulnerability_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Return aggregated CVE counts from the latest scan run, accounting for annotations."""
    return get_vuln_summary(db, auth.tenant_id)


# ---------------------------------------------------------------------------
# Scan trigger + status
# ---------------------------------------------------------------------------

@router.get("/scan/status")
def vuln_scan_status(
    auth: AuthenticatedRequest = Depends(require_read),
) -> dict:
    """Check whether a background vulnerability scan is currently running."""
    running = auth.tenant_id in _scan_in_progress
    return {
        "tenant_id": auth.tenant_id,
        "scan_running": running,
        "status": "running" if running else "idle",
    }


@router.post("/scan")
def trigger_vuln_scan(
    background_tasks: BackgroundTasks,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Trigger a background NVD scan. Rate limit: one concurrent scan per tenant."""
    tenant_id = auth.tenant_id
    if tenant_id in _scan_in_progress:
        return {"status": "scan_already_running", "tenant_id": tenant_id}

    def _run_scan() -> None:
        _scan_in_progress.add(tenant_id)
        scan_db = SessionLocal()
        try:
            run_vuln_scan_for_tenant(scan_db, tenant_id)
        finally:
            scan_db.close()
            _scan_in_progress.discard(tenant_id)

    background_tasks.add_task(_run_scan)
    return {"status": "scan_started", "tenant_id": tenant_id}


# ---------------------------------------------------------------------------
# Findings (latest scan run, merged with annotations)
# ---------------------------------------------------------------------------

@router.get("/findings")
def list_vuln_findings(
    severity: str | None = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    agent_id: str | None = Query(None),
    status: str | None = Query(None, description="open | resolved | accepted_risk | false_positive"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    all_agents: bool = Query(False, description="If true, return findings across ALL scan runs (shows all enrolled agents)"),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    List findings from the latest scan run, merged with annotation status.
    Pass ?all_agents=true to see CVEs from all agents across all scan runs.
    """
    allowed_statuses = {"open", "resolved", "accepted_risk", "false_positive", "archived"}
    status_filter = status or "open"
    if status_filter not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {sorted(allowed_statuses)}",
        )

    if all_agents:
        return get_effective_findings_across_history(
            db=db,
            tenant_id=auth.tenant_id,
            severity=severity,
            status_filter=status_filter,
            agent_id=agent_id,
            limit=limit,
            offset=offset,
        )

    return get_latest_findings_with_annotations(
        db=db,
        tenant_id=auth.tenant_id,
        severity=severity,
        status_filter=status_filter,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Finding status update (backwards-compatible — now creates an annotation)
# ---------------------------------------------------------------------------

class _FindingStatusUpdate(BaseModel):
    status: str
    note: str | None = None


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
    payload: _FindingStatusUpdate | None = None,
    status: str | None = Query(None),
) -> dict:
    """
    Update the status of a finding. Backwards-compatible endpoint.
    Now creates/updates a VulnAnnotation rather than mutating the finding row.
    Allowed: open | resolved | accepted_risk | false_positive
    """
    allowed = {"resolved", "accepted_risk", "false_positive", "open"}
    new_status = (payload.status if payload else None) or status
    note = payload.note if payload else None

    if not new_status:
        raise HTTPException(
            status_code=400,
            detail="Status required — provide as JSON body or ?status= query param",
        )
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {sorted(allowed)}")

    finding = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.id == finding_id,
        VulnerabilityFinding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    # Create/update annotation (finding row itself stays immutable)
    ann = create_or_update_annotation(
        db=db,
        tenant_id=auth.tenant_id,
        cve_id=finding.cve_id,
        agent_id=finding.agent_id,
        software_name=finding.software_name,
        status=new_status,
        note=note,
    )
    return {
        "id": finding_id,
        "cve_id": finding.cve_id,
        "status": new_status,
        "annotation_id": ann.id,
    }


# ---------------------------------------------------------------------------
# Scan run history
# ---------------------------------------------------------------------------

@router.get("/scan-runs")
def list_scan_runs(
    limit: int = Query(20, ge=1, le=100),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return all scan runs for this tenant, newest first."""
    runs = get_scan_runs(db, auth.tenant_id, limit=limit)
    return [
        {
            "id": r.id,
            "scan_epoch": r.scan_epoch,
            "packages_scanned": r.packages_scanned,
            "total_packages": r.total_packages,
            "total_cves": r.total_cves,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
            "medium_count": r.medium_count,
            "low_count": r.low_count,
            "status": r.status,
            "warning": r.warning,
        }
        for r in runs
    ]


@router.get("/scan-runs/{run_id}/findings")
def get_scan_run_findings_route(
    run_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return the immutable findings snapshot for a specific historical scan run."""
    # Verify scan run belongs to this tenant
    scan_run = db.query(VulnScanRun).filter(
        VulnScanRun.id == run_id,
        VulnScanRun.tenant_id == auth.tenant_id,
    ).first()
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found.")

    findings = get_scan_run_findings(db, auth.tenant_id, run_id)
    return [
        {
            "id": f.id,
            "cve_id": f.cve_id,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "software_name": f.software_name,
            "software_version": f.software_version,
            "agent_id": f.agent_id,
            "published": f.published,
            "description": f.description,
        }
        for f in findings
    ]


# ---------------------------------------------------------------------------
# Annotations (direct API — audit trail)
# ---------------------------------------------------------------------------

class _AnnotationCreate(BaseModel):
    cve_id: str
    agent_id: str | None = None
    software_name: str | None = None
    status: str
    note: str | None = None
    annotated_by: str | None = None


@router.post("/annotations")
def create_annotation(
    payload: _AnnotationCreate,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Create or update an annotation for a CVE. One annotation per (cve_id, agent_id)."""
    allowed = {"resolved", "accepted_risk", "false_positive", "open"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of: {sorted(allowed)}")

    ann = create_or_update_annotation(
        db=db,
        tenant_id=auth.tenant_id,
        cve_id=payload.cve_id,
        agent_id=payload.agent_id,
        software_name=payload.software_name,
        status=payload.status,
        annotated_by=payload.annotated_by,
        note=payload.note,
    )
    return {
        "id": ann.id,
        "cve_id": ann.cve_id,
        "agent_id": ann.agent_id,
        "status": ann.status,
        "annotated_epoch": ann.annotated_epoch,
        "note": ann.note,
    }


@router.get("/annotations")
def list_annotations(
    limit: int = Query(500, ge=1, le=1000),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return all annotations for this tenant — the complete audit trail."""
    annotations = get_all_annotations(db, auth.tenant_id, limit=limit)
    return [
        {
            "id": a.id,
            "cve_id": a.cve_id,
            "agent_id": a.agent_id,
            "software_name": a.software_name,
            "status": a.status,
            "annotated_by": a.annotated_by,
            "annotated_epoch": a.annotated_epoch,
            "note": a.note,
        }
        for a in annotations
    ]


# ─────────────────────────────────────────────────────────────────────────────
# AI CVE Exploitability Context
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/findings/{finding_id}/explain")
def explain_cve_finding(
    finding_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    AI-powered CVE explanation: is this vulnerability actually dangerous
    in this specific environment? Returns adjusted priority, patch urgency,
    and plain-English explanation.
    """
    from services.ai_cve_context_service import AICVEContextService
    svc = AICVEContextService(db=db)
    return svc.explain_finding(finding_id=finding_id, tenant_id=auth.tenant_id)


@router.get("/findings/ai-priorities")
def get_ai_cve_priorities(
    limit: int = Query(20, ge=1, le=100),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Returns open CVE findings re-ranked by actual exploitability risk.
    Factors in: known exploits, internet exposure, RCE class,
    authentication requirements, and asset security posture.
    """
    from services.ai_cve_context_service import AICVEContextService
    svc = AICVEContextService(db=db)
    return svc.batch_prioritise(tenant_id=auth.tenant_id, limit=limit)
