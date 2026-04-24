from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import SessionLocal, get_db
from schemas.compliance import AssetComplianceOut, ControlResultOut, TenantComplianceOut
from services.compliance_service import (
    assess_asset,
    assess_network_asset,
    assess_tenant,
    get_compliance_run_detail,
    get_compliance_runs,
    get_control_detail,
    save_compliance_run,
)
from services.ce_report import generate_ce_report
import asyncio as _asyncio
from integrations.dispatcher import dispatch_critical_finding as _dispatch_ce


router = APIRouter()

# Tracks in-progress assessment runs per tenant
_run_in_progress: set[str] = set()


# ---------------------------------------------------------------------------
# Live assessment (no persistence)
# ---------------------------------------------------------------------------

@router.get("/tenant", response_model=TenantComplianceOut)
def get_tenant_compliance(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Run a live CE v3.2 assessment without saving to history.
    Use POST /compliance/run to save results for audit trail purposes.
    """
    return assess_tenant(db, auth.tenant_id)


@router.get("/asset/{agent_id}", response_model=AssetComplianceOut)
def get_asset_compliance(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """
    Run CE v3.2 assessment for a single asset.
    agent_id formats:
      - Standard agent ID → CanonicalAsset
      - 'net-{id}'        → NetworkDiscoveredAsset by DB id
    """
    if agent_id.startswith("net-"):
        try:
            asset_db_id = int(agent_id[4:])
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid network asset ID: '{agent_id}'. Expected 'net-{{integer}}'.",
            )
        report = assess_network_asset(db, auth.tenant_id, asset_db_id)
    else:
        report = assess_asset(db, auth.tenant_id, agent_id)

    if not report:
        raise HTTPException(status_code=404, detail=f"Asset '{agent_id}' not found.")

    return AssetComplianceOut(
        tenant_id=report.tenant_id,
        agent_id=report.agent_id,
        hostname=report.hostname,
        assessed_at_epoch=report.assessed_at_epoch,
        overall_score=report.overall_score,
        overall_status=report.overall_status,
        summary=report.summary,
        controls=[
            ControlResultOut(
                control_id=c.control_id,
                control_name=c.control_name,
                status=c.status,
                score=c.score,
                findings=c.findings,
                evidence=c.evidence,
                remediation=c.remediation,
            )
            for c in report.controls
        ],
    )


# ---------------------------------------------------------------------------
# Saved assessment run (persisted to history)
# ---------------------------------------------------------------------------

@router.post("/run")
def trigger_compliance_run(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run and save a full CE v3.2 assessment immediately.
    """
    tenant_id = auth.tenant_id
    if tenant_id in _run_in_progress:
        return {"status": "run_already_in_progress", "tenant_id": tenant_id}

    _run_in_progress.add(tenant_id)
    try:
        result = save_compliance_run(db, tenant_id, triggered_by="user")

        try:
            controls = result.get("control_summary", {})
            for _cid, _c in controls.items():
                if (_c.get("status") or "") not in ("FAIL", "PARTIAL"):
                    continue
                _event = {
                    "event_type": "ce_control_failure",
                    "severity": 8 if _c.get("status") == "FAIL" else 5,
                    "description": f"CE v3.2 control {_cid} {_c.get('status', '').lower()}: {_c.get('name', '')}",
                    "ce_control": _cid,
                    "ce_compliant": False,
                    "remediation_class": "approval_required" if _c.get("status") == "FAIL" else "informational",
                    "remediation_action": " | ".join((_c.get("top_remediation") or [])[:2])[:300],
                    "tenant_id": tenant_id,
                }
                _asyncio.run(_dispatch_ce(db, tenant_id, _event))
        except Exception as _exc:
            import logging as _l
            _l.getLogger(__name__).warning("CE dispatch failed: %s", _exc)

        return {
            "status": "completed",
            "tenant_id": tenant_id,
            "run_id": result.get("run_id"),
            "run_epoch": result.get("run_epoch"),
            "assets_assessed": result.get("assets_assessed"),
            "assets_passing": result.get("assets_passing"),
            "assets_partial": result.get("assets_partial"),
            "assets_failing": result.get("assets_failing"),
            "ce_ready": result.get("ce_ready"),
            "tenant_overall_score": result.get("tenant_overall_score"),
        }
    finally:
        _run_in_progress.discard(tenant_id)


@router.get("/run/status")
def compliance_run_status(
    auth: AuthenticatedRequest = Depends(require_read),
) -> dict:
    """Check whether a compliance run is currently in progress."""
    running = auth.tenant_id in _run_in_progress
    return {
        "tenant_id": auth.tenant_id,
        "run_in_progress": running,
        "status": "running" if running else "idle",
    }


@router.get("/control/{control_id}")
def get_tenant_control_detail(
    control_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    detail = get_control_detail(db, auth.tenant_id, control_id)
    return detail


# ---------------------------------------------------------------------------
# Compliance history
# ---------------------------------------------------------------------------

@router.get("/runs")
def list_compliance_runs(
    limit: int = Query(50, ge=1, le=200),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return all saved compliance runs for this tenant (last 12 months), newest first."""
    return get_compliance_runs(db, auth.tenant_id, limit=limit)


@router.get("/runs/{run_id}")
def get_run_detail(
    run_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Return full asset-level detail for a specific historical compliance run."""
    detail = get_compliance_run_detail(db, auth.tenant_id, run_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Compliance run not found.")
    return detail


# ---------------------------------------------------------------------------
# PDF report
# ---------------------------------------------------------------------------

@router.get("/tenant/report.pdf")
def download_ce_report(
    org_name: str = Query(default="Organisation"),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Generate and download a CE v3.2 evidence package PDF."""
    from models.asset import CanonicalAsset
    from models.network import NetworkDiscoveredAsset

    tenant_data = assess_tenant(db, auth.tenant_id)
    full_reports = []

    for asset in db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == auth.tenant_id
    ).all():
        report = assess_asset(db, auth.tenant_id, asset.agent_id)
        if report:
            full_reports.append(report)

    for asset in db.query(NetworkDiscoveredAsset).filter(
        NetworkDiscoveredAsset.tenant_id == auth.tenant_id,
        NetworkDiscoveredAsset.is_active == True,
        NetworkDiscoveredAsset.agent_installed == False,
        NetworkDiscoveredAsset.asset_confidence != "observed_host",
    ).all():
        report = assess_network_asset(db, auth.tenant_id, asset.id)
        if report:
            full_reports.append(report)

    try:
        pdf_bytes = generate_ce_report(
            tenant_data=tenant_data,
            org_name=org_name,
            assessor="CyberAssetIQ v2.4",
            full_reports=full_reports,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    from datetime import datetime, timezone
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"CE_v32_Evidence_{org_name.replace(' ','_')}_{date_str}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        }
    )
