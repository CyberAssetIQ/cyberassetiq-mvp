from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db
from models.commands import ScanJob
from models.telemetry import VulnerabilityFinding
from services.asset_correlation_service import list_unified_assets
from services.nvd_service import get_vuln_summary, get_latest_scan_run

router = APIRouter()


@router.get("/summary")
def dashboard_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    tenant_id = auth.tenant_id

    assets = list_unified_assets(db, tenant_id)
    total_assets = len(assets)

    # Production rule:
    # Trust the unified correlation service's final managed flag.
    # Only assets with managed=True are counted as agent-managed.
    managed_assets = sum(
        1 for a in assets
        if a.get("managed") is True
        and str(a.get("agent_id") or "").startswith("agent-")
    )

    network_assets = total_assets - managed_assets

    vuln_summary = get_vuln_summary(db, tenant_id)
    open_cves = int(vuln_summary.get("total_open_cves") or 0)
    critical_cves = int(vuln_summary.get("critical") or 0)

    running_jobs = db.query(ScanJob).filter(
        ScanJob.tenant_id == tenant_id,
        ScanJob.status.in_(["queued", "running"]),
    ).count()

    # Dashboard risk must not use stale raw historical CVE risk from list_unified_assets().
    # For real managed agents, recalculate risk from latest completed vuln scan.
    latest_vuln_scan = get_latest_scan_run(db, tenant_id)
    latest_cve_counts = {}
    if latest_vuln_scan:
        rows = (
            db.query(VulnerabilityFinding.agent_id, func.count(VulnerabilityFinding.id))
            .filter(
                VulnerabilityFinding.tenant_id == tenant_id,
                VulnerabilityFinding.scan_run_id == latest_vuln_scan.id,
                VulnerabilityFinding.status == "open",
            )
            .group_by(VulnerabilityFinding.agent_id)
            .all()
        )
        latest_cve_counts = {agent_id: count for agent_id, count in rows}

    risk_scores = []
    for a in assets:
        agent_id = str(a.get("agent_id") or "")
        if agent_id.startswith("agent-"):
            cve_count = latest_cve_counts.get(agent_id, 0)
            score = (
                95 if cve_count >= 500 else
                85 if cve_count >= 100 else
                70 if cve_count >= 25 else
                50 if cve_count >= 5 else
                20 if cve_count >= 1 else
                0
            )
            risk_scores.append(score)
        else:
            risk_scores.append(int(a.get("risk_score") or 0))

    risk_score = max(risk_scores) if risk_scores else 0

    return {
        "tenant_id": tenant_id,
        "total_assets": total_assets,
        "managed_assets": managed_assets,
        "network_assets": network_assets,
        "open_cves": open_cves,
        "critical_cves": critical_cves,
        "risk_score": risk_score,
        "running_jobs": running_jobs,
        "ai_brief": None,
        "scan_status": "running" if running_jobs else "ready",
        "source": "unified_assets_and_live_vulnerabilities",
    }

