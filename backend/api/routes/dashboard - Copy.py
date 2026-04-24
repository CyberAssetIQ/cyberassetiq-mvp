from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.deps import AuthenticatedRequest, require_read
from db.session import get_db
from models.commands import ScanJob
from models.telemetry import VulnerabilityFinding

router = APIRouter()

@router.get("/summary")
def dashboard_summary(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    tenant_id = auth.tenant_id
    try:
        from models.asset import CanonicalAsset
        managed = db.query(CanonicalAsset).filter_by(tenant_id=tenant_id).count()
    except:
        managed = 0
    try:
        from models.network import NetworkDiscoveredAsset
        network = db.query(NetworkDiscoveredAsset).filter_by(tenant_id=tenant_id).count()
    except:
        network = 0
    open_cves = db.query(VulnerabilityFinding).filter_by(tenant_id=tenant_id, status="open").count()
    critical_cves = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id==tenant_id,
        VulnerabilityFinding.status=="open",
        VulnerabilityFinding.severity=="CRITICAL"
    ).count()
    running_jobs = db.query(ScanJob).filter(
        ScanJob.tenant_id==tenant_id,
        ScanJob.status.in_(["queued","running"])
    ).count()
    return {
        "tenant_id": tenant_id,
        "total_assets": managed + network,
        "managed_assets": managed,
        "network_assets": network,
        "open_cves": open_cves,
        "critical_cves": critical_cves,
        "risk_score": None,
        "running_jobs": running_jobs,
        "ai_brief": None,
        "scan_status": "running" if running_jobs else "ready",
    }
