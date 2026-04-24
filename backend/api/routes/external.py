from __future__ import annotations

from threading import Thread

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import SessionLocal, get_db

router = APIRouter(prefix="/api/external", tags=["external-exposure"])


@router.post("/scan")
def start_external_scan(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Start an external exposure scan against the public IP. Runs in background."""
    from services.external_exposure_service import run_external_scan
    from models.external_exposure import ExternalScan

    # Check if a scan is already running
    from sqlalchemy import desc
    running = db.query(ExternalScan).filter(
        ExternalScan.tenant_id == auth.tenant_id,
        ExternalScan.scan_status == "running",
    ).first()
    if running:
        return {"status": "already_running", "scan_id": running.id,
                "message": "A scan is already in progress. Check /api/external/latest for results."}

    tenant_id = auth.tenant_id

    def _worker():
        wdb = SessionLocal()
        try:
            run_external_scan(wdb, tenant_id)
        finally:
            wdb.close()

    Thread(target=_worker, daemon=True, name="external-scan").start()
    return {"status": "started", "message": "External scan started. Poll /api/external/latest for results."}


@router.get("/latest")
def get_latest_scan(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.external_exposure_service import get_latest_scan
    result = get_latest_scan(db, auth.tenant_id)
    if not result:
        return {"status": "no_scans", "message": "No completed scans yet. Run a scan first."}
    return result


@router.get("/status")
def get_scan_status(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Check if a scan is currently running."""
    from models.external_exposure import ExternalScan
    running = db.query(ExternalScan).filter(
        ExternalScan.tenant_id == auth.tenant_id,
        ExternalScan.scan_status == "running",
    ).first()
    if running:
        return {"status": "running", "scan_id": running.id,
                "public_ip": running.public_ip, "started_at": running.scanned_at.isoformat()}
    return {"status": "idle"}


@router.get("/history")
def get_scan_history(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.external_exposure_service import get_scan_history
    return get_scan_history(db, auth.tenant_id)


@router.get("/public-ip")
def get_public_ip(
    auth: AuthenticatedRequest = Depends(require_read),
):
    from services.external_exposure_service import get_public_ip
    ip = get_public_ip()
    return {"public_ip": ip or "Could not determine"}


class ResolveFindingBody(BaseModel):
    status: str = "resolved"   # resolved / accepted_risk


@router.patch("/findings/{finding_id}")
def resolve_finding(
    finding_id: int,
    body: ResolveFindingBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.external_exposure_service import resolve_finding
    return resolve_finding(db, auth.tenant_id, finding_id, body.status)
