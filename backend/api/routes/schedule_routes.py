from __future__ import annotations

"""
CyberAssetIQ — Scan Schedule API Routes
CRUD for scan schedules + manual trigger
"""

import time
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.schedules import ScanSchedule

router = APIRouter()


class ScheduleIn(BaseModel):
    name:           str
    scan_type:      str   # network_scan | vuln_scan | threat_intel | agent_scan
    target:         str | None = None
    interval_hours: int = 24
    is_active:      bool = True
    config:         dict | None = None


@router.get("")
def list_schedules(
    auth: AuthenticatedRequest = Depends(require_read),
    db:   Session = Depends(get_db),
) -> list[dict]:
    rows = (
        db.query(ScanSchedule)
        .filter(ScanSchedule.tenant_id == auth.tenant_id)
        .order_by(ScanSchedule.id.asc())
        .all()
    )
    return [_fmt(r) for r in rows]


@router.post("")
def create_schedule(
    payload: ScheduleIn,
    auth:    AuthenticatedRequest = Depends(require_admin),
    db:      Session = Depends(get_db),
) -> dict:
    allowed = {"network_scan", "vuln_scan", "threat_intel", "agent_scan"}
    if payload.scan_type not in allowed:
        raise HTTPException(400, detail=f"scan_type must be one of: {sorted(allowed)}")

    now = int(time.time())
    row = ScanSchedule(
        tenant_id      = auth.tenant_id,
        name           = payload.name,
        scan_type      = payload.scan_type,
        target         = payload.target,
        interval_hours = payload.interval_hours,
        is_active      = payload.is_active,
        next_run_epoch = now + payload.interval_hours * 3600,
        config         = payload.config or {},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _fmt(row)


@router.patch("/{schedule_id}")
def update_schedule(
    schedule_id: int,
    payload:     ScheduleIn,
    auth:        AuthenticatedRequest = Depends(require_admin),
    db:          Session = Depends(get_db),
) -> dict:
    row = _get_or_404(db, auth.tenant_id, schedule_id)
    row.name           = payload.name
    row.scan_type      = payload.scan_type
    row.target         = payload.target
    row.interval_hours = payload.interval_hours
    row.is_active      = payload.is_active
    row.config         = payload.config or {}
    if payload.is_active and not row.next_run_epoch:
        row.next_run_epoch = int(time.time()) + payload.interval_hours * 3600
    db.commit()
    db.refresh(row)
    return _fmt(row)


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    auth:        AuthenticatedRequest = Depends(require_admin),
    db:          Session = Depends(get_db),
) -> dict:
    row = _get_or_404(db, auth.tenant_id, schedule_id)
    db.delete(row)
    db.commit()
    return {"status": "deleted", "id": schedule_id}


@router.post("/{schedule_id}/run-now")
def run_schedule_now(
    schedule_id: int,
    auth:        AuthenticatedRequest = Depends(require_admin),
    db:          Session = Depends(get_db),
) -> dict:
    """Trigger a scheduled scan immediately without waiting for the interval."""
    row = _get_or_404(db, auth.tenant_id, schedule_id)
    # Force next_run_epoch to now so the background loop picks it up immediately
    row.next_run_epoch = int(time.time()) - 1
    db.commit()
    return {"status": "triggered", "id": schedule_id, "scan_type": row.scan_type}


def _get_or_404(db: Session, tenant_id: str, schedule_id: int) -> ScanSchedule:
    row = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.id        == schedule_id,
            ScanSchedule.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(404, detail="Schedule not found.")
    return row


def _fmt(r: ScanSchedule) -> dict:
    import datetime
    next_run_str = None
    if r.next_run_epoch:
        next_run_str = datetime.datetime.fromtimestamp(
            r.next_run_epoch, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    last_run_str = None
    if r.last_run_epoch:
        last_run_str = datetime.datetime.fromtimestamp(
            r.last_run_epoch, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    return {
        "id":             r.id,
        "name":           r.name,
        "scan_type":      r.scan_type,
        "target":         r.target,
        "interval_hours": r.interval_hours,
        "is_active":      r.is_active,
        "last_run":       last_run_str,
        "next_run":       next_run_str,
        "last_status":    r.last_status,
        "last_result":    r.last_result,
        "config":         r.config,
    }
