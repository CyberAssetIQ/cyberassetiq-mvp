"""api/routes/agent_health.py - Agent staleness sweep + per-agent health endpoint"""
from __future__ import annotations
import time
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.agent import Agent

router = APIRouter(prefix="/api/admin", tags=["admin"])
DEFAULT_THRESHOLD = 600  # 10 minutes

@router.post("/agents/check-staleness")
def check_agent_staleness(
    threshold_seconds: int = Query(DEFAULT_THRESHOLD, ge=60, le=86400,
        description="Seconds without heartbeat before agent marked offline"),
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Sweep all agents for this tenant. Any agent whose last_seen_epoch is
    older than threshold_seconds is set to 'offline'; agents that have
    recovered are set back to 'active'. Designed to be called by the
    scheduler (posture_rebuild) and from the admin panel on demand.
    """
    now    = int(time.time())
    cutoff = now - threshold_seconds
    agents = db.query(Agent).filter(Agent.tenant_id == auth.tenant_id).all()
    went_offline, came_online, already_ok, already_offline, no_data = [], [], [], [], []
    for a in agents:
        if a.last_seen_epoch is None:
            no_data.append(a.agent_id); continue
        if a.last_seen_epoch < cutoff:
            if a.status == "active":
                a.status = "offline"; went_offline.append(a.agent_id)
            else:
                already_offline.append(a.agent_id)
        else:
            if a.status != "active":
                a.status = "active"; came_online.append(a.agent_id)
            else:
                already_ok.append(a.agent_id)
    db.commit()
    return {
        "threshold_seconds": threshold_seconds,
        "evaluated_at":      now,
        "total_agents":      len(agents),
        "went_offline":      went_offline,
        "came_online":       came_online,
        "already_active":    already_ok,
        "already_offline":   already_offline,
        "unknown_no_data":   no_data,
        "summary": {
            "newly_offline": len(went_offline),
            "newly_online":  len(came_online),
            "active":        len(already_ok) + len(came_online),
            "offline":       len(already_offline) + len(went_offline),
        },
    }

@router.get("/agents/{agent_id}/health")
def get_agent_health(agent_id: str,
    threshold_seconds: int = Query(DEFAULT_THRESHOLD, ge=60, le=86400),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Real-time health verdict for a single agent based on last heartbeat."""
    a = db.query(Agent).filter(Agent.tenant_id==auth.tenant_id,
        Agent.agent_id==agent_id).first()
    if not a: raise HTTPException(status_code=404, detail="Agent not found.")
    now = int(time.time())
    last = a.last_seen_epoch
    if last is None:
        secs, within, verdict = None, False, "unknown"
    else:
        secs    = now - last
        within  = secs <= threshold_seconds
        verdict = "online" if within else "offline"
    return {"agent_id": a.agent_id, "hostname": a.hostname, "stored_status": a.status,
            "verdict": verdict, "last_seen_epoch": last,
            "seconds_since_heartbeat": secs, "threshold_seconds": threshold_seconds,
            "within_threshold": within, "checked_at": now}
