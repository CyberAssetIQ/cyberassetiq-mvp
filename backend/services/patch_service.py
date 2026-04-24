from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.patch")


# ---------------------------------------------------------------------------
# Ingest from agent
# ---------------------------------------------------------------------------

def ingest_patch_report(db: Session, tenant_id: str, data: dict) -> dict:
    from models.patch import PatchReport

    agent_id = data.get("agent_id", "unknown")

    report = PatchReport(
        tenant_id         = tenant_id,
        agent_id          = agent_id,
        os_name           = data.get("os_name"),
        os_version        = data.get("os_version"),
        os_build          = data.get("os_build"),
        os_supported      = data.get("os_supported", True),
        os_arch           = data.get("os_arch"),
        patch_score       = data.get("patch_score", 100),
        pending_total     = data.get("pending_total", 0),
        pending_critical  = data.get("pending_critical", 0),
        pending_important = data.get("pending_important", 0),
        outdated_count    = data.get("outdated_count", 0),
        windows_updates_json   = data.get("windows_updates", []),
        outdated_software_json = data.get("outdated_software", []),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    logger.info(
        "Patch report ingested: agent=%s score=%d pending=%d outdated=%d",
        agent_id, report.patch_score, report.pending_total, report.outdated_count,
    )

    return {
        "id":             report.id,
        "patch_score":    report.patch_score,
        "pending_total":  report.pending_total,
        "outdated_count": report.outdated_count,
    }


# ---------------------------------------------------------------------------
# Dashboard summary — latest report per agent
# ---------------------------------------------------------------------------

def get_patch_dashboard(db: Session, tenant_id: str) -> dict[str, Any]:
    from models.patch import PatchReport
    from models.agent import Agent

    # Get all agents for this tenant
    agents = db.query(Agent).filter(
        Agent.tenant_id == tenant_id,
    ).all()

    agent_map = {a.agent_id: a for a in agents}
    agent_reports = []

    for agent_id in agent_map:
        latest = (
            db.query(PatchReport)
            .filter(PatchReport.tenant_id == tenant_id, PatchReport.agent_id == agent_id)
            .order_by(desc(PatchReport.id))
            .first()
        )
        if latest:
            a = agent_map[agent_id]
            agent_reports.append({
                "agent_id":        agent_id,
                "hostname":        getattr(a, "hostname", agent_id) or agent_id,
                "os_name":         latest.os_name or "Unknown",
                "os_version":      latest.os_version or "",
                "os_supported":    latest.os_supported,
                "patch_score":     latest.patch_score,
                "pending_total":   latest.pending_total,
                "pending_critical": latest.pending_critical,
                "pending_important": latest.pending_important,
                "outdated_count":  latest.outdated_count,
                "reported_at":     latest.reported_at.isoformat() if latest.reported_at else None,
                "report_id":       latest.id,
            })

    # Also check for reports from agents not in the agents table
    all_agent_ids_with_reports = (
        db.query(PatchReport.agent_id)
        .filter(PatchReport.tenant_id == tenant_id)
        .distinct()
        .all()
    )
    reported_ids = {r.agent_id for r in all_agent_ids_with_reports}
    known_ids    = set(agent_map.keys())
    extra_ids    = reported_ids - known_ids

    for agent_id in extra_ids:
        latest = (
            db.query(PatchReport)
            .filter(PatchReport.tenant_id == tenant_id, PatchReport.agent_id == agent_id)
            .order_by(desc(PatchReport.id))
            .first()
        )
        if latest:
            agent_reports.append({
                "agent_id":        agent_id,
                "hostname":        agent_id,
                "os_name":         latest.os_name or "Unknown",
                "os_version":      latest.os_version or "",
                "os_supported":    latest.os_supported,
                "patch_score":     latest.patch_score,
                "pending_total":   latest.pending_total,
                "pending_critical": latest.pending_critical,
                "pending_important": latest.pending_important,
                "outdated_count":  latest.outdated_count,
                "reported_at":     latest.reported_at.isoformat() if latest.reported_at else None,
                "report_id":       latest.id,
            })

    if not agent_reports:
        return {
            "agents_assessed":     0,
            "avg_patch_score":     None,
            "total_critical":      0,
            "total_important":     0,
            "total_outdated":      0,
            "unsupported_os":      0,
            "agents":              [],
        }

    return {
        "agents_assessed": len(agent_reports),
        "avg_patch_score": round(sum(r["patch_score"] for r in agent_reports) / len(agent_reports)),
        "total_critical":  sum(r["pending_critical"] for r in agent_reports),
        "total_important": sum(r["pending_important"] for r in agent_reports),
        "total_outdated":  sum(r["outdated_count"]    for r in agent_reports),
        "unsupported_os":  sum(1 for r in agent_reports if not r["os_supported"]),
        "agents":          sorted(agent_reports, key=lambda x: x["patch_score"]),
    }


# ---------------------------------------------------------------------------
# Per-agent detail
# ---------------------------------------------------------------------------

def get_agent_patch_detail(db: Session, tenant_id: str, agent_id: str) -> dict | None:
    from models.patch import PatchReport

    latest = (
        db.query(PatchReport)
        .filter(PatchReport.tenant_id == tenant_id, PatchReport.agent_id == agent_id)
        .order_by(desc(PatchReport.id))
        .first()
    )
    if not latest:
        return None

    return {
        "agent_id":          agent_id,
        "os_name":           latest.os_name,
        "os_version":        latest.os_version,
        "os_build":          latest.os_build,
        "os_supported":      latest.os_supported,
        "os_arch":           latest.os_arch,
        "patch_score":       latest.patch_score,
        "pending_total":     latest.pending_total,
        "pending_critical":  latest.pending_critical,
        "pending_important": latest.pending_important,
        "outdated_count":    latest.outdated_count,
        "reported_at":       latest.reported_at.isoformat() if latest.reported_at else None,
        "windows_updates":   latest.windows_updates_json or [],
        "outdated_software": latest.outdated_software_json or [],
    }


# ---------------------------------------------------------------------------
# Approve a patch (dispatches command to agent)
# ---------------------------------------------------------------------------

def approve_patch(
    db: Session,
    tenant_id: str,
    agent_id: str,
    software_name: str,
    winget_id: str | None,
    patch_type: str = "software",
) -> dict:
    from models.patch import PatchApproval
    from models.commands import AgentCommand, ScanJob
    import uuid as _uuid

    now = datetime.now(timezone.utc)

    # Create approval record
    approval = PatchApproval(
        tenant_id     = tenant_id,
        agent_id      = agent_id,
        software_name = software_name,
        winget_id     = winget_id,
        patch_type    = patch_type,
        status        = "pending",
        approved_at   = now,
    )
    db.add(approval)
    db.flush()

    # Create a job + command for the agent to pick up
    job = ScanJob(
        tenant_id    = tenant_id,
        job_type     = "apply_patch",
        status       = "queued",
        requested_by = "admin",
    )
    db.add(job)
    db.flush()

    cmd_uuid = str(_uuid.uuid4())
    command = AgentCommand(
        command_uuid  = cmd_uuid,
        tenant_id     = tenant_id,
        agent_id      = agent_id,
        command_type  = "apply_patch",
        job_id        = job.id,
        status        = "queued",
        arguments_json = {
            "software_name": software_name,
            "winget_id":     winget_id or "",
        },
    )
    db.add(command)

    approval.command_uuid = cmd_uuid
    approval.status = "dispatched"
    db.commit()

    logger.info(
        "Patch approved: agent=%s software=%s winget_id=%s command=%s",
        agent_id, software_name, winget_id, cmd_uuid,
    )

    return {
        "approval_id":  approval.id,
        "command_uuid": cmd_uuid,
        "status":       "dispatched",
        "message":      f"Patch command queued for agent — {software_name} will be updated on next command poll.",
    }


# ---------------------------------------------------------------------------
# List approvals
# ---------------------------------------------------------------------------

def list_approvals(db: Session, tenant_id: str) -> list[dict]:
    from models.patch import PatchApproval
    from models.commands import AgentCommand

    rows = (
        db.query(PatchApproval)
        .filter(PatchApproval.tenant_id == tenant_id)
        .order_by(desc(PatchApproval.id))
        .limit(50)
        .all()
    )

    result = []
    for r in rows:
        # Sync status from live command record
        live_status = r.status
        if r.command_uuid:
            cmd = db.query(AgentCommand).filter(
                AgentCommand.command_uuid == r.command_uuid
            ).first()
            if cmd:
                if cmd.status == "completed":
                    live_status = "completed"
                elif cmd.status in ("failed", "cancelled", "expired"):
                    live_status = "failed"
                elif cmd.status in ("acked", "running"):
                    live_status = "running"
                elif cmd.status == "dispatched":
                    live_status = "dispatched"
                # Persist the updated status
                if live_status != r.status:
                    r.status = live_status
                    db.commit()

        result.append({
            "id":            r.id,
            "agent_id":      r.agent_id,
            "software_name": r.software_name,
            "winget_id":     r.winget_id,
            "patch_type":    r.patch_type,
            "status":        live_status,
            "approved_at":   r.approved_at.isoformat() if r.approved_at else None,
            "command_uuid":  r.command_uuid,
        })
    return result
