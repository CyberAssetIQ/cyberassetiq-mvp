from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_auth, require_read, require_admin
from db.session import get_db
from models.commands import ScanJob
from schemas.commands import (
    AgentCommandAckRequest,
    AgentCommandOut,
    AgentCommandPollResponse,
    AgentCommandResultRequest,
    CreateScanJobRequest,
    ScanJobResponse,
)
from services.command_service import ack_command, complete_command, create_scan_job, poll_agent_commands

router = APIRouter()


@router.post("/scan-jobs", response_model=ScanJobResponse)
def create_job(
    payload: CreateScanJobRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ScanJobResponse:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    if not payload.agent_ids:
        raise HTTPException(status_code=400, detail="agent_ids cannot be empty")
    job, commands = create_scan_job(
        db=db,
        tenant_id=payload.tenant_id,
        agent_ids=payload.agent_ids,
        job_type=payload.job_type,
        requested_by=payload.requested_by,
        arguments=payload.arguments,
        expires_epoch=payload.expires_epoch,
        priority=payload.priority,
    )
    return ScanJobResponse(
        job_id=job.id,
        tenant_id=job.tenant_id,
        status=job.status,
        target_count=job.target_count,
        completed_count=job.completed_count,
        failed_count=job.failed_count,
        command_ids=[c.command_uuid for c in commands],
    )


@router.get("/scan-jobs")
def list_jobs(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    jobs = db.query(ScanJob).filter(ScanJob.tenant_id == auth.tenant_id).order_by(ScanJob.id.desc()).limit(100).all()
    return [
        {
            "job_id": j.id,
            "tenant_id": j.tenant_id,
            "requested_by": j.requested_by,
            "job_type": j.job_type,
            "status": j.status,
            "target_count": j.target_count,
            "completed_count": j.completed_count,
            "failed_count": j.failed_count,
            "created_at": str(j.created_at),
        }
        for j in jobs
    ]


@router.get("/agents/{agent_id}/commands", response_model=AgentCommandPollResponse)
def get_agent_commands(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
) -> AgentCommandPollResponse:
    auth.require_role("agent", "admin")
    if auth.agent_id and auth.agent_id != agent_id and auth.role != "admin":
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")
    commands, suggested_poll = poll_agent_commands(db, tenant_id=auth.tenant_id, agent_id=agent_id)
    return AgentCommandPollResponse(
        commands=[
            AgentCommandOut(
                command_id=c.command_uuid,
                command_type=c.command_type,
                arguments=c.arguments_json or {},
                priority=c.priority,
                expires_epoch=c.expires_epoch,
            )
            for c in commands
        ],
        suggested_poll_interval_seconds=suggested_poll,
    )


@router.post("/agents/{agent_id}/commands/{command_id}/ack")
def ack_agent_command(
    agent_id: str,
    command_id: str,
    payload: AgentCommandAckRequest,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
) -> dict:
    auth.require_role("agent", "admin")
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    if auth.agent_id and auth.agent_id != agent_id and auth.role != "admin":
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")
    command = ack_command(db, tenant_id=payload.tenant_id, agent_id=agent_id, command_uuid=command_id, acked_epoch=payload.acked_epoch)
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    return {"status": "acked", "command_id": command.command_uuid}


@router.post("/agents/{agent_id}/commands/{command_id}/result")
def command_result(
    agent_id: str,
    command_id: str,
    payload: AgentCommandResultRequest,
    auth: AuthenticatedRequest = Depends(require_auth),
    db: Session = Depends(get_db),
) -> dict:
    auth.require_role("agent", "admin")
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    if auth.agent_id and auth.agent_id != agent_id and auth.role != "admin":
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")
    command = complete_command(
        db,
        tenant_id=payload.tenant_id,
        agent_id=agent_id,
        command_uuid=command_id,
        status=payload.status,
        started_epoch=payload.started_epoch,
        completed_epoch=payload.completed_epoch,
        result=payload.result,
    )
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    return {"status": command.status, "command_id": command.command_uuid}


@router.post("/agents/{agent_id}/quarantine")
def quarantine_host(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    _, commands = create_scan_job(
        db=db,
        tenant_id=auth.tenant_id,
        agent_ids=[agent_id],
        job_type="isolate_host",
        requested_by=f"admin:key_id:{auth.key_id}",
        arguments={"reason": "Manual quarantine - admin initiated"},
        expires_epoch=None,
        priority="high",
    )
    cmd = commands[0]
    return {"ok": True, "agent_id": agent_id, "command_id": cmd.command_uuid, "status": cmd.status}


@router.post("/agents/{agent_id}/force-checkin")
def force_checkin(
    agent_id: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    _, commands = create_scan_job(
        db=db,
        tenant_id=auth.tenant_id,
        agent_ids=[agent_id],
        job_type="force_checkin",
        requested_by=f"admin:key_id:{auth.key_id}",
        arguments={},
        expires_epoch=None,
        priority="high",
    )
    cmd = commands[0]
    return {"ok": True, "agent_id": agent_id, "command_id": cmd.command_uuid, "status": cmd.status}
