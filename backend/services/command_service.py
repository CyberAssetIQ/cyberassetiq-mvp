from __future__ import annotations

import time
import uuid
from typing import Any

from sqlalchemy import case
from sqlalchemy.orm import Session

from models.commands import AgentCommand, ScanJob

# Numeric priority mapping so ORDER BY works correctly:
# high=3, normal=2, low=1 — higher number dispatched first
_PRIORITY_ORDER = case(
    (AgentCommand.priority == "high", 3),
    (AgentCommand.priority == "normal", 2),
    (AgentCommand.priority == "low", 1),
    else_=2,
)


def create_scan_job(
    db: Session,
    tenant_id: str,
    agent_ids: list[str],
    job_type: str,
    requested_by: str | None,
    arguments: dict[str, Any] | None,
    expires_epoch: int | None,
    priority: str,
) -> tuple[ScanJob, list[AgentCommand]]:
    job = ScanJob(
        tenant_id=tenant_id,
        requested_by=requested_by,
        job_type=job_type,
        status="queued",
        target_count=len(agent_ids),
        arguments_json=arguments or {},
    )
    db.add(job)
    db.flush()

    commands: list[AgentCommand] = []
    for agent_id in agent_ids:
        command = AgentCommand(
            tenant_id=tenant_id,
            agent_id=agent_id,
            job_id=job.id,
            command_uuid=f"cmd_{uuid.uuid4().hex[:20]}",
            command_type=job_type,
            arguments_json=arguments or {},
            status="queued",
            priority=priority,
            expires_epoch=expires_epoch,
        )
        db.add(command)
        commands.append(command)

    db.commit()
    return job, commands


def poll_agent_commands(
    db: Session,
    tenant_id: str,
    agent_id: str,
    limit: int = 5,
) -> tuple[list[AgentCommand], int]:
    now = int(time.time())

    # Expire stale commands
    expired = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.is_deleted.is_(False),
            AgentCommand.status.in_(["queued", "dispatched", "acked", "running"]),
            AgentCommand.expires_epoch.is_not(None),
            AgentCommand.expires_epoch < now,
        )
        .all()
    )
    for item in expired:
        item.status = "expired"
        item.completed_epoch = now

    # Fetch commands ordered by numeric priority (high first), then FIFO within priority
    commands = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.is_deleted.is_(False),
            AgentCommand.status.in_(["queued", "dispatched"]),
        )
        .order_by(_PRIORITY_ORDER.desc(), AgentCommand.id.asc())
        .limit(limit)
        .all()
    )

    for command in commands:
        command.status = "dispatched"
        command.delivery_count += 1

    db.commit()
    suggested_poll = 15 if commands else 60
    return commands, suggested_poll


def ack_command(
    db: Session,
    tenant_id: str,
    agent_id: str,
    command_uuid: str,
    acked_epoch: int,
) -> AgentCommand | None:
    command = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.command_uuid == command_uuid,
            AgentCommand.is_deleted.is_(False),
        )
        .first()
    )
    if not command:
        return None
    command.status = "acked"
    command.acked_epoch = acked_epoch
    db.commit()
    return command


def complete_command(
    db: Session,
    tenant_id: str,
    agent_id: str,
    command_uuid: str,
    status: str,
    started_epoch: int | None,
    completed_epoch: int | None,
    result: dict[str, Any],
) -> AgentCommand | None:
    command = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.command_uuid == command_uuid,
            AgentCommand.is_deleted.is_(False),
        )
        .first()
    )
    if not command:
        return None

    command.status = status
    command.started_epoch = started_epoch or command.started_epoch
    command.completed_epoch = completed_epoch or int(time.time())
    command.result_json = result

    if command.job_id:
        refresh_job_status(db, command.job_id)
    db.commit()
    return command


def refresh_job_status(db: Session, job_id: int) -> None:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        return
    commands = (
        db.query(AgentCommand)
        .filter(AgentCommand.job_id == job.id, AgentCommand.is_deleted.is_(False))
        .all()
    )
    if not commands:
        job.status = "completed"
        return

    completed = sum(1 for c in commands if c.status == "completed")
    failed = sum(1 for c in commands if c.status in {"failed", "expired", "cancelled"})
    running = any(c.status in {"acked", "running", "dispatched"} for c in commands)

    job.completed_count = completed
    job.failed_count = failed

    if completed + failed == len(commands):
        job.status = "completed" if failed == 0 else "partial_failed"
    elif running:
        job.status = "running"
    else:
        job.status = "queued"
