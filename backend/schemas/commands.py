from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CreateScanJobRequest(BaseModel):
    tenant_id: str
    agent_ids: list[str] = Field(default_factory=list)
    job_type: str = "run_scan_full"
    requested_by: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    expires_epoch: int | None = None
    priority: str = "high"


class ScanJobResponse(BaseModel):
    job_id: int
    tenant_id: str
    status: str
    target_count: int
    completed_count: int
    failed_count: int
    command_ids: list[str]


class AgentCommandOut(BaseModel):
    command_id: str
    command_type: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    priority: str = "normal"
    expires_epoch: int | None = None


class AgentCommandPollResponse(BaseModel):
    commands: list[AgentCommandOut] = Field(default_factory=list)
    suggested_poll_interval_seconds: int = 60


class AgentCommandAckRequest(BaseModel):
    tenant_id: str
    acked_epoch: int


class AgentCommandResultRequest(BaseModel):
    tenant_id: str
    status: str
    started_epoch: int | None = None
    completed_epoch: int | None = None
    result: dict[str, Any] = Field(default_factory=dict)
