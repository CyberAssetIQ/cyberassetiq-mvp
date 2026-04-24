from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentEnrollRequest(BaseModel):
    tenant_id: str
    enrollment_token: str
    hostname: str


class AgentEnrollResponse(BaseModel):
    agent_id: str
    policy: dict[str, Any]


class AgentPolicyResponse(BaseModel):
    tenant_id: str
    agent_id: str
    policy: dict[str, Any]


class TelemetryAck(BaseModel):
    status: str = "accepted"
    tenant_id: str
    agent_id: str
    telemetry_type: str


class AssetPayload(BaseModel):
    hostname: str | None = None
    fqdn: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    domain: str | None = None
    serial_number: str | None = None
    device_id: str | None = None
    ips: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)


class AssetSnapshotIn(BaseModel):
    tenant_id: str
    agent_id: str
    timestamp: int | None = None
    asset: AssetPayload


class SoftwareItem(BaseModel):
    name: str | None = None
    version: str | None = None
    publisher: str | None = None
    install_date: str | None = None


class SoftwareInventoryIn(BaseModel):
    tenant_id: str
    agent_id: str
    timestamp: int | None = None
    software: list[SoftwareItem] = Field(default_factory=list)


class SecurityPostureIn(BaseModel):
    tenant_id: str
    agent_id: str
    timestamp: int | None = None
    security_posture: dict[str, Any] = Field(default_factory=dict)


class LocalFinding(BaseModel):
    type: str | None = None
    local_ip: str | None = None
    local_port: int | None = None
    pid: int | None = None
    protocol: str | None = None
    status: str | None = None
    secret_type: str | None = None
    file_path: str | None = None
    preview: str | None = None


class LocalFindingsIn(BaseModel):
    tenant_id: str
    agent_id: str
    findings: list[LocalFinding] = Field(default_factory=list)


class HeartbeatIn(BaseModel):
    tenant_id: str
    agent_id: str | None = None
    hostname: str | None = None
    platform: str | None = None
    platform_release: str | None = None
    boot_time: float | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    timestamp: int | None = None
