from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class ControlResultOut(BaseModel):
    control_id: str
    control_name: str
    status: str
    score: float
    findings: list[str]
    evidence: dict[str, Any]
    remediation: list[str]


class AssetComplianceOut(BaseModel):
    tenant_id: str
    agent_id: str
    hostname: str | None
    assessed_at_epoch: int
    overall_score: float
    overall_status: str
    controls: list[ControlResultOut]
    summary: dict[str, Any]


class TenantComplianceOut(BaseModel):
    tenant_id: str
    assessed_at_epoch: int
    assets_assessed: int
    agent_assets_assessed: int = 0
    network_assets_assessed: int = 0
    assets_passing: int
    assets_partial: int
    assets_failing: int
    ce_ready: bool
    tenant_overall_score: float
    assets: list[dict[str, Any]]


class VulnScanResultOut(BaseModel):
    tenant_id: str
    packages_scanned: int
    total_packages_in_inventory: int
    total_cves_found: int
    critical: int
    high: int
    medium: int
    scan_epoch: int


class VulnSummaryOut(BaseModel):
    tenant_id: str
    total_open_cves: int
    critical: int
    high: int
    medium: int
    low: int
    affected_assets: int


class VulnFindingOut(BaseModel):
    id: int
    agent_id: str
    software_name: str
    software_version: str | None
    cve_id: str
    severity: str
    cvss_score: float | None
    description: str | None
    published: str | None
    status: str
    scan_epoch: int | None = None
    resolved_epoch: int | None = None
    resolution_note: str | None = None

    class Config:
        from_attributes = True
