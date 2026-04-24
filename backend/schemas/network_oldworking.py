from __future__ import annotations

from pydantic import BaseModel


class NetworkScanRequest(BaseModel):
    tenant_id: str
    target: str
    requested_by: str | None = None


class NetworkScanResponse(BaseModel):
    job_id: int
    tenant_id: str
    status: str
    target: str
    engine: str | None = None
    discovered_count: int = 0
