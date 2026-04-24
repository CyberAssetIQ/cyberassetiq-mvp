from __future__ import annotations
from pydantic import BaseModel

class ExtensionServiceRequest(BaseModel):
    tenant_id: str
    target: str | None = None
    requested_by: str | None = None
    job_type: str

class ExtensionServiceResponse(BaseModel):
    job_id: int
    tenant_id: str
    status: str
    target: str | None = None
    job_type: str
    service_name: str

class ExtensionJobListItem(BaseModel):
    job_id: int
    target: str | None = None
    status: str
    job_type: str
    service_name: str
    progress_percent: int = 0
    current_stage: str | None = None
    current_target: str | None = None
    findings_count: int = 0
