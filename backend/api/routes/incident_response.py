"""api/routes/incident_response.py

Incident Response Lifecycle endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.incident_response_service import (
    create_incident,
    list_incidents,
    get_incident_detail,
    transition_incident_phase,
    assign_incident,
    update_incident_severity,
    add_analyst_note,
    link_asset_to_incident,
    unlink_asset_from_incident,
    mark_asset_contained,
    mark_asset_clean,
    record_rescan_result,
    create_incident_report,
)

router = APIRouter(prefix="/api/incidents", tags=["incident-response"])


class CreateIncidentRequest(BaseModel):
    title: str
    description: str | None = None
    severity: str = "high"
    source: str = "manual"
    source_ref_id: int | None = None
    source_ref_type: str | None = None
    ai_investigation_id: int | None = None
    ai_executive_summary: str | None = None
    ai_mitre_tactic: str | None = None
    ai_mitre_technique: str | None = None
    mitre_tags_json: list | None = None
    tags_json: list | None = None
    extra_json: dict | None = None
    estimated_risk_score_impact: float = 0.0


class TransitionPhaseRequest(BaseModel):
    to_phase: str
    summary: str | None = None
    closure_notes: str | None = None
    root_cause: str | None = None
    force_close: bool = False


class AssignIncidentRequest(BaseModel):
    assigned_to_user_id: int | None = None
    assigned_to_name: str | None = None


class UpdateSeverityRequest(BaseModel):
    severity: str


class AnalystNoteRequest(BaseModel):
    note: str


class LinkAssetRequest(BaseModel):
    asset_id: int
    asset_role: str = "affected"
    notes: str | None = None


class UnlinkAssetRequest(BaseModel):
    asset_id: int


class ContainAssetRequest(BaseModel):
    asset_id: int
    contain_command_id: str | None = None


class MarkAssetCleanRequest(BaseModel):
    asset_id: int
    is_clean: bool


class RescanResultRequest(BaseModel):
    rescan_job_id: str
    verified_clean: bool


class CreateReportRequest(BaseModel):
    report_type: str = "full"
    pdf_path: str | None = None
    report_json: dict | None = None
    model_used: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@router.post("", status_code=201)
def create_incident_route(
    payload: CreateIncidentRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return create_incident(
        db,
        auth.tenant_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        source=payload.source,
        source_ref_id=payload.source_ref_id,
        source_ref_type=payload.source_ref_type,
        created_by="system",
        ai_investigation_id=payload.ai_investigation_id,
        ai_executive_summary=payload.ai_executive_summary,
        ai_mitre_tactic=payload.ai_mitre_tactic,
        ai_mitre_technique=payload.ai_mitre_technique,
        mitre_tags_json=payload.mitre_tags_json,
        tags_json=payload.tags_json,
        extra_json=payload.extra_json,
        estimated_risk_score_impact=payload.estimated_risk_score_impact,
    )


@router.get("")
def list_incidents_route(
    phase: str | None = None,
    severity: str | None = None,
    assigned_to_user_id: int | None = None,
    source: str | None = None,
    limit: int = 100,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    return list_incidents(
        db,
        auth.tenant_id,
        phase=phase,
        severity=severity,
        assigned_to_user_id=assigned_to_user_id,
        source=source,
        limit=limit,
    )


@router.get("/{incident_id}")
def get_incident_route(
    incident_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    return get_incident_detail(db, auth.tenant_id, incident_id)


@router.post("/{incident_id}/transition")
def transition_phase_route(
    incident_id: int,
    payload: TransitionPhaseRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return transition_incident_phase(
        db,
        auth.tenant_id,
        incident_id,
        to_phase=payload.to_phase,
        actor="system",
        summary=payload.summary,
        closure_notes=payload.closure_notes,
        root_cause=payload.root_cause,
        force_close=payload.force_close,
    )


@router.post("/{incident_id}/assign")
def assign_incident_route(
    incident_id: int,
    payload: AssignIncidentRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return assign_incident(
        db,
        auth.tenant_id,
        incident_id,
        assigned_to_user_id=payload.assigned_to_user_id,
        assigned_to_name=payload.assigned_to_name,
        actor="system",
    )


@router.post("/{incident_id}/severity")
def update_severity_route(
    incident_id: int,
    payload: UpdateSeverityRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return update_incident_severity(
        db,
        auth.tenant_id,
        incident_id,
        severity=payload.severity,
        actor="system",
    )


@router.post("/{incident_id}/notes")
def add_note_route(
    incident_id: int,
    payload: AnalystNoteRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return add_analyst_note(
        db,
        auth.tenant_id,
        incident_id,
        note=payload.note,
        actor="system",
    )


@router.post("/{incident_id}/assets")
def link_asset_route(
    incident_id: int,
    payload: LinkAssetRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return link_asset_to_incident(
        db,
        auth.tenant_id,
        incident_id,
        asset_id=payload.asset_id,
        asset_role=payload.asset_role,
        notes=payload.notes,
        added_by="system",
    )


@router.delete("/{incident_id}/assets")
def unlink_asset_route(
    incident_id: int,
    payload: UnlinkAssetRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return unlink_asset_from_incident(
        db,
        auth.tenant_id,
        incident_id,
        asset_id=payload.asset_id,
        actor="system",
    )


@router.post("/{incident_id}/assets/contain")
def mark_asset_contained_route(
    incident_id: int,
    payload: ContainAssetRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return mark_asset_contained(
        db,
        auth.tenant_id,
        incident_id,
        asset_id=payload.asset_id,
        contain_command_id=payload.contain_command_id,
        actor="system",
    )


@router.post("/{incident_id}/assets/clean")
def mark_asset_clean_route(
    incident_id: int,
    payload: MarkAssetCleanRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return mark_asset_clean(
        db,
        auth.tenant_id,
        incident_id,
        asset_id=payload.asset_id,
        is_clean=payload.is_clean,
        actor="system",
    )


@router.post("/{incident_id}/rescan-result")
def record_rescan_result_route(
    incident_id: int,
    payload: RescanResultRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return record_rescan_result(
        db,
        auth.tenant_id,
        incident_id,
        rescan_job_id=payload.rescan_job_id,
        verified_clean=payload.verified_clean,
        actor="system",
    )


@router.post("/{incident_id}/reports", status_code=201)
def create_report_route(
    incident_id: int,
    payload: CreateReportRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    return create_incident_report(
        db,
        auth.tenant_id,
        incident_id,
        report_type=payload.report_type,
        generated_by="system",
        pdf_path=payload.pdf_path,
        report_json=payload.report_json,
        model_used=payload.model_used,
        prompt_tokens=payload.prompt_tokens,
        completion_tokens=payload.completion_tokens,
    )