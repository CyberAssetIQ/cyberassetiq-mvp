"""services/incident_response_service.py

Incident Response Lifecycle business logic.

Implements:
  - Incident creation
  - 7-phase transition validation
  - Immutable incident timeline
  - Asset linking / unlinking
  - Assignment
  - Severity updates
  - Analyst notes
  - Report generation metadata persistence
  - Close / reopen support via phase transitions

Design rules:
  - All queries are tenant-scoped
  - Timeline is append-only
  - Invalid phase transitions are blocked
  - Returns plain dicts, not ORM objects
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.incident_response import (
    Incident,
    IncidentTimeline,
    IncidentAsset,
    IncidentReport,
    INCIDENT_PHASES,
    ALLOWED_TRANSITIONS,
    SEVERITY_LEVELS,
    INCIDENT_SOURCES,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now():
    return datetime.now(timezone.utc)


def _incident_to_dict(i: Incident) -> dict[str, Any]:
    return {
        "id": i.id,
        "tenant_id": i.tenant_id,
        "title": i.title,
        "description": i.description,
        "severity": i.severity,
        "phase": i.phase,
        "phase_entered_at": i.phase_entered_at.isoformat() if i.phase_entered_at else None,
        "source": i.source,
        "source_ref_id": i.source_ref_id,
        "source_ref_type": i.source_ref_type,
        "assigned_to_user_id": i.assigned_to_user_id,
        "assigned_to_name": i.assigned_to_name,
        "assigned_at": i.assigned_at.isoformat() if i.assigned_at else None,
        "ai_investigation_id": i.ai_investigation_id,
        "ai_executive_summary": i.ai_executive_summary,
        "ai_mitre_tactic": i.ai_mitre_tactic,
        "ai_mitre_technique": i.ai_mitre_technique,
        "contain_command_ids": i.contain_command_ids,
        "remediation_action_ids": i.remediation_action_ids,
        "rescan_job_id": i.rescan_job_id,
        "rescan_verified_clean": i.rescan_verified_clean,
        "rescan_completed_at": i.rescan_completed_at.isoformat() if i.rescan_completed_at else None,
        "report_id": i.report_id,
        "estimated_risk_score_impact": i.estimated_risk_score_impact,
        "affected_asset_count": i.affected_asset_count,
        "closed_at": i.closed_at.isoformat() if i.closed_at else None,
        "closed_by": i.closed_by,
        "closure_notes": i.closure_notes,
        "root_cause": i.root_cause,
        "created_by": i.created_by,
        "mitre_tags_json": i.mitre_tags_json,
        "tags_json": i.tags_json,
        "extra_json": i.extra_json,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }


def _timeline_to_dict(t: IncidentTimeline) -> dict[str, Any]:
    return {
        "id": t.id,
        "tenant_id": t.tenant_id,
        "incident_id": t.incident_id,
        "event_type": t.event_type,
        "from_phase": t.from_phase,
        "to_phase": t.to_phase,
        "summary": t.summary,
        "actor": t.actor,
        "actor_user_id": t.actor_user_id,
        "ref_type": t.ref_type,
        "ref_id": t.ref_id,
        "detail_json": t.detail_json,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def _asset_to_dict(a: IncidentAsset) -> dict[str, Any]:
    return {
        "id": a.id,
        "tenant_id": a.tenant_id,
        "incident_id": a.incident_id,
        "asset_id": a.asset_id,
        "asset_role": a.asset_role,
        "is_contained": a.is_contained,
        "contained_at": a.contained_at.isoformat() if a.contained_at else None,
        "contain_command_id": a.contain_command_id,
        "is_clean": a.is_clean,
        "verified_clean_at": a.verified_clean_at.isoformat() if a.verified_clean_at else None,
        "notes": a.notes,
        "added_at": a.added_at.isoformat() if a.added_at else None,
        "added_by": a.added_by,
    }


def _report_to_dict(r: IncidentReport) -> dict[str, Any]:
    return {
        "id": r.id,
        "tenant_id": r.tenant_id,
        "incident_id": r.incident_id,
        "report_type": r.report_type,
        "generated_by": r.generated_by,
        "pdf_path": r.pdf_path,
        "report_json": r.report_json,
        "model_used": r.model_used,
        "prompt_tokens": r.prompt_tokens,
        "completion_tokens": r.completion_tokens,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _get_incident(db: Session, tenant_id: str, incident_id: int) -> Incident:
    incident = (
        db.query(Incident)
        .filter(Incident.tenant_id == tenant_id, Incident.id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


def _append_timeline(
    db: Session,
    *,
    tenant_id: str,
    incident_id: int,
    event_type: str,
    summary: str,
    actor: str = "system",
    actor_user_id: int | None = None,
    from_phase: str | None = None,
    to_phase: str | None = None,
    ref_type: str | None = None,
    ref_id: str | None = None,
    detail_json: dict | None = None,
) -> IncidentTimeline:
    row = IncidentTimeline(
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type=event_type,
        from_phase=from_phase,
        to_phase=to_phase,
        summary=summary,
        actor=actor,
        actor_user_id=actor_user_id,
        ref_type=ref_type,
        ref_id=ref_id,
        detail_json=detail_json,
    )
    db.add(row)
    db.flush()
    return row


# ── Incident CRUD ────────────────────────────────────────────────────────────

def create_incident(
    db: Session,
    tenant_id: str,
    *,
    title: str,
    description: str | None = None,
    severity: str = "high",
    source: str = "manual",
    source_ref_id: int | None = None,
    source_ref_type: str | None = None,
    created_by: str = "system",
    ai_investigation_id: int | None = None,
    ai_executive_summary: str | None = None,
    ai_mitre_tactic: str | None = None,
    ai_mitre_technique: str | None = None,
    mitre_tags_json: list | None = None,
    tags_json: list | None = None,
    extra_json: dict | None = None,
    estimated_risk_score_impact: float = 0.0,
) -> dict[str, Any]:
    if severity not in SEVERITY_LEVELS:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Allowed: {SEVERITY_LEVELS}")
    if source not in INCIDENT_SOURCES:
        raise HTTPException(status_code=400, detail=f"Invalid source. Allowed: {INCIDENT_SOURCES}")

    incident = Incident(
        tenant_id=tenant_id,
        title=title.strip(),
        description=description,
        severity=severity,
        phase="detected",
        phase_entered_at=_now(),
        source=source,
        source_ref_id=source_ref_id,
        source_ref_type=source_ref_type,
        created_by=created_by,
        ai_investigation_id=ai_investigation_id,
        ai_executive_summary=ai_executive_summary,
        ai_mitre_tactic=ai_mitre_tactic,
        ai_mitre_technique=ai_mitre_technique,
        mitre_tags_json=mitre_tags_json,
        tags_json=tags_json,
        extra_json=extra_json,
        estimated_risk_score_impact=estimated_risk_score_impact,
        affected_asset_count=0,
    )
    db.add(incident)
    db.flush()

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident.id,
        event_type="incident_created",
        summary=f"Incident created in detected phase: {incident.title}",
        actor=created_by,
        detail_json={
            "severity": severity,
            "source": source,
            "source_ref_id": source_ref_id,
            "source_ref_type": source_ref_type,
        },
    )

    db.commit()
    db.refresh(incident)
    return _incident_to_dict(incident)


def list_incidents(
    db: Session,
    tenant_id: str,
    *,
    phase: str | None = None,
    severity: str | None = None,
    assigned_to_user_id: int | None = None,
    source: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    q = db.query(Incident).filter(Incident.tenant_id == tenant_id)

    if phase:
        q = q.filter(Incident.phase == phase)
    if severity:
        q = q.filter(Incident.severity == severity)
    if assigned_to_user_id is not None:
        q = q.filter(Incident.assigned_to_user_id == assigned_to_user_id)
    if source:
        q = q.filter(Incident.source == source)

    rows = q.order_by(Incident.created_at.desc()).limit(min(limit, 500)).all()
    return {
        "tenant_id": tenant_id,
        "total": len(rows),
        "incidents": [_incident_to_dict(x) for x in rows],
    }


def get_incident_detail(db: Session, tenant_id: str, incident_id: int) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)

    assets = (
        db.query(IncidentAsset)
        .filter(IncidentAsset.tenant_id == tenant_id, IncidentAsset.incident_id == incident_id)
        .order_by(IncidentAsset.added_at.asc())
        .all()
    )
    timeline = (
        db.query(IncidentTimeline)
        .filter(IncidentTimeline.tenant_id == tenant_id, IncidentTimeline.incident_id == incident_id)
        .order_by(IncidentTimeline.created_at.asc(), IncidentTimeline.id.asc())
        .all()
    )
    reports = (
        db.query(IncidentReport)
        .filter(IncidentReport.tenant_id == tenant_id, IncidentReport.incident_id == incident_id)
        .order_by(IncidentReport.created_at.desc())
        .all()
    )

    return {
        "incident": _incident_to_dict(incident),
        "assets": [_asset_to_dict(x) for x in assets],
        "timeline": [_timeline_to_dict(x) for x in timeline],
        "reports": [_report_to_dict(x) for x in reports],
    }


# ── Phase transitions ────────────────────────────────────────────────────────

def transition_incident_phase(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    to_phase: str,
    actor: str = "system",
    actor_user_id: int | None = None,
    summary: str | None = None,
    closure_notes: str | None = None,
    root_cause: str | None = None,
    force_close: bool = False,
) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)

    if to_phase not in INCIDENT_PHASES:
        raise HTTPException(status_code=400, detail=f"Invalid phase. Allowed: {INCIDENT_PHASES}")

    from_phase = incident.phase
    allowed = ALLOWED_TRANSITIONS.get(from_phase, [])

    if to_phase not in allowed:
        if not (force_close and to_phase == "closed"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid transition from '{from_phase}' to '{to_phase}'. Allowed: {allowed}",
            )

    incident.phase = to_phase
    incident.phase_entered_at = _now()

    if to_phase == "closed":
        incident.closed_at = _now()
        incident.closed_by = actor
        if closure_notes is not None:
            incident.closure_notes = closure_notes
        if root_cause is not None:
            incident.root_cause = root_cause
    else:
        # reopening from closed or continuing lifecycle
        if from_phase == "closed":
            incident.closed_at = None
            incident.closed_by = None

    timeline_summary = summary or f"Phase changed from {from_phase} to {to_phase}."

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="phase_transition",
        from_phase=from_phase,
        to_phase=to_phase,
        summary=timeline_summary,
        actor=actor,
        actor_user_id=actor_user_id,
        detail_json={
            "force_close": force_close,
            "closure_notes": closure_notes,
            "root_cause": root_cause,
        },
    )

    db.commit()
    db.refresh(incident)
    return _incident_to_dict(incident)


# ── Assignment / severity / notes ───────────────────────────────────────────

def assign_incident(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    assigned_to_user_id: int | None,
    assigned_to_name: str | None,
    actor: str = "system",
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)

    old_user_id = incident.assigned_to_user_id
    old_name = incident.assigned_to_name

    incident.assigned_to_user_id = assigned_to_user_id
    incident.assigned_to_name = assigned_to_name
    incident.assigned_at = _now() if assigned_to_user_id or assigned_to_name else None

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="assignment_changed",
        summary=f"Assignment changed from {old_name or 'unassigned'} to {assigned_to_name or 'unassigned'}.",
        actor=actor,
        actor_user_id=actor_user_id,
        detail_json={
            "old_assigned_to_user_id": old_user_id,
            "old_assigned_to_name": old_name,
            "new_assigned_to_user_id": assigned_to_user_id,
            "new_assigned_to_name": assigned_to_name,
        },
    )

    db.commit()
    db.refresh(incident)
    return _incident_to_dict(incident)


def update_incident_severity(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    severity: str,
    actor: str = "system",
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    if severity not in SEVERITY_LEVELS:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Allowed: {SEVERITY_LEVELS}")

    incident = _get_incident(db, tenant_id, incident_id)
    old = incident.severity
    incident.severity = severity

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="severity_changed",
        summary=f"Severity changed from {old} to {severity}.",
        actor=actor,
        actor_user_id=actor_user_id,
        detail_json={"from": old, "to": severity},
    )

    db.commit()
    db.refresh(incident)
    return _incident_to_dict(incident)


def add_analyst_note(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    note: str,
    actor: str = "system",
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    _get_incident(db, tenant_id, incident_id)

    row = _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="analyst_note",
        summary=note.strip(),
        actor=actor,
        actor_user_id=actor_user_id,
    )
    db.commit()
    db.refresh(row)
    return _timeline_to_dict(row)


# ── Assets ───────────────────────────────────────────────────────────────────

def link_asset_to_incident(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    asset_id: int,
    asset_role: str = "affected",
    notes: str | None = None,
    added_by: str = "system",
) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)

    existing = (
        db.query(IncidentAsset)
        .filter(
            IncidentAsset.tenant_id == tenant_id,
            IncidentAsset.incident_id == incident_id,
            IncidentAsset.asset_id == asset_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Asset already linked to this incident.")

    row = IncidentAsset(
        tenant_id=tenant_id,
        incident_id=incident_id,
        asset_id=asset_id,
        asset_role=asset_role,
        notes=notes,
        added_by=added_by,
    )
    db.add(row)
    db.flush()

    incident.affected_asset_count = (
        db.query(IncidentAsset)
        .filter(IncidentAsset.tenant_id == tenant_id, IncidentAsset.incident_id == incident_id)
        .count()
    )

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="asset_linked",
        summary=f"Asset {asset_id} linked to incident as {asset_role}.",
        actor=added_by,
        ref_type="asset",
        ref_id=str(asset_id),
        detail_json={"asset_role": asset_role, "notes": notes},
    )

    db.commit()
    db.refresh(row)
    db.refresh(incident)
    return {
        "asset": _asset_to_dict(row),
        "affected_asset_count": incident.affected_asset_count,
    }


def unlink_asset_from_incident(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    asset_id: int,
    actor: str = "system",
) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)

    row = (
        db.query(IncidentAsset)
        .filter(
            IncidentAsset.tenant_id == tenant_id,
            IncidentAsset.incident_id == incident_id,
            IncidentAsset.asset_id == asset_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Linked asset not found.")

    db.delete(row)
    db.flush()

    incident.affected_asset_count = (
        db.query(IncidentAsset)
        .filter(IncidentAsset.tenant_id == tenant_id, IncidentAsset.incident_id == incident_id)
        .count()
    )

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="asset_unlinked",
        summary=f"Asset {asset_id} unlinked from incident.",
        actor=actor,
        ref_type="asset",
        ref_id=str(asset_id),
    )

    db.commit()
    db.refresh(incident)
    return {
        "message": f"Asset {asset_id} unlinked.",
        "affected_asset_count": incident.affected_asset_count,
    }


def mark_asset_contained(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    asset_id: int,
    contain_command_id: str | None = None,
    actor: str = "system",
) -> dict[str, Any]:
    row = (
        db.query(IncidentAsset)
        .filter(
            IncidentAsset.tenant_id == tenant_id,
            IncidentAsset.incident_id == incident_id,
            IncidentAsset.asset_id == asset_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Linked asset not found.")

    row.is_contained = True
    row.contained_at = _now()
    row.contain_command_id = contain_command_id

    incident = _get_incident(db, tenant_id, incident_id)
    command_ids = incident.contain_command_ids or []
    if contain_command_id and contain_command_id not in command_ids:
        command_ids.append(contain_command_id)
        incident.contain_command_ids = command_ids

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="containment_command",
        summary=f"Containment recorded for asset {asset_id}.",
        actor=actor,
        ref_type="command",
        ref_id=contain_command_id,
        detail_json={"asset_id": asset_id},
    )

    db.commit()
    db.refresh(row)
    db.refresh(incident)
    return _asset_to_dict(row)


def mark_asset_clean(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    asset_id: int,
    is_clean: bool,
    actor: str = "system",
) -> dict[str, Any]:
    row = (
        db.query(IncidentAsset)
        .filter(
            IncidentAsset.tenant_id == tenant_id,
            IncidentAsset.incident_id == incident_id,
            IncidentAsset.asset_id == asset_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Linked asset not found.")

    row.is_clean = is_clean
    row.verified_clean_at = _now() if is_clean else None

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="rescan_completed",
        summary=f"Clean-state verification updated for asset {asset_id}: is_clean={is_clean}.",
        actor=actor,
        detail_json={"asset_id": asset_id, "is_clean": is_clean},
    )

    db.commit()
    db.refresh(row)
    return _asset_to_dict(row)


# ── Recovery / reports ───────────────────────────────────────────────────────

def record_rescan_result(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    rescan_job_id: str,
    verified_clean: bool,
    actor: str = "system",
) -> dict[str, Any]:
    incident = _get_incident(db, tenant_id, incident_id)
    incident.rescan_job_id = rescan_job_id
    incident.rescan_verified_clean = verified_clean
    incident.rescan_completed_at = _now()

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="rescan_completed",
        summary=f"Rescan completed for job {rescan_job_id}. verified_clean={verified_clean}.",
        actor=actor,
        ref_type="rescan_job",
        ref_id=rescan_job_id,
        detail_json={"verified_clean": verified_clean},
    )

    db.commit()
    db.refresh(incident)
    return _incident_to_dict(incident)


def create_incident_report(
    db: Session,
    tenant_id: str,
    incident_id: int,
    *,
    report_type: str = "full",
    generated_by: str = "system",
    pdf_path: str | None = None,
    report_json: dict | None = None,
    model_used: str | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> dict[str, Any]:
    if report_type not in ("full", "executive", "technical"):
        raise HTTPException(status_code=400, detail="Invalid report_type.")

    incident = _get_incident(db, tenant_id, incident_id)

    report = IncidentReport(
        tenant_id=tenant_id,
        incident_id=incident_id,
        report_type=report_type,
        generated_by=generated_by,
        pdf_path=pdf_path,
        report_json=report_json,
        model_used=model_used,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
    db.add(report)
    db.flush()

    incident.report_id = report.id

    _append_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="report_generated",
        summary=f"{report_type.capitalize()} incident report generated.",
        actor=generated_by,
        ref_type="report",
        ref_id=str(report.id),
        detail_json={"pdf_path": pdf_path, "model_used": model_used},
    )

    db.commit()
    db.refresh(report)
    db.refresh(incident)
    return _report_to_dict(report)