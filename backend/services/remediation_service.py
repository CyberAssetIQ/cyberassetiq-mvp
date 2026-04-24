"""remediation_service.py

Remediation Automation Expansion (Phase 3).

Reads from:  canonical_assets, asset_drift_events, vulnerability_findings,
             exposure_findings, risk_recommendations, crown_jewel_assets,
             attack_paths, backup_risk_findings.
Writes to:   remediation_actions, remediation_playbooks, remediation_runs,
             remediation_approvals  (all new — no existing tables modified).

Safety classification rules
    informational   → recommendation only, no system action
    auto_safe       → executed immediately without approval
    approval_required → queued until a human approves via POST /api/remediation/approve
    manual_only     → system produces instructions but takes no action itself
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.drift import AssetDriftEvent
from models.remediation import (
    RemediationAction,
    RemediationApproval,
    RemediationPlaybook,
    RemediationRun,
)
from models.risk_engine import RiskRecommendation

logger = logging.getLogger("cyberassetiq.remediation")

# ---------------------------------------------------------------------------
# Safety classification lookup — action_type → (safety_level, description)
# ---------------------------------------------------------------------------
_ACTION_SAFETY: dict[str, tuple[str, str]] = {
    # Informational
    "create_investigation":     ("informational",    "Creates an AI investigation record for review"),
    "send_webhook":             ("informational",    "Sends a Slack/Teams notification"),
    "trigger_rescan":           ("auto_safe",        "Queues a fresh vulnerability/asset rescan"),
    # Auto-safe
    "enable_firewall_rule":     ("auto_safe",        "Enables a specific firewall rule via agent"),
    "enable_av":                ("auto_safe",        "Restarts AV service via agent command"),
    # Approval required
    "disable_rdp":              ("approval_required", "Disables RDP access on the target host"),
    "disable_smbv1":            ("approval_required", "Disables SMBv1 protocol on the target host"),
    "remove_local_admin":       ("approval_required", "Removes a local admin account"),
    "rotate_secret":            ("approval_required", "Rotates or revokes an exposed credential"),
    "uninstall_software":       ("approval_required", "Removes rogue/unapproved software"),
    "stop_service":             ("approval_required", "Stops a specific service on the host"),
    "patch_now":                ("approval_required", "Triggers immediate patching via patch agent"),
    # Manual only
    "isolate_host":             ("manual_only",      "Network isolation — requires manual firewall change"),
    "revoke_cloud_identity":    ("manual_only",      "Revoke cloud identity — requires portal action"),
    "physical_inspection":      ("manual_only",      "Asset requires physical review"),
}

# ---------------------------------------------------------------------------
# Default playbooks seeded on first run
# ---------------------------------------------------------------------------
_DEFAULT_PLAYBOOKS = [
    {
        "playbook_name": "New Local Admin Alert",
        "trigger_type": "drift_new_admin",
        "description": "Triggered when a new local administrator account is detected on an asset.",
        "approval_required": True,
        "steps": [
            {"action_type": "create_investigation", "safety_level": "informational",
             "parameters": {"title": "New local admin detected — review required"}},
            {"action_type": "send_webhook", "safety_level": "informational",
             "parameters": {"message": "New local admin detected on {{asset_hostname}}"}},
            {"action_type": "trigger_rescan", "safety_level": "auto_safe", "parameters": {}},
        ],
    },
    {
        "playbook_name": "New Exposed Port Response",
        "trigger_type": "drift_new_port",
        "description": "Triggered when a new high-risk port is opened on a managed asset.",
        "approval_required": True,
        "steps": [
            {"action_type": "create_investigation", "safety_level": "informational",
             "parameters": {"title": "New exposed port detected — review required"}},
            {"action_type": "send_webhook", "safety_level": "informational",
             "parameters": {"message": "New exposed port on {{asset_hostname}}: {{port}}"}},
            {"action_type": "trigger_rescan", "safety_level": "auto_safe", "parameters": {}},
        ],
    },
    {
        "playbook_name": "Credential Leak Response",
        "trigger_type": "credential_leak",
        "description": "Triggered when a credential or API key leak is confirmed.",
        "approval_required": True,
        "steps": [
            {"action_type": "create_investigation", "safety_level": "informational",
             "parameters": {"title": "Confirmed credential leak — rotation required"}},
            {"action_type": "send_webhook", "safety_level": "informational",
             "parameters": {"message": "Credential leak confirmed for {{entity}}"}},
            {"action_type": "rotate_secret", "safety_level": "approval_required",
             "parameters": {"requires_human_approval": True}},
        ],
    },
    {
        "playbook_name": "Ransomware Indicator Response",
        "trigger_type": "ransomware_indicator",
        "description": "Triggered when blast radius analysis detects a ransomware-propagation-capable path.",
        "approval_required": True,
        "steps": [
            {"action_type": "create_investigation", "safety_level": "informational",
             "parameters": {"title": "Ransomware propagation path detected"}},
            {"action_type": "send_webhook", "safety_level": "informational",
             "parameters": {"message": "Ransomware path detected from {{source_asset}}"}},
            {"action_type": "disable_smbv1", "safety_level": "approval_required", "parameters": {}},
            {"action_type": "disable_rdp", "safety_level": "approval_required", "parameters": {}},
        ],
    },
    {
        "playbook_name": "Rogue Software Response",
        "trigger_type": "shadow_it_software",
        "description": "Triggered when blacklisted or high-risk unapproved software is detected.",
        "approval_required": True,
        "steps": [
            {"action_type": "create_investigation", "safety_level": "informational",
             "parameters": {"title": "High-risk unapproved software detected"}},
            {"action_type": "uninstall_software", "safety_level": "approval_required",
             "parameters": {"requires_human_approval": True}},
        ],
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_remediation_summary(db: Session, tenant_id: str) -> dict:
    total = db.query(RemediationAction).filter(
        RemediationAction.tenant_id == tenant_id
    ).count()
    pending = db.query(RemediationAction).filter(
        RemediationAction.tenant_id == tenant_id,
        RemediationAction.status == "pending",
    ).count()
    awaiting_approval = db.query(RemediationApproval).filter(
        RemediationApproval.tenant_id == tenant_id,
        RemediationApproval.approval_status == "pending",
    ).count()
    completed = db.query(RemediationAction).filter(
        RemediationAction.tenant_id == tenant_id,
        RemediationAction.status == "completed",
    ).count()
    failed = db.query(RemediationAction).filter(
        RemediationAction.tenant_id == tenant_id,
        RemediationAction.status == "failed",
    ).count()
    playbook_count = db.query(RemediationPlaybook).filter(
        RemediationPlaybook.tenant_id == tenant_id,
        RemediationPlaybook.enabled == True,
    ).count()
    return {
        "total_actions": total,
        "pending": pending,
        "awaiting_approval": awaiting_approval,
        "completed": completed,
        "failed": failed,
        "enabled_playbooks": playbook_count,
    }


def list_actions(db: Session, tenant_id: str, status: str | None = None,
                 limit: int = 50) -> list[dict]:
    q = db.query(RemediationAction).filter(RemediationAction.tenant_id == tenant_id)
    if status:
        q = q.filter(RemediationAction.status == status)
    actions = q.order_by(RemediationAction.created_at.desc()).limit(limit).all()
    return [_action_to_dict(a) for a in actions]


def create_action(db: Session, tenant_id: str, action_type: str,
                  asset_id: int | None = None, parameters: dict | None = None,
                  created_by: str = "system", source: str = "manual",
                  trigger_finding_type: str | None = None,
                  trigger_severity: str | None = None,
                  expected_score_gain: float = 0.0) -> dict:
    safety_level, description = _ACTION_SAFETY.get(
        action_type, ("informational", "Custom action")
    )
    action = RemediationAction(
        tenant_id=tenant_id,
        asset_id=asset_id,
        action_type=action_type,
        parameters_json=parameters or {},
        safety_level=safety_level,
        source=source,
        created_by=created_by,
        trigger_finding_type=trigger_finding_type,
        trigger_severity=trigger_severity,
        expected_score_gain=expected_score_gain,
        status="pending",
        result_summary=description,
    )
    db.add(action)
    db.flush()

    # Auto-safe actions are immediately marked for execution
    if safety_level == "auto_safe":
        action.status = "approved"

    # Approval-required actions need an approval record
    if safety_level == "approval_required":
        approval = RemediationApproval(
            tenant_id=tenant_id,
            action_id=action.id,
            requested_by=created_by,
            approval_status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.add(approval)

    db.commit()
    logger.info(
        "Remediation action created: tenant=%s type=%s safety=%s asset=%s",
        tenant_id, action_type, safety_level, asset_id,
    )
    return _action_to_dict(action)


def approve_action(db: Session, tenant_id: str, action_id: int,
                   approved_by: str = "admin", notes: str | None = None,
                   decision: str = "approved") -> dict:
    """Approve or reject a pending remediation action."""
    approval = db.query(RemediationApproval).filter(
        RemediationApproval.tenant_id == tenant_id,
        RemediationApproval.action_id == action_id,
        RemediationApproval.approval_status == "pending",
    ).first()
    if not approval:
        return {"error": "No pending approval found for this action"}

    approval.approved_by = approved_by
    approval.approval_status = decision  # approved | rejected
    approval.notes = notes
    approval.approved_at = datetime.now(timezone.utc)

    action = db.query(RemediationAction).filter(
        RemediationAction.id == action_id,
        RemediationAction.tenant_id == tenant_id,
    ).first()
    if action:
        action.status = decision  # approved | rejected

    db.commit()
    return {"action_id": action_id, "decision": decision, "approved_by": approved_by}


def list_playbooks(db: Session, tenant_id: str) -> list[dict]:
    playbooks = db.query(RemediationPlaybook).filter(
        RemediationPlaybook.tenant_id == tenant_id
    ).order_by(RemediationPlaybook.id).all()
    return [_playbook_to_dict(p) for p in playbooks]


def seed_default_playbooks(db: Session, tenant_id: str) -> int:
    """Seeds the default playbooks for a tenant if none exist yet."""
    existing = db.query(RemediationPlaybook).filter(
        RemediationPlaybook.tenant_id == tenant_id
    ).count()
    if existing > 0:
        return 0

    seeded = 0
    for spec in _DEFAULT_PLAYBOOKS:
        pb = RemediationPlaybook(
            tenant_id=tenant_id,
            playbook_name=spec["playbook_name"],
            trigger_type=spec["trigger_type"],
            description=spec.get("description"),
            approval_required=spec.get("approval_required", True),
            steps_json=spec["steps"],
            enabled=True,
        )
        db.add(pb)
        seeded += 1
    db.commit()
    logger.info("Seeded %d default playbooks for tenant %s", seeded, tenant_id)
    return seeded


def list_runs(db: Session, tenant_id: str, limit: int = 30) -> list[dict]:
    runs = db.query(RemediationRun).filter(
        RemediationRun.tenant_id == tenant_id
    ).order_by(RemediationRun.started_at.desc()).limit(limit).all()
    return [_run_to_dict(r) for r in runs]


def generate_ai_recommendations(db: Session, tenant_id: str) -> list[dict]:
    """Pull top risk recommendations and convert them to remediation actions."""
    recs = db.query(RiskRecommendation).filter(
        RiskRecommendation.tenant_id == tenant_id,
        RiskRecommendation.status == "open",
    ).order_by(
        RiskRecommendation.priority_rank.asc()
    ).limit(10).all()

    created = []
    for rec in recs:
        # Map recommendation type to closest action type
        action_type = _recommendation_to_action(rec.recommendation_type)
        if action_type:
            action = create_action(
                db, tenant_id, action_type,
                asset_id=rec.asset_id,
                source="risk_engine",
                trigger_finding_type=rec.recommendation_type,
                expected_score_gain=rec.expected_score_gain or 0.0,
            )
            created.append(action)
    return created


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _recommendation_to_action(rec_type: str) -> str | None:
    mapping = {
        "patch_critical_cve": "patch_now",
        "disable_exposed_rdp": "disable_rdp",
        "disable_smbv1": "disable_smbv1",
        "remove_unauthorised_admin": "remove_local_admin",
        "rotate_leaked_credential": "rotate_secret",
        "remove_rogue_software": "uninstall_software",
        "isolate_compromised_host": "isolate_host",
        "rescan_asset": "trigger_rescan",
    }
    return mapping.get(rec_type)


def _action_to_dict(a: RemediationAction) -> dict:
    return {
        "id": a.id,
        "action_type": a.action_type,
        "asset_id": a.asset_id,
        "safety_level": a.safety_level,
        "status": a.status,
        "source": a.source,
        "created_by": a.created_by,
        "result_summary": a.result_summary,
        "expected_score_gain": a.expected_score_gain,
        "trigger_finding_type": a.trigger_finding_type,
        "trigger_severity": a.trigger_severity,
        "parameters_json": a.parameters_json,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


def _playbook_to_dict(p: RemediationPlaybook) -> dict:
    return {
        "id": p.id,
        "playbook_name": p.playbook_name,
        "trigger_type": p.trigger_type,
        "description": p.description,
        "approval_required": p.approval_required,
        "enabled": p.enabled,
        "run_count": p.run_count,
        "steps": p.steps_json or [],
        "last_triggered_at": p.last_triggered_at.isoformat() if p.last_triggered_at else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _run_to_dict(r: RemediationRun) -> dict:
    return {
        "id": r.id,
        "playbook_id": r.playbook_id,
        "action_id": r.action_id,
        "asset_id": r.asset_id,
        "result_status": r.result_status,
        "triggered_by": r.triggered_by,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "ended_at": r.ended_at.isoformat() if r.ended_at else None,
        "duration_seconds": r.duration_seconds,
        "execution_log": r.execution_log_json or [],
    }
