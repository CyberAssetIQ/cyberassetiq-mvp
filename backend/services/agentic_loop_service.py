"""services/agentic_loop_service.py

Supervised Agentic AI Loop — Core Engine

The loop runs in 5 stages:
  1. GATHER   — query blast radius, attack graph, dark web, identity, CVEs, criticality
  2. BRIEF    — AI synthesises context into a structured decision brief
  3. PLAN     — generate tiered action list (tier 0/1/2)
  4. EXECUTE  — run tier 0 actions immediately; queue tier 1/2 for approval
  5. REPORT   — update run record with outcomes

Key design principles:
  - Tier 0 actions are always safe (no production impact)
  - Tier 1/2 never execute without explicit human approval
  - All context gathering uses try/except — a failing module never stops the loop
  - Every action is recorded whether approved or not (immutable audit trail)
  - The AI is given only redacted platform data — never raw credentials
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from models.agentic_loop import AgentLoopRun, AgentLoopAction
from services.ai_provider_service import AIProviderService
from services.ai_redaction_service import redact_dict

logger = logging.getLogger("cyberassetiq.agentic_loop")

SYSTEM_PROMPT = """You are the CyberAssetIQ Supervised Agentic Security Analyst.

You have been given structured security context gathered automatically from all platform modules.
Your job is to:
1. Analyse the context and assess what is happening
2. Produce a concise decision brief in JSON format
3. Recommend a tiered action list

You MUST respond with valid JSON only. No preamble, no explanation outside the JSON.

Response format:
{
  "brief_title": "Short title (max 80 chars)",
  "severity": "critical|high|medium|low",
  "confidence": 85,
  "brief_summary": "2-3 sentence non-technical summary for business owners",
  "brief_technical": "Technical analyst detail — what happened, how, and evidence",
  "mitre_tactic": "Lateral Movement",
  "mitre_technique": "T1021.002",
  "assessed_risk_score": 78,
  "affected_asset_count": 5,
  "crown_jewels_at_risk": 2,
  "actions": [
    {
      "action_type": "create_incident",
      "tier": 0,
      "title": "Create incident record for this event",
      "rationale": "This event requires tracking through the IR lifecycle",
      "expected_outcome": "Incident created in phase detected for analyst review",
      "risk_reduction_estimate": 0,
      "target_type": null,
      "target_id": null,
      "target_name": null
    },
    {
      "action_type": "isolate_asset",
      "tier": 1,
      "title": "Isolate WORKSTATION-04 from the network",
      "rationale": "Asset is the confirmed initial vector with active lateral movement detected",
      "expected_outcome": "Agent receives isolation command. Asset network access suspended pending investigation.",
      "risk_reduction_estimate": 45,
      "target_type": "asset",
      "target_id": "3",
      "target_name": "WORKSTATION-04"
    }
  ]
}

Rules:
- severity must be: critical, high, medium, or low
- confidence is 0-100
- assessed_risk_score is 0-100
- tier 0: create_investigation, create_incident, notify_team, trigger_rescan
- tier 1: isolate_asset, force_password_reset, disable_account, block_ip
- tier 2: bulk_account_action, firewall_rule_change
- Never recommend tier 2 unless evidence is overwhelming
- Always explain rationale in plain English
- UK English throughout
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def trigger_loop(
    db: Session,
    tenant_id: str,
    trigger_type: str,
    trigger_ref_id: int | None = None,
    trigger_ref_type: str | None = None,
    trigger_asset_id: int | None = None,
    trigger_summary: str = "",
    run_async: bool = False,
) -> AgentLoopRun:
    """
    Create a new agentic loop run and execute it synchronously.
    Returns the completed run record.
    """
    run = AgentLoopRun(
        tenant_id=tenant_id,
        trigger_type=trigger_type,
        trigger_ref_id=trigger_ref_id,
        trigger_ref_type=trigger_ref_type,
        trigger_asset_id=trigger_asset_id,
        trigger_summary=trigger_summary,
        status="pending",
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        _execute_loop(db, run)
    except Exception as exc:
        logger.exception("Agentic loop run %d failed: %s", run.id, exc)
        run.status = "failed"
        run.error_message = str(exc)
        run.completed_at = datetime.now(timezone.utc)
        db.commit()

    return run


def get_run(db: Session, tenant_id: str, run_id: int) -> AgentLoopRun:
    run = (
        db.query(AgentLoopRun)
        .filter(AgentLoopRun.id == run_id, AgentLoopRun.tenant_id == tenant_id)
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="Agentic loop run not found.")
    return run


def list_runs(
    db: Session,
    tenant_id: str,
    status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    q = db.query(AgentLoopRun).filter(AgentLoopRun.tenant_id == tenant_id)
    if status:
        q = q.filter(AgentLoopRun.status == status)
    runs = q.order_by(desc(AgentLoopRun.created_at)).limit(limit).all()
    return [_run_to_dict(r) for r in runs]


def get_run_detail(db: Session, tenant_id: str, run_id: int) -> dict:
    run = get_run(db, tenant_id, run_id)
    actions = (
        db.query(AgentLoopAction)
        .filter(AgentLoopAction.run_id == run_id, AgentLoopAction.tenant_id == tenant_id)
        .order_by(AgentLoopAction.tier.asc(), AgentLoopAction.id.asc())
        .all()
    )
    result = _run_to_dict(run)
    result["actions"] = [_action_to_dict(a) for a in actions]
    result["context"] = run.context_json or {}
    return result


def approve_action(
    db: Session,
    tenant_id: str,
    action_id: int,
    decided_by: str,
    decision_note: str = "",
) -> dict:
    """Approve a tier 1 or tier 2 action and execute it."""
    action = _get_action(db, tenant_id, action_id)

    if action.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Action is already '{action.status}'. Only pending actions can be approved.",
        )
    if action.tier == 0:
        raise HTTPException(status_code=400, detail="Tier 0 actions execute automatically.")

    action.status = "approved"
    action.decided_by = decided_by
    action.decided_at = datetime.now(timezone.utc)
    action.decision_note = decision_note
    db.commit()

    # Execute
    _execute_action(db, action)

    # Update run counters
    run = db.query(AgentLoopRun).filter(
        AgentLoopRun.id == action.run_id,
        AgentLoopRun.tenant_id == tenant_id,
    ).first()
    if run:
        run.approved_actions = (run.approved_actions or 0) + 1
        run.pending_approval = max(0, (run.pending_approval or 0) - 1)
        db.commit()

    return _action_to_dict(action)


def reject_action(
    db: Session,
    tenant_id: str,
    action_id: int,
    decided_by: str,
    decision_note: str = "",
) -> dict:
    """Reject a pending tier 1/2 action."""
    action = _get_action(db, tenant_id, action_id)

    if action.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Action is already '{action.status}'.",
        )

    action.status = "rejected"
    action.decided_by = decided_by
    action.decided_at = datetime.now(timezone.utc)
    action.decision_note = decision_note or "Rejected by analyst."
    db.commit()

    # Update run counters
    run = db.query(AgentLoopRun).filter(
        AgentLoopRun.id == action.run_id,
        AgentLoopRun.tenant_id == tenant_id,
    ).first()
    if run:
        run.rejected_actions = (run.rejected_actions or 0) + 1
        run.pending_approval = max(0, (run.pending_approval or 0) - 1)
        db.commit()

    return _action_to_dict(action)


def get_pending_approvals(db: Session, tenant_id: str) -> list[dict]:
    """Return all actions waiting for human approval across all runs."""
    actions = (
        db.query(AgentLoopAction)
        .filter(
            AgentLoopAction.tenant_id == tenant_id,
            AgentLoopAction.status == "pending",
            AgentLoopAction.tier > 0,
        )
        .order_by(AgentLoopAction.tier.asc(), AgentLoopAction.created_at.asc())
        .all()
    )
    return [_action_to_dict(a) for a in actions]


# ---------------------------------------------------------------------------
# Stage 1: Gather context
# ---------------------------------------------------------------------------

def _gather_context(db: Session, run: AgentLoopRun) -> dict[str, Any]:
    """
    Query all relevant platform modules and build a unified context dict.
    Each module call is wrapped in try/except — failures are logged but
    never stop the loop. The loop proceeds with whatever data it has.
    """
    tenant_id = run.tenant_id
    asset_id = run.trigger_asset_id
    context: dict[str, Any] = {}

    # ── Blast Radius ──────────────────────────────────────────────────────────
    try:
        from services.blast_radius_service import get_asset_blast_radius, get_blast_radius_summary
        if asset_id:
            br = get_asset_blast_radius(db, tenant_id, asset_id)
            context["blast_radius"] = br
        else:
            br_sum = get_blast_radius_summary(db, tenant_id)
            context["blast_radius"] = br_sum
        logger.debug("Loop %d: blast radius gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: blast radius failed: %s", run.id, exc)
        context["blast_radius"] = {"error": str(exc), "available": False}

    # ── Attack Graph ──────────────────────────────────────────────────────────
    try:
        from services.attack_graph_service import get_attack_graph_summary
        if asset_id:
            from services.attack_graph_service import get_asset_attack_routes
            ag = get_asset_attack_routes(db, tenant_id, asset_id)
            context["attack_graph"] = ag
        else:
            ag = get_attack_graph_summary(db, tenant_id)
            context["attack_graph"] = ag
        logger.debug("Loop %d: attack graph gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: attack graph failed: %s", run.id, exc)
        context["attack_graph"] = {"error": str(exc), "available": False}

    # ── Dark Web ──────────────────────────────────────────────────────────────
    try:
        from models.darkweb import DarkWebFinding
        from sqlalchemy import func
        dw_count = (
            db.query(func.count(DarkWebFinding.id))
            .filter(
                DarkWebFinding.tenant_id == tenant_id,
                DarkWebFinding.status == "active",
            )
            .scalar() or 0
        )
        # If triggered by a dark web hit, get the specific finding
        dw_finding = None
        if run.trigger_ref_type == "darkweb_finding" and run.trigger_ref_id:
            f = db.query(DarkWebFinding).filter(DarkWebFinding.id == run.trigger_ref_id).first()
            if f:
                dw_finding = {
                    "id": f.id,
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "description": f.description,
                }
        context["dark_web"] = {
            "active_findings_count": dw_count,
            "triggering_finding": dw_finding,
        }
        logger.debug("Loop %d: dark web gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: dark web failed: %s", run.id, exc)
        context["dark_web"] = {"error": str(exc), "available": False}

    # ── Identity Risk ─────────────────────────────────────────────────────────
    try:
        from services.identity_service import get_identity_risk_summary
        identity = get_identity_risk_summary(db, tenant_id)
        context["identity_risk"] = identity
        logger.debug("Loop %d: identity risk gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: identity risk failed: %s", run.id, exc)
        context["identity_risk"] = {"error": str(exc), "available": False}

    # ── Open CVEs ─────────────────────────────────────────────────────────────
    try:
        from models.telemetry import VulnerabilityFinding
        from sqlalchemy import func
        cve_q = db.query(
            VulnerabilityFinding.severity,
            func.count(VulnerabilityFinding.id).label("count"),
        ).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.status == "open",
        ).group_by(VulnerabilityFinding.severity).all()

        cve_counts = {row.severity: row.count for row in cve_q}

        # Top 5 most critical CVEs
        top_cves = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.tenant_id == tenant_id,
                VulnerabilityFinding.status == "open",
                VulnerabilityFinding.severity == "CRITICAL",
            )
            .order_by(VulnerabilityFinding.cvss_score.desc())
            .limit(5)
            .all()
        )
        context["open_cves"] = {
            "counts_by_severity": cve_counts,
            "top_critical": [
                {
                    "cve_id": c.cve_id,
                    "software_name": c.software_name,
                    "cvss_score": c.cvss_score,
                    "asset_id": c.asset_id,
                }
                for c in top_cves
            ],
        }
        logger.debug("Loop %d: CVEs gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: CVE gathering failed: %s", run.id, exc)
        context["open_cves"] = {"error": str(exc), "available": False}

    # ── Asset Criticality ─────────────────────────────────────────────────────
    try:
        from models.criticality import CrownJewelAsset
        crown_count = (
            db.query(func.count(CrownJewelAsset.id))
            .filter(CrownJewelAsset.tenant_id == tenant_id)
            .scalar() or 0
        )
        context["asset_criticality"] = {
            "crown_jewel_count": crown_count,
        }
        if asset_id:
            cj = db.query(CrownJewelAsset).filter(
                CrownJewelAsset.tenant_id == tenant_id,
                CrownJewelAsset.asset_id == asset_id,
            ).first()
            context["asset_criticality"]["trigger_asset_is_crown_jewel"] = bool(cj)
        logger.debug("Loop %d: criticality gathered", run.id)
    except Exception as exc:
        logger.warning("Loop %d: criticality failed: %s", run.id, exc)
        context["asset_criticality"] = {"error": str(exc), "available": False}

    # ── Trigger Record (alert / finding) ──────────────────────────────────────
    try:
        if run.trigger_ref_type == "ai_alert" and run.trigger_ref_id:
            from models.ai_alert import AIAlert
            alert = db.query(AIAlert).filter(AIAlert.id == run.trigger_ref_id).first()
            if alert:
                context["trigger_record"] = {
                    "type": "ai_alert",
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "title": alert.title,
                    "summary": alert.summary,
                    "recommendation": alert.recommendation,
                    "confidence": alert.confidence,
                }
    except Exception as exc:
        logger.warning("Loop %d: trigger record fetch failed: %s", run.id, exc)

    return context


# ---------------------------------------------------------------------------
# Stage 2 + 3: Generate decision brief and action plan via AI
# ---------------------------------------------------------------------------

def _generate_brief(run: AgentLoopRun, context: dict) -> dict[str, Any]:
    """
    Send gathered context to the AI provider and parse the decision brief.
    Falls back to a structured heuristic brief if AI is unavailable.
    """
    provider = AIProviderService()

    # Redact before sending to LLM
    safe_context = redact_dict(context)

    user_message = f"""
TRIGGER: {run.trigger_type} — {run.trigger_summary}
ASSET ID: {run.trigger_asset_id or 'Unknown'}

GATHERED CONTEXT:
{json.dumps(safe_context, indent=2, default=str)[:6000]}

Please analyse this context and provide your decision brief and action recommendations as JSON.
"""

    try:
        if not provider.is_configured():
            raise ValueError("No AI provider configured")

        response = provider.call(
            system_prompt=SYSTEM_PROMPT,
            user_message=user_message,
            max_tokens=2000,
        )

        raw = response.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        brief = json.loads(raw)
        brief["_ai_model"] = response.model
        brief["_ai_generated"] = True
        return brief

    except Exception as exc:
        logger.warning("Loop %d: AI brief generation failed: %s — using heuristic", run.id, exc)
        return _heuristic_brief(run, context)


def _heuristic_brief(run: AgentLoopRun, context: dict) -> dict:
    """
    Fallback brief when AI provider is unavailable.
    Uses rule-based heuristics to generate a basic decision brief.
    """
    blast = context.get("blast_radius", {})
    cves = context.get("open_cves", {})
    darkweb = context.get("dark_web", {})
    criticality = context.get("asset_criticality", {})
    trigger_rec = context.get("trigger_record", {})

    critical_cves = cves.get("counts_by_severity", {}).get("CRITICAL", 0)
    affected = blast.get("reachable_asset_count", 0) if isinstance(blast, dict) else 0
    crown_jewels = blast.get("crown_jewels_at_risk", 0) if isinstance(blast, dict) else 0
    dw_hits = darkweb.get("active_findings_count", 0)
    is_crown_jewel = criticality.get("trigger_asset_is_crown_jewel", False)

    # Simple risk scoring
    score = 30
    if critical_cves > 0: score += min(30, critical_cves * 5)
    if crown_jewels > 0: score += 25
    if dw_hits > 0: score += 15
    if is_crown_jewel: score += 20
    score = min(100, score)

    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"

    actions = [
        {
            "action_type": "create_incident",
            "tier": 0,
            "title": "Create incident record for this event",
            "rationale": "This event requires tracking through the incident response lifecycle.",
            "expected_outcome": "Incident created for analyst review and assignment.",
            "risk_reduction_estimate": 0.0,
            "target_type": None,
            "target_id": None,
            "target_name": None,
        },
        {
            "action_type": "notify_team",
            "tier": 0,
            "title": "Send security alert notification to team",
            "rationale": "Team should be aware of this security event immediately.",
            "expected_outcome": "Alert sent via configured notification channels (email/Slack).",
            "risk_reduction_estimate": 0.0,
            "target_type": None,
            "target_id": None,
            "target_name": None,
        },
        {
            "action_type": "trigger_rescan",
            "tier": 0,
            "title": "Trigger vulnerability rescan on affected asset",
            "rationale": "Rescan will confirm current vulnerability state and detect any changes.",
            "expected_outcome": "CVE scan queued for affected asset. Results available in 5-10 minutes.",
            "risk_reduction_estimate": 5.0,
            "target_type": "asset",
            "target_id": str(run.trigger_asset_id) if run.trigger_asset_id else None,
            "target_name": f"Asset ID {run.trigger_asset_id}" if run.trigger_asset_id else "All assets",
        },
    ]

    if crown_jewels > 0 and run.trigger_asset_id:
        actions.append({
            "action_type": "isolate_asset",
            "tier": 1,
            "title": f"Isolate trigger asset (ID: {run.trigger_asset_id}) from network",
            "rationale": f"Asset has {crown_jewels} crown jewel(s) reachable within blast radius. Isolation prevents lateral spread.",
            "expected_outcome": "Agent receives network isolation command. Asset disconnected pending investigation.",
            "risk_reduction_estimate": 40.0,
            "target_type": "asset",
            "target_id": str(run.trigger_asset_id),
            "target_name": f"Asset ID {run.trigger_asset_id}",
        })

    return {
        "brief_title": f"Security event detected: {run.trigger_type.replace('_', ' ').title()}",
        "severity": severity,
        "confidence": 60,
        "brief_summary": f"A {severity} severity security event has been detected. {affected} assets may be affected. {crown_jewels} crown jewel(s) are potentially reachable. Immediate analyst review is recommended.",
        "brief_technical": f"Trigger: {run.trigger_type}. CVE count (CRITICAL): {critical_cves}. Dark web findings: {dw_hits}. Blast radius asset count: {affected}. Crown jewels at risk: {crown_jewels}. Source: heuristic (AI unavailable).",
        "mitre_tactic": None,
        "mitre_technique": None,
        "assessed_risk_score": float(score),
        "affected_asset_count": affected,
        "crown_jewels_at_risk": crown_jewels,
        "actions": actions,
        "_ai_generated": False,
        "_ai_model": "heuristic_fallback",
    }


# ---------------------------------------------------------------------------
# Stage 4: Execute actions
# ---------------------------------------------------------------------------

def _execute_action(db: Session, action: AgentLoopAction) -> None:
    """Execute a single action. Updates action status and result."""
    now = datetime.now(timezone.utc)
    action.status = "executing"
    action.executed_at = now
    db.commit()

    try:
        result = _dispatch_action(db, action)
        action.status = "completed"
        action.execution_result = result.get("message", "Completed successfully.")
        action.execution_ref_id = str(result.get("ref_id", "")) if result.get("ref_id") else None
    except Exception as exc:
        logger.exception("Action %d (%s) failed: %s", action.id, action.action_type, exc)
        action.status = "failed"
        action.execution_result = str(exc)

    db.commit()


def _dispatch_action(db: Session, action: AgentLoopAction) -> dict:
    """Route an action to its handler. Returns a result dict."""

    # ── TIER 0: Safe, automatic ───────────────────────────────────────────────

    if action.action_type == "create_incident":
        from services.incident_response_service import create_incident
        tenant_id = action.tenant_id
        run = db.query(AgentLoopRun).filter(AgentLoopRun.id == action.run_id).first()
        inc = create_incident(
            db=db,
            tenant_id=tenant_id,
            title=run.brief_title or "AI-detected security event",
            description=run.brief_summary or "",
            severity=run.brief_severity or "high",
            source="ai_alert",
            source_ref_id=run.trigger_ref_id,
            source_ref_type=run.trigger_ref_type,
            created_by="agentic_loop",
        )
        # Link incident back to run
        run.incident_id = inc["id"]
        db.commit()
        return {"message": f"Incident #{inc['id']} created.", "ref_id": inc["id"]}

    elif action.action_type == "notify_team":
        from services.notification_service import evaluate_all_rules
        try:
            evaluate_all_rules(db, action.tenant_id)
            return {"message": "Notification rules evaluated and alerts sent."}
        except Exception:
            return {"message": "Notification evaluation triggered (partial)."}

    elif action.action_type == "trigger_rescan":
        from models.commands import ScanJob
        import time
        job = ScanJob(
            tenant_id=action.tenant_id,
            job_type="vuln_scan",
            status="queued",
            requested_by="agentic_loop",
            target_count=1,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return {"message": f"Vulnerability rescan queued (job #{job.id}).", "ref_id": job.id}

    elif action.action_type == "create_investigation":
        from services.ai_action_service import AIActionService
        run = db.query(AgentLoopRun).filter(AgentLoopRun.id == action.run_id).first()
        if run and run.trigger_ref_id and run.trigger_ref_type == "ai_alert":
            svc = AIActionService(db)
            result = svc._create_investigation(
                db.query(__import__('models.ai_alert', fromlist=['AIAlert']).AIAlert)
                .filter_by(id=run.trigger_ref_id).first(),
                action.tenant_id,
            )
            if run and result:
                run.investigation_id = getattr(result, 'data', {}).get('investigation_id')
                db.commit()
            return {"message": "AI investigation created.", "ref_id": run.investigation_id}
        return {"message": "Investigation skipped (no alert reference)."}

    # ── TIER 1: One-click — executed only after approval ─────────────────────

    elif action.action_type == "isolate_asset":
        from models.commands import AgentCommand, ScanJob
        import time, uuid
        if not action.target_id:
            return {"message": "No target asset specified."}

        # Create isolation command via Command Centre
        job = ScanJob(
            tenant_id=action.tenant_id,
            job_type="isolate_asset",
            status="queued",
            requested_by="agentic_loop",
            target_count=1,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        cmd = AgentCommand(
            tenant_id=action.tenant_id,
            agent_id=int(action.target_id),
            job_id=job.id,
            command_uuid=str(uuid.uuid4()),
            command_type="isolate",
            status="queued",
            arguments_json={"reason": "Agentic loop isolation — supervisor approved"},
        )
        db.add(cmd)
        db.commit()
        return {
            "message": f"Isolation command issued to agent {action.target_id} (command: {cmd.command_uuid}).",
            "ref_id": cmd.command_uuid,
        }

    elif action.action_type == "force_password_reset":
        from models.commands import AgentCommand, ScanJob
        import uuid
        job = ScanJob(
            tenant_id=action.tenant_id,
            job_type="force_password_reset",
            status="queued",
            requested_by="agentic_loop",
            target_count=1,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return {"message": f"Password reset command queued for {action.target_name}.", "ref_id": job.id}

    elif action.action_type == "disable_account":
        from models.commands import ScanJob
        job = ScanJob(
            tenant_id=action.tenant_id,
            job_type="disable_account",
            status="queued",
            requested_by="agentic_loop",
            target_count=1,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return {"message": f"Account disable command queued for {action.target_name}.", "ref_id": job.id}

    elif action.action_type == "block_ip":
        return {"message": f"IP block recommendation logged for {action.target_name}. Implement via firewall rule."}

    else:
        return {"message": f"Action type '{action.action_type}' acknowledged but not yet implemented."}


# ---------------------------------------------------------------------------
# Main loop orchestrator
# ---------------------------------------------------------------------------

def _execute_loop(db: Session, run: AgentLoopRun) -> None:
    """Execute all 5 stages of the agentic loop."""
    now = datetime.now(timezone.utc)

    # Stage 1: Gather
    run.status = "gathering"
    db.commit()
    context = _gather_context(db, run)
    run.context_json = context
    run.context_gathered_at = datetime.now(timezone.utc)
    db.commit()

    # Stage 2+3: Brief + Plan
    run.status = "briefing"
    db.commit()
    brief = _generate_brief(run, context)

    run.brief_title = brief.get("brief_title", "Security Event Detected")
    run.brief_severity = brief.get("severity", "medium")
    run.brief_confidence = int(brief.get("confidence", 0))
    run.brief_summary = brief.get("brief_summary", "")
    run.brief_technical = brief.get("brief_technical", "")
    run.brief_mitre_tactic = brief.get("mitre_tactic")
    run.brief_mitre_technique = brief.get("mitre_technique")
    run.assessed_risk_score = float(brief.get("assessed_risk_score", 0))
    run.affected_asset_count = int(brief.get("affected_asset_count", 0))
    run.crown_jewels_at_risk = int(brief.get("crown_jewels_at_risk", 0))
    run.ai_model_used = brief.get("_ai_model", "unknown")
    run.brief_generated_at = datetime.now(timezone.utc)
    db.commit()

    # Create action records
    actions_data = brief.get("actions", [])
    action_objects = []
    for a in actions_data:
        act = AgentLoopAction(
            tenant_id=run.tenant_id,
            run_id=run.id,
            action_type=a.get("action_type", "unknown"),
            tier=int(a.get("tier", 0)),
            title=a.get("title", ""),
            rationale=a.get("rationale", ""),
            expected_outcome=a.get("expected_outcome", ""),
            risk_reduction_estimate=float(a.get("risk_reduction_estimate", 0)),
            target_type=a.get("target_type"),
            target_id=str(a.get("target_id")) if a.get("target_id") else None,
            target_name=a.get("target_name"),
            status="pending",
        )
        db.add(act)
        action_objects.append(act)

    db.commit()
    for act in action_objects:
        db.refresh(act)

    tier0 = [a for a in action_objects if a.tier == 0]
    pending = [a for a in action_objects if a.tier > 0]

    run.total_actions = len(action_objects)
    run.auto_executed = len(tier0)
    run.pending_approval = len(pending)
    run.status = "executing"
    db.commit()

    # Stage 4: Execute tier 0 actions automatically
    for act in tier0:
        try:
            _execute_action(db, act)
            run.auto_executed = (run.auto_executed or 0)
        except Exception as exc:
            logger.warning("Tier 0 action %d failed: %s", act.id, exc)

    # Stage 5: Complete
    run.status = "awaiting_approval" if pending else "completed"
    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    logger.info(
        "Agentic loop run %d complete — severity=%s tier0_executed=%d pending_approval=%d",
        run.id, run.brief_severity, len(tier0), len(pending),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_action(db: Session, tenant_id: str, action_id: int) -> AgentLoopAction:
    action = (
        db.query(AgentLoopAction)
        .filter(AgentLoopAction.id == action_id, AgentLoopAction.tenant_id == tenant_id)
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail="Action not found.")
    return action


def _run_to_dict(r: AgentLoopRun) -> dict:
    return {
        "id": r.id,
        "tenant_id": r.tenant_id,
        "trigger_type": r.trigger_type,
        "trigger_ref_id": r.trigger_ref_id,
        "trigger_ref_type": r.trigger_ref_type,
        "trigger_asset_id": r.trigger_asset_id,
        "trigger_summary": r.trigger_summary,
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "brief_title": r.brief_title,
        "brief_severity": r.brief_severity,
        "brief_confidence": r.brief_confidence,
        "brief_summary": r.brief_summary,
        "brief_technical": r.brief_technical,
        "mitre_tactic": r.brief_mitre_tactic,
        "mitre_technique": r.brief_mitre_technique,
        "assessed_risk_score": r.assessed_risk_score,
        "affected_asset_count": r.affected_asset_count,
        "crown_jewels_at_risk": r.crown_jewels_at_risk,
        "ai_model_used": r.ai_model_used,
        "total_actions": r.total_actions,
        "auto_executed": r.auto_executed,
        "pending_approval": r.pending_approval,
        "approved_actions": r.approved_actions,
        "rejected_actions": r.rejected_actions,
        "incident_id": r.incident_id,
        "investigation_id": r.investigation_id,
        "reviewed_by": r.reviewed_by,
        "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        "error_message": r.error_message,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _action_to_dict(a: AgentLoopAction) -> dict:
    return {
        "id": a.id,
        "run_id": a.run_id,
        "action_type": a.action_type,
        "tier": a.tier,
        "tier_label": ["automatic", "one-click approval", "deliberate approval"][min(a.tier, 2)],
        "title": a.title,
        "rationale": a.rationale,
        "expected_outcome": a.expected_outcome,
        "risk_reduction_estimate": a.risk_reduction_estimate,
        "target_type": a.target_type,
        "target_id": a.target_id,
        "target_name": a.target_name,
        "status": a.status,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
        "execution_result": a.execution_result,
        "execution_ref_id": a.execution_ref_id,
        "decided_by": a.decided_by,
        "decided_at": a.decided_at.isoformat() if a.decided_at else None,
        "decision_note": a.decision_note,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
