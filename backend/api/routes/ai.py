"""
AI Security Intelligence Routes  (v2 — full API)
All AI-facing endpoints: overview, alerts, events, correlations, investigations,
risk intelligence, attack timeline, daily brief, copilot, and explain.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from db.session import get_db
from models.ai_event import AIEvent
from models.ai_alert import AIAlert
from services.ai_copilot_service import AICopilotService
from services.ai_summary_service import AISummaryService
from services.ai_risk_service import AIRiskService
from services.ai_provider_service import AIProviderService

router = APIRouter(prefix="/api/ai", tags=["AI Security Intelligence"])


# ──────────────────────────────────────────────────────────────
# Pydantic request schemas
# ──────────────────────────────────────────────────────────────

class CopilotRequest(BaseModel):
    prompt: str
    context: Optional[Dict[str, Any]] = None


class InvestigationRequest(BaseModel):
    alert_ids: List[int]


class AlertStatusUpdate(BaseModel):
    status: str


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _serialise_alert(a: AIAlert) -> dict:
    return {
        "id": a.id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "title": a.title,
        "summary": a.summary,
        "recommendation": a.recommendation,
        "confidence": a.confidence,
        "status": a.status,
        "entities": a.entities or [],
        "evidence": a.evidence or {},
        "metadata_json": a.metadata_json or {},
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _serialise_event(e: AIEvent) -> dict:
    return {
        "id": e.id,
        "event_type": e.event_type,
        "severity": e.severity,
        "title": e.title,
        "description": e.description,
        "source": e.source,
        "asset_id": e.asset_id,
        "asset_name": e.asset_name,
        "ip_address": e.ip_address,
        "hostname": e.hostname,
        "status": e.status,
        "risk_score": e.risk_score,
        "ai_summary": e.ai_summary,
        "ai_recommendation": e.ai_recommendation,
        "tags": e.tags or [],
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


# ──────────────────────────────────────────────────────────────
# Overview
# ──────────────────────────────────────────────────────────────

@router.get("/overview")
def get_ai_overview(db: Session = Depends(get_db)):
    """Summary metrics for the AI Security Intelligence dashboard header."""
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=24)

    total_alerts   = db.query(AIAlert).count()
    open_alerts    = db.query(AIAlert).filter(AIAlert.status.in_(["new", "acknowledged"])).count()
    alerts_24h     = db.query(AIAlert).filter(AIAlert.created_at >= since_24h).count()
    critical_open  = db.query(AIAlert).filter(
        AIAlert.status.in_(["new", "acknowledged"]),
        AIAlert.severity == "critical"
    ).count()
    events_24h     = db.query(AIEvent).filter(AIEvent.created_at >= since_24h).count()
    avg_conf_row   = db.query(func.avg(AIAlert.confidence)).filter(AIAlert.status == "new").scalar()
    avg_conf       = round(float(avg_conf_row or 0), 1)

    provider = AIProviderService()
    return {
        "open_alerts":     open_alerts,
        "alerts_24h":      alerts_24h,
        "critical_open":   critical_open,
        "events_24h":      events_24h,
        "total_alerts":    total_alerts,
        "mean_confidence": avg_conf,
        "ai_configured":   provider.is_configured(),
        "ai_provider":     provider.provider_name() if provider.is_configured() else "not configured",
        "ai_model":        provider.model_name()    if provider.is_configured() else None,
    }


# ──────────────────────────────────────────────────────────────
# Alerts
# ──────────────────────────────────────────────────────────────

@router.get("/alerts")
def get_ai_alerts(
    severity:   Optional[str] = None,
    status:     Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: int  = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(AIAlert).order_by(desc(AIAlert.created_at))
    if severity:   q = q.filter(AIAlert.severity == severity)
    if status:     q = q.filter(AIAlert.status == status)
    if alert_type: q = q.filter(AIAlert.alert_type == alert_type)
    alerts = q.limit(limit).all()
    return {"total": len(alerts), "items": [_serialise_alert(a) for a in alerts]}


@router.get("/alerts/{alert_id}")
def get_ai_alert(alert_id: int, db: Session = Depends(get_db)):
    a = db.query(AIAlert).filter(AIAlert.id == alert_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialise_alert(a)


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    a = db.query(AIAlert).filter(AIAlert.id == alert_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    allowed = {"new", "acknowledged", "closed", "false_positive"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {allowed}")
    a.status = payload.status
    db.commit()
    return {"id": alert_id, "status": a.status}


@router.post("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """LLM-powered plain-English explanation for a specific alert."""
    svc = AISummaryService(db=db)
    explanation = svc.summarise_alert(alert_id)
    provider = AIProviderService()
    return {
        "alert_id": alert_id,
        "explanation": explanation,
        "provider": provider.provider_name(),
    }


# ──────────────────────────────────────────────────────────────
# Events
# ──────────────────────────────────────────────────────────────

@router.get("/events")
def get_ai_events(
    source:   Optional[str] = None,
    severity: Optional[str] = None,
    status:   Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(AIEvent).order_by(desc(AIEvent.created_at))
    if source:   q = q.filter(AIEvent.source == source)
    if severity: q = q.filter(AIEvent.severity == severity)
    if status:   q = q.filter(AIEvent.status == status)
    events = q.limit(limit).all()
    return {"total": len(events), "items": [_serialise_event(e) for e in events]}


# ──────────────────────────────────────────────────────────────
# Attack Timeline
# ──────────────────────────────────────────────────────────────

@router.get("/attack-timeline")
def get_attack_timeline(
    limit: int = Query(80, ge=1, le=500),
    db: Session = Depends(get_db),
):
    events = db.query(AIEvent).order_by(desc(AIEvent.created_at)).limit(limit).all()
    alerts = (
        db.query(AIAlert)
        .filter(AIAlert.status.in_(["new", "acknowledged"]))
        .order_by(desc(AIAlert.created_at))
        .limit(20)
        .all()
    )

    timeline = []
    for e in events:
        timeline.append({
            "kind": "event",
            "id": e.id,
            "timestamp": e.created_at.isoformat() if e.created_at else None,
            "title": e.title,
            "event_type": e.event_type,
            "severity": e.severity,
            "source": e.source,
            "asset": e.asset_name or e.hostname or e.ip_address,
            "risk_score": e.risk_score,
            "summary": e.ai_summary or e.description,
            "tags": e.tags or [],
        })
    for a in alerts:
        timeline.append({
            "kind": "alert",
            "id": a.id,
            "timestamp": a.created_at.isoformat() if a.created_at else None,
            "title": a.title,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "status": a.status,
            "entities": a.entities or [],
        })

    timeline.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "items": timeline[:limit],
    }


# ──────────────────────────────────────────────────────────────
# Daily Brief
# ──────────────────────────────────────────────────────────────

@router.get("/daily-brief")
def get_ai_daily_brief(
    use_llm: bool = Query(True),
    db: Session = Depends(get_db),
):
    """AI-generated daily security brief. Set use_llm=false for data-only mode."""
    if use_llm:
        svc = AISummaryService(db=db)
        return svc.generate_daily_brief()

    # ── Fallback: data summary, no LLM ──
    now = datetime.utcnow()
    since = now - timedelta(hours=24)
    recent_alerts = (
        db.query(AIAlert)
        .filter(AIAlert.created_at >= since)
        .order_by(desc(AIAlert.created_at))
        .limit(20)
        .all()
    )
    recent_events = (
        db.query(AIEvent)
        .filter(AIEvent.created_at >= since)
        .order_by(desc(AIEvent.created_at))
        .limit(50)
        .all()
    )
    critical = [a for a in recent_alerts if (a.severity or "").lower() == "critical"]
    high     = [a for a in recent_alerts if (a.severity or "").lower() == "high"]

    return {
        "llm_summary": (
            f"{len(recent_alerts)} AI alerts in the last 24 hours — "
            f"{len(critical)} critical, {len(high)} high. "
            f"{len(recent_events)} security events processed."
        ),
        "metrics": {
            "alerts_24h":     len(recent_alerts),
            "critical_alerts": len(critical),
            "high_alerts":    len(high),
            "events_24h":     len(recent_events),
        },
        "top_alerts": [
            {
                "id": a.id, "title": a.title,
                "severity": a.severity, "confidence": a.confidence,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in recent_alerts[:5]
        ],
        "top_vulns": [],
    }


# ──────────────────────────────────────────────────────────────
# Risk Intelligence
# ──────────────────────────────────────────────────────────────

@router.get("/risk-intelligence")
def get_risk_intelligence(db: Session = Depends(get_db)):
    """Returns AI-scored asset risk intelligence."""
    svc = AIRiskService(db=db)
    top_assets = svc.get_top_risky_assets("tenant-001", limit=10)
    summary    = svc.build_risk_summary("tenant-001")
    return {
        "summary": summary,
        "top_assets": top_assets,
    }


@router.post("/risk/asset/{asset_id}")
def explain_asset_risk(asset_id: int, db: Session = Depends(get_db)):
    """LLM explanation of why a specific asset is at its current risk level."""
    svc = AISummaryService(db=db)
    explanation = svc.summarise_asset_risk(asset_id)
    return {"asset_id": asset_id, "explanation": explanation}


# ──────────────────────────────────────────────────────────────
# Investigations
# ──────────────────────────────────────────────────────────────

@router.post("/investigations/generate")
def generate_investigation(payload: InvestigationRequest, db: Session = Depends(get_db)):
    """Generate an LLM-powered investigation report for a set of correlated alerts."""
    if not payload.alert_ids:
        raise HTTPException(status_code=400, detail="Provide at least one alert_id")
    svc = AISummaryService(db=db)
    return svc.summarise_investigation(payload.alert_ids)


# ──────────────────────────────────────────────────────────────
# Copilot
# ──────────────────────────────────────────────────────────────

@router.post("/copilot")
def ai_copilot(payload: CopilotRequest, db: Session = Depends(get_db)):
    """Natural-language security Q&A grounded in live platform data."""
    svc = AICopilotService(db=db)
    return svc.ask(prompt=payload.prompt, context=payload.context or {})


# ──────────────────────────────────────────────────────────────
# Demo data seed
# ──────────────────────────────────────────────────────────────

@router.post("/seed-demo")
def seed_ai_demo_data(db: Session = Depends(get_db)):
    """Seeds realistic demo events and alerts for UI demonstration."""
    import json

    demo_events = [
        AIEvent(
            event_type="login_failure", severity="high",
            title="Repeated failed logins — possible brute force",
            description="18 failed authentication attempts in 7 minutes from 203.0.113.42.",
            source="siem", asset_name="WIN-DC01", ip_address="192.168.0.10",
            hostname="WIN-DC01.corp.local", status="open", risk_score=82,
            ai_summary="Brute-force pattern detected. Source IP is external.",
            ai_recommendation="Block source IP at firewall. Review AD lockout policies. Enable MFA.",
            tags=["brute_force", "identity", "external_ip"],
        ),
        AIEvent(
            event_type="login_success", severity="critical",
            title="Successful login after 18 failures — credential compromise suspected",
            description="Admin account login succeeded after a brute-force burst from an external IP.",
            source="siem", asset_name="WIN-DC01", ip_address="192.168.0.10",
            hostname="WIN-DC01.corp.local", status="open", risk_score=97,
            ai_summary="Post-brute-force success login is a high-confidence compromise indicator.",
            ai_recommendation="Isolate host immediately. Reset admin credentials. Engage IR team.",
            tags=["brute_force_success", "identity", "critical"],
        ),
        AIEvent(
            event_type="powershell_suspicious", severity="high",
            title="Encoded PowerShell execution detected",
            description="PowerShell launched with -EncodedCommand flag — common evasion technique.",
            source="edr", asset_name="LAPTOP-HR01", ip_address="192.168.0.55",
            hostname="LAPTOP-HR01.corp.local", status="open", risk_score=78,
            ai_summary="Encoded PowerShell is frequently used for payload delivery and C2 staging.",
            ai_recommendation="Capture and decode the payload. Check child processes. Review user context.",
            tags=["powershell", "execution", "evasion"],
        ),
        AIEvent(
            event_type="api_key_exposure", severity="critical",
            title="Stripe API key detected in source code repository",
            description="Live Stripe secret key committed to internal Git repository.",
            source="credential_scanner", asset_name="GIT-REPO",
            ip_address=None, hostname=None, status="open", risk_score=95,
            ai_summary="Live production credential exposed in version control. Revoke immediately.",
            ai_recommendation="Revoke key in Stripe dashboard. Rotate all repo secrets. Enable pre-commit scanning.",
            tags=["credential_leak", "api_key", "stripe"],
        ),
    ]

    event_ids = []
    for ev in demo_events:
        db.add(ev)
        db.flush()
        event_ids.append(ev.id)

    demo_alerts = [
        AIAlert(
            ai_event_id=event_ids[1],
            alert_type="brute_force_success",
            severity="critical",
            title="Brute Force — Successful Credential Compromise",
            summary=(
                "An admin account on WIN-DC01 was successfully accessed following 18 failed "
                "attempts from external IP 203.0.113.42. This pattern is consistent with "
                "a brute-force credential attack that achieved access."
            ),
            recommendation="Isolate WIN-DC01. Reset domain admin credentials. Engage incident response. Review AD audit logs.",
            confidence=94,
            status="new",
            entities=["WIN-DC01.corp.local", "203.0.113.42", "admin@corp.local"],
            evidence={"failed_logins": 18, "successful_login": 1, "source_ip": "203.0.113.42", "time_window_minutes": 7},
            metadata_json={"mitre_tactic": "Credential Access", "mitre_technique": "T1110 — Brute Force"},
        ),
        AIAlert(
            ai_event_id=event_ids[2],
            alert_type="suspicious_script",
            severity="high",
            title="Suspicious Encoded PowerShell Execution",
            summary=(
                "An encoded PowerShell command was executed on LAPTOP-HR01. "
                "Encoded commands are frequently used to evade detection during initial "
                "access, payload staging, and C2 communication."
            ),
            recommendation="Decode and analyse the PowerShell payload. Check parent process tree. Review user activity. Scan for persistence mechanisms.",
            confidence=81,
            status="new",
            entities=["LAPTOP-HR01.corp.local", "192.168.0.55"],
            evidence={"command_line": "powershell.exe -EncodedCommand <base64>", "parent_process": "winword.exe"},
            metadata_json={"mitre_tactic": "Execution", "mitre_technique": "T1059.001 — PowerShell"},
        ),
        AIAlert(
            ai_event_id=event_ids[3],
            alert_type="api_key_exposure",
            severity="critical",
            title="Live Production API Key Exposed in Git Repository",
            summary=(
                "A live Stripe secret key was found committed to an internal Git repository. "
                "This credential is currently valid and could be used to make unauthorised "
                "financial transactions or access customer payment data."
            ),
            recommendation="Revoke key in Stripe dashboard immediately. Audit recent API activity. Rotate all repository secrets. Enable pre-commit hooks.",
            confidence=99,
            status="new",
            entities=["GIT-REPO", "stripe_secret_key"],
            evidence={"key_type": "stripe_live_secret", "location": "src/payment/config.py", "exposed_since": "2025-11-12"},
            metadata_json={"mitre_tactic": "Credential Access", "mitre_technique": "T1552 — Unsecured Credentials"},
        ),
    ]

    for al in demo_alerts:
        db.add(al)

    db.commit()
    return {
        "message": "Demo AI data seeded successfully",
        "events_created": len(demo_events),
        "alerts_created": len(demo_alerts),
    }


# ──────────────────────────────────────────────────────────────
# Auto-response
# ──────────────────────────────────────────────────────────────

class RespondRequest(BaseModel):
    actions: Optional[List[str]] = None
    tenant_id: Optional[str] = "tenant-001"


@router.post("/alerts/{alert_id}/respond")
def respond_to_alert(
    alert_id: int,
    payload: RespondRequest,
    db: Session = Depends(get_db),
):
    """
    Trigger safe automated response actions for an alert.
    Actions: create_investigation, trigger_rescan, send_webhook.
    If actions not specified, defaults are chosen based on alert severity.
    """
    from services.ai_action_service import AIActionService
    svc = AIActionService(db=db)
    results = svc.respond_to_alert(
        alert_id=alert_id,
        tenant_id=payload.tenant_id or "tenant-001",
        actions=payload.actions,
    )
    return {
        "alert_id": alert_id,
        "actions_run": len(results),
        "results": [r.to_dict() for r in results],
    }
