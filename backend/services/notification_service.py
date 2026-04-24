from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.request
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.notifications")

# ---------------------------------------------------------------------------
# Trigger type definitions
# ---------------------------------------------------------------------------

TRIGGER_LABELS = {
    "new_critical_cve":     "New Critical CVE Detected",
    "new_ai_alert":         "New High/Critical AI Alert",
    "dark_web_exposure":    "Dark Web Exposure Found",
    "patch_score_low":      "Patch Score Below Threshold",
    "new_credential_leak":  "Credential / Secret Leak Detected",
    "ce_compliance_fail":   "CE Compliance Score Below Threshold",
}

TRIGGER_DEFAULTS = {
    "new_critical_cve":     {"threshold": 1,  "desc": "Alert when critical CVE count reaches threshold"},
    "new_ai_alert":         {"threshold": 1,  "desc": "Alert when high/critical AI alerts are raised"},
    "dark_web_exposure":    {"threshold": 1,  "desc": "Alert when active dark web findings exist"},
    "patch_score_low":      {"threshold": 70, "desc": "Alert when patch score drops below threshold"},
    "new_credential_leak":  {"threshold": 1,  "desc": "Alert when credential/secret leaks are detected"},
    "ce_compliance_fail":   {"threshold": 70, "desc": "Alert when CE score drops below threshold %"},
}


# ---------------------------------------------------------------------------
# Sending functions
# ---------------------------------------------------------------------------

def _send_email(destination: str, subject: str, body_html: str) -> None:
    host     = os.getenv("CYBERASSETIQ_SMTP_HOST", "")
    port     = int(os.getenv("CYBERASSETIQ_SMTP_PORT", "587"))
    user     = os.getenv("CYBERASSETIQ_SMTP_USER", "")
    password = os.getenv("CYBERASSETIQ_SMTP_PASS", "")
    from_addr = os.getenv("CYBERASSETIQ_SMTP_FROM", user)
    use_tls  = os.getenv("CYBERASSETIQ_SMTP_TLS", "true").lower() == "true"

    if not host:
        raise ValueError("SMTP not configured — set CYBERASSETIQ_SMTP_HOST env var")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = destination
    msg.attach(MIMEText(body_html, "html"))

    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.send_message(msg)


def _send_slack(webhook_url: str, title: str, text: str, severity: str = "medium") -> None:
    colour = {"critical": "#B32D1F", "high": "#C7600A", "medium": "#2E75B6", "low": "#1F7A4D"}.get(severity, "#2E75B6")
    payload = {
        "attachments": [{
            "color":  colour,
            "title":  f"🛡️ CyberAssetIQ — {title}",
            "text":   text,
            "footer": "CyberAssetIQ Security Platform",
            "ts":     int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _send_teams(webhook_url: str, title: str, text: str, severity: str = "medium") -> None:
    colour = {"critical": "B32D1F", "high": "C7600A", "medium": "2E75B6", "low": "1F7A4D"}.get(severity, "2E75B6")
    payload = {
        "@type":    "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": colour,
        "summary":  title,
        "sections": [{"activityTitle": f"🛡️ {title}", "activityText": text}],
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _send_webhook(webhook_url: str, title: str, text: str, trigger_type: str) -> None:
    """Generic Slack-compatible webhook."""
    payload = {
        "text":        f"*CyberAssetIQ Alert — {title}*\n{text}",
        "trigger_type": trigger_type,
        "platform":    "CyberAssetIQ",
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _build_email_body(title: str, detail: str, trigger_type: str) -> str:
    return f"""
<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
  <div style="background:#1B3A5C;padding:20px;border-radius:8px 8px 0 0">
    <h2 style="color:#fff;margin:0">🛡️ CyberAssetIQ Security Alert</h2>
  </div>
  <div style="background:#f8f9fa;padding:24px;border:1px solid #dee2e6;border-radius:0 0 8px 8px">
    <h3 style="color:#1B3A5C;margin-top:0">{title}</h3>
    <p style="color:#333;font-size:14px;line-height:1.6">{detail}</p>
    <hr style="border:none;border-top:1px solid #dee2e6;margin:20px 0">
    <p style="color:#666;font-size:12px">Trigger: {TRIGGER_LABELS.get(trigger_type, trigger_type)}<br>
    This alert was generated automatically by CyberAssetIQ.<br>
    Log in to your dashboard to investigate and take action.</p>
  </div>
</body></html>
"""


# ---------------------------------------------------------------------------
# Dispatch a single notification
# ---------------------------------------------------------------------------

def _dispatch(
    db: Session,
    rule_id: int | None,
    tenant_id: str,
    channel: str,
    destination: str,
    title: str,
    detail: str,
    trigger_type: str,
    severity: str = "medium",
) -> bool:
    from models.notification import NotificationLog

    subject = f"CyberAssetIQ Alert — {title}"
    status  = "sent"
    error   = None

    try:
        if channel == "email":
            _send_email(destination, subject, _build_email_body(title, detail, trigger_type))
        elif channel == "slack":
            _send_slack(destination, title, detail, severity)
        elif channel == "teams":
            _send_teams(destination, title, detail, severity)
        elif channel == "webhook":
            _send_webhook(destination, title, detail, trigger_type)
        else:
            raise ValueError(f"Unknown channel: {channel}")

        logger.info("Notification sent: channel=%s trigger=%s", channel, trigger_type)

    except Exception as exc:
        status = "failed"
        error  = str(exc)
        logger.warning("Notification failed: channel=%s error=%s", channel, exc)

    log = NotificationLog(
        tenant_id    = tenant_id,
        rule_id      = rule_id,
        channel      = channel,
        destination  = destination,
        subject      = subject,
        body         = detail,
        trigger_type = trigger_type,
        status       = status,
        error        = error,
    )
    db.add(log)
    db.commit()

    return status == "sent"


# ---------------------------------------------------------------------------
# Trigger evaluation
# ---------------------------------------------------------------------------

def _evaluate_trigger(
    db: Session,
    tenant_id: str,
    trigger_type: str,
    threshold: int | None,
) -> tuple[bool, str, str]:
    """Returns (triggered, detail_message, severity)."""
    now  = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    try:
        if trigger_type == "new_critical_cve":
            from models.telemetry import VulnerabilityFinding
            count = db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.tenant_id == tenant_id,
                VulnerabilityFinding.severity == "CRITICAL",
                VulnerabilityFinding.status == "open",
            ).count()
            limit = threshold or 1
            if count >= limit:
                return True, f"{count} open critical CVE(s) detected on your assets.", "critical"
            return False, f"{count} critical CVEs (threshold: {limit})", "critical"

        elif trigger_type == "new_ai_alert":
            from models.ai_alert import AIAlert
            count = db.query(AIAlert).filter(
                AIAlert.tenant_id == tenant_id,
                AIAlert.severity.in_(["HIGH", "CRITICAL"]),
                AIAlert.created_at >= day_ago,
            ).count()
            limit = threshold or 1
            if count >= limit:
                return True, f"{count} high/critical AI security alert(s) raised in the last 24 hours.", "high"
            return False, f"{count} alerts in 24h (threshold: {limit})", "high"

        elif trigger_type == "dark_web_exposure":
            from models.darkweb import DarkWebFinding
            count = db.query(DarkWebFinding).filter(
                DarkWebFinding.tenant_id == tenant_id,
                DarkWebFinding.status != "resolved",
            ).count()
            limit = threshold or 1
            if count >= limit:
                return True, f"{count} active dark web exposure(s) found — credentials or data may be compromised.", "critical"
            return False, f"{count} dark web findings (threshold: {limit})", "critical"

        elif trigger_type == "patch_score_low":
            from models.patch import PatchReport
            latest = db.query(PatchReport).filter(
                PatchReport.tenant_id == tenant_id,
            ).order_by(desc(PatchReport.id)).first()
            if latest:
                limit = threshold or 70
                if latest.patch_score < limit:
                    return True, f"Patch score is {latest.patch_score}/100 — below the {limit} threshold. {latest.pending_critical} critical update(s) pending.", "high"
                return False, f"Patch score {latest.patch_score} (threshold: {limit})", "medium"
            return False, "No patch data available yet", "medium"

        elif trigger_type == "new_credential_leak":
            from models.telemetry import LocalFindingsEvent
            recent = db.query(LocalFindingsEvent).filter(
                LocalFindingsEvent.tenant_id == tenant_id,
                LocalFindingsEvent.created_at >= day_ago,
            ).all()
            count = 0
            for evt in recent:
                try:
                    findings = (
                        evt.findings_json
                        if isinstance(evt.findings_json, list)
                        else json.loads(evt.findings_json or "[]")
                    )
                    count += sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
                except Exception:
                    pass
            limit = threshold or 1
            if count >= limit:
                return True, f"{count} critical/high severity credential or secret leak(s) detected by endpoint agents in the last 24 hours.", "critical"
            return False, f"{count} credential leaks in 24h (threshold: {limit})", "critical"

        elif trigger_type == "ce_compliance_fail":
            from models.compliance_run import ComplianceRun
            latest = db.query(ComplianceRun).filter(
                ComplianceRun.tenant_id == tenant_id,
            ).order_by(desc(ComplianceRun.id)).first()
            if latest:
                score = latest.tenant_overall_score or 0
                limit = threshold or 70
                if score < limit:
                    return True, f"Cyber Essentials compliance score is {score:.0f}% — below the {limit}% certification threshold.", "high"
                return False, f"CE score {score:.0f}% (threshold: {limit}%)", "medium"
            return False, "No compliance data available yet", "medium"

    except Exception as exc:
        logger.warning("Trigger evaluation error (%s): %s", trigger_type, exc)

    return False, "Evaluation error", "medium"


# ---------------------------------------------------------------------------
# Evaluate all active rules for a tenant
# ---------------------------------------------------------------------------

def evaluate_rules(db: Session, tenant_id: str) -> int:
    from models.notification import NotificationRule

    rules = db.query(NotificationRule).filter(
        NotificationRule.tenant_id == tenant_id,
        NotificationRule.is_active.is_(True),
    ).all()

    sent = 0
    now  = datetime.now(timezone.utc)

    for rule in rules:
        # Check cooldown
        if rule.last_triggered_at:
            elapsed = (now - rule.last_triggered_at).total_seconds() / 60
            if elapsed < (rule.cooldown_minutes or 60):
                continue

        triggered, detail, severity = _evaluate_trigger(
            db, tenant_id, rule.trigger_type, rule.threshold
        )

        if triggered:
            title = TRIGGER_LABELS.get(rule.trigger_type, rule.trigger_type)
            ok = _dispatch(
                db, rule.id, tenant_id,
                rule.channel, rule.destination,
                title, detail, rule.trigger_type, severity,
            )
            if ok:
                rule.last_triggered_at = now
                db.commit()
                sent += 1

    return sent


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_rule(db: Session, tenant_id: str, data: dict) -> dict:
    from models.notification import NotificationRule

    rule = NotificationRule(
        tenant_id        = tenant_id,
        name             = data["name"],
        trigger_type     = data["trigger_type"],
        threshold        = data.get("threshold"),
        cooldown_minutes = data.get("cooldown_minutes", 60),
        channel          = data["channel"],
        destination      = data["destination"],
        is_active        = data.get("is_active", True),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_dict(rule)


def list_rules(db: Session, tenant_id: str) -> list[dict]:
    from models.notification import NotificationRule

    rows = db.query(NotificationRule).filter(
        NotificationRule.tenant_id == tenant_id,
    ).order_by(desc(NotificationRule.id)).all()
    return [_rule_dict(r) for r in rows]


def toggle_rule(db: Session, tenant_id: str, rule_id: int, active: bool) -> dict:
    from models.notification import NotificationRule

    rule = db.query(NotificationRule).filter(
        NotificationRule.id == rule_id,
        NotificationRule.tenant_id == tenant_id,
    ).first()
    if not rule:
        return {"error": "Rule not found"}
    rule.is_active = active
    db.commit()
    return _rule_dict(rule)


def delete_rule(db: Session, tenant_id: str, rule_id: int) -> dict:
    from models.notification import NotificationRule

    rule = db.query(NotificationRule).filter(
        NotificationRule.id == rule_id,
        NotificationRule.tenant_id == tenant_id,
    ).first()
    if not rule:
        return {"error": "Rule not found"}
    db.delete(rule)
    db.commit()
    return {"deleted": True}


def test_rule(db: Session, tenant_id: str, rule_id: int) -> dict:
    from models.notification import NotificationRule

    rule = db.query(NotificationRule).filter(
        NotificationRule.id == rule_id,
        NotificationRule.tenant_id == tenant_id,
    ).first()
    if not rule:
        return {"error": "Rule not found"}

    title = f"[TEST] {TRIGGER_LABELS.get(rule.trigger_type, rule.trigger_type)}"
    detail = f"This is a test notification from CyberAssetIQ for rule '{rule.name}'."
    ok = _dispatch(
        db, rule.id, tenant_id,
        rule.channel, rule.destination,
        title, detail, rule.trigger_type, "medium",
    )
    return {"sent": ok, "channel": rule.channel, "destination": rule.destination}


def list_logs(db: Session, tenant_id: str, limit: int = 50) -> list[dict]:
    from models.notification import NotificationLog

    rows = db.query(NotificationLog).filter(
        NotificationLog.tenant_id == tenant_id,
    ).order_by(desc(NotificationLog.id)).limit(limit).all()

    return [
        {
            "id":           r.id,
            "sent_at":      r.sent_at.isoformat() if r.sent_at else None,
            "channel":      r.channel,
            "destination":  r.destination,
            "subject":      r.subject,
            "trigger_type": r.trigger_type,
            "status":       r.status,
            "error":        r.error,
        }
        for r in rows
    ]


def _rule_dict(r) -> dict:
    return {
        "id":               r.id,
        "name":             r.name,
        "trigger_type":     r.trigger_type,
        "trigger_label":    TRIGGER_LABELS.get(r.trigger_type, r.trigger_type),
        "threshold":        r.threshold,
        "cooldown_minutes": r.cooldown_minutes,
        "channel":          r.channel,
        "destination":      r.destination,
        "is_active":        r.is_active,
        "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
    }


def get_smtp_status() -> dict:
    host = os.getenv("CYBERASSETIQ_SMTP_HOST", "")
    return {
        "email_configured": bool(host),
        "smtp_host":        host or "Not configured",
        "smtp_port":        os.getenv("CYBERASSETIQ_SMTP_PORT", "587"),
        "smtp_user":        os.getenv("CYBERASSETIQ_SMTP_USER", ""),
        "smtp_from":        os.getenv("CYBERASSETIQ_SMTP_FROM", ""),
    }
