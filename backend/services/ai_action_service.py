"""
AI Action Service
Safe automated response actions triggered by AI alerts.

Actions implemented:
  1. create_investigation  - Creates an AIInvestigation record with LLM summary
  2. trigger_rescan        - Queues a vulnerability rescan for the affected asset
  3. send_webhook          - POSTs alert data to a configurable webhook URL

Philosophy: These are SAFE actions only. No automated asset isolation,
account disabling, or firewall rule changes — those remain manual decisions.
The platform recommends, the human decides on destructive actions.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from models.ai_alert import AIAlert
from models.ai_event import AIEvent
from models.ai_investigation import AIInvestigation
from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset
from services.ai_summary_service import AISummaryService
from services.ai_mitre_service import AIMitreService

logger = logging.getLogger(__name__)
_mitre = AIMitreService()

# Webhook URL from environment (optional)
WEBHOOK_URL = os.getenv("CYBERASSETIQ_WEBHOOK_URL", "")
WEBHOOK_ENABLED = bool(WEBHOOK_URL)


class ActionResult:
    def __init__(self, action: str, success: bool, detail: str, data: Dict[str, Any] = None):
        self.action = action
        self.success = success
        self.detail = detail
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action":  self.action,
            "success": self.success,
            "detail":  self.detail,
            "data":    self.data,
        }


class AIActionService:

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Public: respond to an alert with all applicable actions
    # ------------------------------------------------------------------

    def respond_to_alert(
        self,
        alert_id: int,
        tenant_id: str = "tenant-001",
        actions: Optional[List[str]] = None,
    ) -> List[ActionResult]:
        """
        Run safe automated response actions for a given alert.

        actions: list of action names to run, or None for all applicable.
        Available: ["create_investigation", "trigger_rescan", "send_webhook"]
        """
        alert = self.db.query(AIAlert).filter(AIAlert.id == alert_id).first()
        if not alert:
            return [ActionResult("respond", False, f"Alert {alert_id} not found")]

        all_actions = actions or self._default_actions_for_alert(alert)
        results = []

        for action in all_actions:
            try:
                if action == "create_investigation":
                    result = self._create_investigation(alert, tenant_id)
                elif action == "trigger_rescan":
                    result = self._trigger_rescan(alert, tenant_id)
                elif action == "send_webhook":
                    result = self._send_webhook(alert, tenant_id)
                else:
                    result = ActionResult(action, False, f"Unknown action: {action}")
                results.append(result)
            except Exception as exc:
                logger.error("Action %s failed for alert %d: %s", action, alert_id, exc)
                results.append(ActionResult(action, False, str(exc)))

        return results

    # ------------------------------------------------------------------
    # Action 1: Create Investigation
    # ------------------------------------------------------------------

    def _create_investigation(
        self, alert: AIAlert, tenant_id: str
    ) -> ActionResult:
        """
        Create an AIInvestigation record for this alert.
        Generates an LLM summary if AI is configured.
        Idempotent — skips if investigation already exists for this alert.
        """
        # Check if investigation already exists
        existing = (
            self.db.query(AIInvestigation)
            .filter(AIInvestigation.alert_id == alert.id)
            .first()
        )
        if existing:
            return ActionResult(
                "create_investigation", True,
                f"Investigation already exists (id={existing.id})",
                {"investigation_id": existing.id},
            )

        # Generate LLM summary
        llm_summary = None
        model_used = None
        try:
            svc = AISummaryService(self.db)
            llm_summary = svc.summarise_alert(alert.id)
            from services.ai_provider_service import AIProviderService
            model_used = AIProviderService.model_name()
        except Exception as exc:
            logger.warning("LLM summary failed for investigation: %s", exc)
            llm_summary = (
                f"Alert: {alert.title}\n"
                f"Severity: {alert.severity}\n"
                f"Summary: {alert.summary or 'No summary available'}\n"
                f"Recommendation: {alert.recommendation or 'Review alert details'}"
            )

        # Build remediation steps from alert recommendation
        remediation = []
        if alert.recommendation:
            for i, step in enumerate(alert.recommendation.split(". "), 1):
                step = step.strip().rstrip(".")
                if step:
                    remediation.append({"step": i, "action": step})

        # Build timeline from event
        timeline = []
        if alert.ai_event_id:
            event = self.db.query(AIEvent).filter(AIEvent.id == alert.ai_event_id).first()
            if event:
                timeline.append({
                    "time": event.created_at.isoformat() if event.created_at else None,
                    "event": event.title,
                    "severity": event.severity,
                    "source": event.source,
                })
        timeline.append({
            "time": alert.created_at.isoformat() if alert.created_at else None,
            "event": f"Alert created: {alert.title}",
            "severity": alert.severity,
            "source": "ai_detection",
        })

        mitre = (alert.metadata_json or {}).get("mitre_tactic")
        technique = (alert.metadata_json or {}).get("mitre_technique_id")

        investigation = AIInvestigation(
            tenant_id=tenant_id,
            alert_id=alert.id,
            executive_summary=f"{alert.severity.upper()} alert: {alert.title}. {(alert.summary or '')[:200]}",
            technical_summary=llm_summary,
            analyst_notes=f"Auto-created by AI Action Service. Alert confidence: {alert.confidence}%.",
            remediation_steps_json=remediation,
            timeline_json=timeline,
            mitre_tactic=mitre,
            mitre_technique=technique,
            model_used=model_used,
        )
        self.db.add(investigation)

        # Update alert status to acknowledged
        if alert.status == "new":
            alert.status = "acknowledged"

        self.db.commit()

        logger.info(
            "Investigation created: id=%d for alert %d (%s)",
            investigation.id, alert.id, alert.title,
        )
        return ActionResult(
            "create_investigation", True,
            f"Investigation {investigation.id} created",
            {"investigation_id": investigation.id},
        )

    # ------------------------------------------------------------------
    # Action 2: Trigger Rescan
    # ------------------------------------------------------------------

    def _trigger_rescan(
        self, alert: AIAlert, tenant_id: str
    ) -> ActionResult:
        """
        Queue a vulnerability rescan for the asset referenced in the alert.
        Uses the existing scan job infrastructure.
        """
        # Find affected asset from alert entities
        asset_name = (alert.entities or [None])[0] if alert.entities else None
        if not asset_name:
            return ActionResult(
                "trigger_rescan", False,
                "No asset entity found in alert — cannot target rescan",
            )

        # Look up asset agent_id
        canonical = (
            self.db.query(CanonicalAsset)
            .filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.hostname == asset_name,
            )
            .first()
        )

        if canonical:
            # Queue agent scan via command
            try:
                from services.command_service import create_scan_job
                job = create_scan_job(
                    self.db, tenant_id,
                    [canonical.agent_id],
                    job_type="run_scan_full",
                    requested_by="ai_action_service",
                )
                self.db.commit()
                logger.info(
                    "Rescan queued: agent=%s for alert %d",
                    canonical.agent_id, alert.id,
                )
                return ActionResult(
                    "trigger_rescan", True,
                    f"Rescan queued for agent {canonical.agent_id}",
                    {"agent_id": canonical.agent_id, "job_id": job.id},
                )
            except Exception as exc:
                logger.warning("Agent rescan failed: %s", exc)

        # Fallback: queue network scan for IP
        ip = (alert.entities or [None])[1] if alert.entities and len(alert.entities) > 1 else None
        if ip and ip.count(".") == 3:
            try:
                from services.network_scan_service import run_network_scan_job
                job, _ = run_network_scan_job(
                    self.db, tenant_id, ip, requested_by="ai_action_service"
                )
                return ActionResult(
                    "trigger_rescan", True,
                    f"Network rescan queued for {ip}",
                    {"target": ip},
                )
            except Exception as exc:
                logger.warning("Network rescan failed: %s", exc)

        return ActionResult(
            "trigger_rescan", False,
            f"Could not find asset '{asset_name}' to rescan",
        )

    # ------------------------------------------------------------------
    # Action 3: Send Webhook
    # ------------------------------------------------------------------

    def _send_webhook(
        self, alert: AIAlert, tenant_id: str
    ) -> ActionResult:
        """
        POST alert data to CYBERASSETIQ_WEBHOOK_URL if configured.
        Payload is compatible with Slack incoming webhooks and generic
        HTTP webhook receivers (Zapier, Make, Teams, PagerDuty, etc).
        """
        if not WEBHOOK_URL:
            return ActionResult(
                "send_webhook", False,
                "No webhook URL configured (set CYBERASSETIQ_WEBHOOK_URL in .env)",
            )

        mitre = (alert.metadata_json or {}).get("mitre_tactic", "")
        severity_emoji = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🟢",
        }.get((alert.severity or "").lower(), "⚪")

        # Slack-compatible payload (also works as generic JSON webhook)
        payload = {
            "text": f"{severity_emoji} *CyberAssetIQ Alert: {alert.title}*",
            "attachments": [
                {
                    "color": {
                        "critical": "danger",
                        "high":     "warning",
                        "medium":   "warning",
                        "low":      "good",
                    }.get((alert.severity or "").lower(), "#808080"),
                    "fields": [
                        {"title": "Severity",    "value": (alert.severity or "").upper(), "short": True},
                        {"title": "Confidence",  "value": f"{alert.confidence}%",         "short": True},
                        {"title": "MITRE Tactic","value": mitre or "—",                   "short": True},
                        {"title": "Status",      "value": alert.status or "new",          "short": True},
                        {"title": "Summary",     "value": (alert.summary or "")[:300],    "short": False},
                        {"title": "Recommendation", "value": (alert.recommendation or "")[:200], "short": False},
                    ],
                    "footer": f"CyberAssetIQ | tenant: {tenant_id}",
                    "ts": int(time.time()),
                }
            ],
            # Also include raw data for non-Slack receivers
            "cyberassetiq_alert": {
                "id":           alert.id,
                "alert_type":   alert.alert_type,
                "severity":     alert.severity,
                "title":        alert.title,
                "summary":      alert.summary,
                "entities":     alert.entities or [],
                "confidence":   alert.confidence,
                "created_at":   alert.created_at.isoformat() if alert.created_at else None,
                "tenant_id":    tenant_id,
            },
        }

        try:
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                WEBHOOK_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
            logger.info("Webhook sent for alert %d: HTTP %d", alert.id, status)
            return ActionResult(
                "send_webhook", True,
                f"Webhook delivered (HTTP {status})",
                {"webhook_url": WEBHOOK_URL[:40] + "...", "http_status": status},
            )
        except Exception as exc:
            logger.warning("Webhook delivery failed for alert %d: %s", alert.id, exc)
            return ActionResult(
                "send_webhook", False,
                f"Webhook delivery failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_actions_for_alert(self, alert: AIAlert) -> List[str]:
        """Determine which actions to run based on alert severity and type."""
        actions = []

        severity = (alert.severity or "").lower()

        # Always create investigation for critical/high alerts
        if severity in ("critical", "high"):
            actions.append("create_investigation")

        # Trigger rescan for CVE-related or credential alerts
        if alert.alert_type in (
            "credential_exposure", "api_key_exposure",
            "brute_force_success", "external_login",
        ):
            actions.append("trigger_rescan")

        # Send webhook for critical alerts if configured
        if severity == "critical" and WEBHOOK_ENABLED:
            actions.append("send_webhook")

        return actions or ["create_investigation"]
