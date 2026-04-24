"""
AI Summary Service
Generates LLM-powered summaries for incidents, daily briefs, and asset risk explanations.
Uses ai_provider_service.py as the LLM backend and ai_redaction_service.py for safety.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

from models.ai_event import AIEvent
from models.ai_alert import AIAlert
from models.asset import CanonicalAsset
from models.telemetry import VulnerabilityFinding
from models.darkweb import DarkWebFinding
from services.ai_provider_service import AIProviderService
from services.ai_redaction_service import redact_dict, redact_text, safe_truncate
from services.ai_mitre_service import AIMitreService

logger = logging.getLogger(__name__)
_mitre = AIMitreService()

SYSTEM_PROMPT = """You are the CyberAssetIQ AI Security Intelligence Analyst.

Your role is to analyse structured security context from CyberAssetIQ and respond as a professional UK-based security analyst.

Rules you must always follow:
- Only use information from the structured context provided. Never invent assets, incidents, users, CVEs, or events not present in the context.
- Write in professional UK English. Be concise and direct.
- Distinguish clearly between confirmed facts, correlated inferences, and low-confidence signals.
- If evidence is limited or ambiguous, say so plainly.
- Never claim guaranteed zero-day prevention. Use language like "likely", "may indicate", or "consistent with" for inferences.
- Prioritise operational usefulness: what matters most, and what should be done first.
- Always include concrete next actions.
- When mapping to MITRE ATT&CK, only use the provided mappings — do not invent technique IDs.

Format:
- Use plain prose. No markdown. No bullet asterisks.
- Keep responses under 400 words unless asked for a detailed report.
- Start with the direct answer or finding, then supporting evidence, then recommended actions."""


class AISummaryService:

    def __init__(self, db: Session):
        self.db = db
        self._provider = AIProviderService()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summarise_alert(self, alert_id: int) -> str:
        """Generate a plain-English explanation of a specific AI alert."""
        alert = self.db.query(AIAlert).filter(AIAlert.id == alert_id).first()
        if not alert:
            return "Alert not found."

        context = self._build_alert_context(alert)
        prompt = (
            f"Explain this security alert to a security analyst.\n\n"
            f"Alert context:\n{json.dumps(context, default=str)}\n\n"
            f"Include: what happened, why it matters, likely cause, business impact, "
            f"and 3 specific next actions. Mention MITRE tactic if relevant."
        )
        return self._call_llm(prompt)

    def summarise_asset_risk(self, asset_id: int) -> str:
        """Generate a risk explanation for a specific asset.
        Checks CanonicalAsset first, then NetworkDiscoveredAsset."""
        from models.network import NetworkDiscoveredAsset

        asset = self.db.query(CanonicalAsset).filter(CanonicalAsset.id == asset_id).first()
        if asset:
            context = self._build_asset_context(asset)
        else:
            net = self.db.query(NetworkDiscoveredAsset).filter(
                NetworkDiscoveredAsset.id == asset_id
            ).first()
            if not net:
                return "Asset not found."
            context = self._build_network_asset_context(net)

        prompt = (
            f"Explain why this asset is at risk and what should be done.\n\n"
            f"Asset context:\n{json.dumps(context, default=str)}\n\n"
            f"Cover: risk factors, most critical issues, remediation priority, and estimated effort."
        )
        return self._call_llm(prompt)

    def generate_daily_brief(self) -> Dict[str, Any]:
        """Generate an LLM-powered daily security briefing."""
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        recent_alerts = (
            self.db.query(AIAlert)
            .filter(AIAlert.created_at >= since)
            .order_by(desc(AIAlert.created_at))
            .limit(20)
            .all()
        )
        recent_events = (
            self.db.query(AIEvent)
            .filter(AIEvent.created_at >= since)
            .order_by(desc(AIEvent.created_at))
            .limit(30)
            .all()
        )
        top_vulns = (
            self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.status == "open", VulnerabilityFinding.severity.in_(["critical", "high"]))
            .order_by(desc(VulnerabilityFinding.cvss_score))
            .limit(5)
            .all()
        )

        metrics = {
            "alerts_24h": len(recent_alerts),
            "critical_alerts": sum(1 for a in recent_alerts if (a.severity or "").lower() == "critical"),
            "high_alerts": sum(1 for a in recent_alerts if (a.severity or "").lower() == "high"),
            "events_24h": len(recent_events),
            "open_critical_cves": len(top_vulns),
        }

        if not recent_alerts and not recent_events:
            return {
                "llm_summary": "No security events recorded in the last 24 hours. Continue monitoring.",
                "metrics": metrics,
                "top_alerts": [],
                "top_vulns": [],
            }

        context_dict = {
            "period": "last 24 hours",
            "alert_count": len(recent_alerts),
            "event_count": len(recent_events),
            "alerts": [
                {
                    "title": a.title,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "type": a.alert_type,
                    "entities": a.entities or [],
                }
                for a in recent_alerts[:10]
            ],
            "high_risk_events": [
                {
                    "title": e.title,
                    "severity": e.severity,
                    "asset": e.asset_name or e.hostname or e.ip_address,
                    "source": e.source,
                    "risk_score": e.risk_score,
                }
                for e in sorted(recent_events, key=lambda x: x.risk_score or 0, reverse=True)[:5]
            ],
            "critical_cves": [
                {
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "cvss": float(v.cvss_score) if v.cvss_score else None,
                    "software": v.software_name,
                }
                for v in top_vulns
            ],
        }

        prompt = (
            f"Generate a concise daily security brief for the last 24 hours.\n\n"
            f"Security context:\n{json.dumps(context_dict, default=str)}\n\n"
            f"Cover: overall security posture, top 3 concerns, assets needing immediate attention, "
            f"and the 3 most important actions for today. Keep it under 300 words."
        )

        llm_summary = self._call_llm(prompt)

        return {
            "llm_summary": llm_summary,
            "metrics": metrics,
            "top_alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in recent_alerts[:5]
            ],
            "top_vulns": [
                {
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "cvss": float(v.cvss_score) if v.cvss_score else None,
                    "software": v.software_name,
                }
                for v in top_vulns
            ],
        }

    def summarise_investigation(self, alert_ids: List[int]) -> Dict[str, Any]:
        """Build a full investigation summary across multiple correlated alerts."""
        alerts = self.db.query(AIAlert).filter(AIAlert.id.in_(alert_ids)).all()
        if not alerts:
            return {"summary": "No alerts found for investigation."}

        asset_ids = list({a.entities[0] if a.entities else None for a in alerts if a.entities})
        context_dict = {
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "type": a.alert_type,
                    "confidence": a.confidence,
                    "summary": safe_truncate(a.summary or "", 400),
                    "recommendation": a.recommendation,
                    "entities": a.entities or [],
                    "evidence": redact_dict(a.evidence or {}),
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
        }

        prompt = (
            f"Generate a structured security investigation report for these correlated alerts.\n\n"
            f"Context:\n{json.dumps(context_dict, default=str)}\n\n"
            f"Structure your response as:\n"
            f"EXECUTIVE SUMMARY (2-3 sentences for management)\n"
            f"TECHNICAL ANALYSIS (what happened, attack sequence, evidence quality)\n"
            f"IMPACT ASSESSMENT (affected assets, data, services)\n"
            f"MITRE ATT&CK MAPPING (tactics and techniques observed)\n"
            f"RECOMMENDED ACTIONS (ordered by priority, specific steps)"
        )

        llm_text = self._call_llm(prompt, max_tokens=800)

        return {
            "alert_count": len(alerts),
            "alert_ids": alert_ids,
            "investigation_summary": llm_text,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Context builders
    # ------------------------------------------------------------------

    def _build_alert_context(self, alert: AIAlert) -> dict:
        ctx: Dict[str, Any] = {
            "alert_id": alert.id,
            "type": alert.alert_type,
            "title": alert.title,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "status": alert.status,
            "summary": safe_truncate(alert.summary or "", 600),
            "recommendation": alert.recommendation,
            "entities": alert.entities or [],
            "evidence": redact_dict(alert.evidence or {}),
        }
        mitre = _mitre.map_detection(alert.alert_type or "")
        if mitre:
            ctx["mitre"] = {
                "tactic": mitre[0],
                "technique_id": mitre[1],
                "technique_name": mitre[2],
            }
        return ctx

    def _build_asset_context(self, asset: CanonicalAsset) -> dict:
        vulns = (
            self.db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.agent_id == asset.agent_id,
                VulnerabilityFinding.status == "open",
            )
            .order_by(desc(VulnerabilityFinding.cvss_score))
            .limit(10)
            .all()
        )
        dw = (
            self.db.query(DarkWebFinding)
            .filter(DarkWebFinding.asset_id == asset.id)
            .limit(5)
            .all()
        )
        return {
            "asset_name": asset.hostname or asset.agent_id,
            "ip": (asset.ips or [None])[0] if asset.ips else None,
            "os": getattr(asset, "os_family", None),
            "risk_score": None,
            "risk_level": None,
            "open_cves": len(vulns),
            "top_cves": [
                {"cve_id": v.cve_id, "severity": v.severity, "cvss": float(v.cvss_score) if v.cvss_score else None}
                for v in vulns[:5]
            ],
            "dark_web_findings": len(dw),
        }

    def _build_network_asset_context(self, asset) -> dict:
        """Build context dict for a NetworkDiscoveredAsset."""
        open_ports = asset.open_ports or []
        port_list  = [f"{p.get('port')}/{p.get('service','?')}" for p in open_ports[:8]]
        risk_factors = asset.risk_factors or []
        return {
            "asset_name":    asset.hostname or asset.netbios_name or asset.ip_address,
            "ip":            asset.ip_address,
            "os":            asset.os_guess or "Unknown",
            "device_type":   asset.device_type or "Unknown",
            "risk_score":    float(asset.risk_score or 0),
            "risk_level":    asset.risk_level or "unknown",
            "managed":       asset.managed,
            "agent_installed": asset.agent_installed,
            "is_internet_facing": asset.is_internet_facing,
            "open_ports":    port_list,
            "risk_factors":  risk_factors,
            "cve_count":     asset.cve_count or 0,
            "critical_cves": asset.critical_cve_count or 0,
            "high_cves":     asset.high_cve_count or 0,
            "asset_type":    "network_discovered",
        }

    # ------------------------------------------------------------------
    # LLM wrapper
    # ------------------------------------------------------------------

    def _call_llm(self, user_message: str, max_tokens: int = 500) -> str:
        if not self._provider.is_configured():
            return (
                "AI summary unavailable: no LLM provider configured. "
                "Add ANTHROPIC_API_KEY to your .env file and restart the backend."
            )
        try:
            response = self._provider.call(
                system_prompt=SYSTEM_PROMPT,
                user_message=redact_text(user_message),
                max_tokens=max_tokens,
            )
            return response.content.strip()
        except Exception as exc:
            logger.error("LLM call failed in AISummaryService: %s", exc)
            return f"AI summary temporarily unavailable: {exc}"
