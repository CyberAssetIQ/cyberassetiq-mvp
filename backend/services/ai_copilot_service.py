"""
AI Copilot Service  (v2 — real LLM)
Answers natural-language questions grounded entirely in CyberAssetIQ platform data.
Uses Anthropic Claude (default) or OpenAI via ai_provider_service.py.
Secrets are redacted before any LLM call via ai_redaction_service.py.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

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

SYSTEM_PROMPT = """You are the CyberAssetIQ AI Security Copilot — a professional cyber asset intelligence analyst embedded in a UK SME security platform.

Your job is to answer questions from security teams and IT managers based ONLY on the structured CyberAssetIQ platform data provided to you in each query.

Strict rules:
1. Only use information from the provided context. Never invent assets, alerts, CVEs, users, or events not present.
2. Write in professional UK English. Be direct and concise.
3. Distinguish facts from inferences. Use "may indicate", "likely", or "consistent with" for inferences.
4. If context is insufficient to answer, say so clearly and suggest what data would help.
5. Always end with 3 specific, prioritised recommended actions.
6. When relevant, mention MITRE ATT&CK tactic/technique from the provided mapping only.
7. Never mention generic security advice unrelated to the specific context provided.
8. Maximum response length: 350 words unless a detailed report is explicitly requested.

Response structure:
- Direct answer to the question (1-2 sentences)
- Key evidence from the platform data (up to 5 bullet points as prose)
- Business or security impact
- 3 recommended next actions (numbered, specific)
- Confidence note if evidence is limited"""


class AICopilotService:

    def __init__(self, db: Session):
        self.db = db
        self._provider = AIProviderService()

    def ask(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point. Builds grounded context from platform data,
        calls LLM, and returns structured response.
        """
        prompt = (prompt or "").strip()
        if not prompt:
            return {
                "answer": "Please provide a question for the AI Copilot.",
                "sources": [],
                "suggested_actions": [
                    "Ask: Which assets are highest risk right now?",
                    "Ask: Summarise today's security alerts.",
                    "Ask: Which CVEs should I patch first?",
                ],
            }

        # Try rule-based fast path first (no LLM cost)
        fast = self._fast_path(prompt)
        if fast:
            return fast

        # Build full platform context
        platform_context = self._build_platform_context(prompt)

        # Check if LLM is available
        if not self._provider.is_configured():
            return self._fallback_response(prompt, platform_context)

        # Call LLM
        user_message = self._compose_user_message(prompt, platform_context)
        try:
            response = self._provider.call(
                system_prompt=SYSTEM_PROMPT,
                user_message=redact_text(user_message),
                max_tokens=600,
            )
            answer = response.content.strip()
        except Exception as exc:
            logger.error("Copilot LLM call failed: %s", exc)
            answer = f"AI Copilot temporarily unavailable: {exc}. Here is a data summary:\n\n{self._data_summary(platform_context)}"

        return {
            "answer": answer,
            "sources": platform_context.get("sources", []),
            "suggested_actions": self._suggest_actions(prompt),
            "llm_model": self._provider.model_name(),
            "context_tokens": len(user_message) // 4,  # rough estimate
        }

    # ------------------------------------------------------------------
    # Fast-path responses (no LLM cost for simple queries)
    # ------------------------------------------------------------------

    def _fast_path(self, prompt: str) -> Optional[Dict[str, Any]]:
        pl = prompt.lower()

        if "help" in pl or "what can you" in pl or "example" in pl:
            return {
                "answer": (
                    "I can answer questions about your assets, vulnerabilities, alerts, compliance status, "
                    "and dark web exposure. Try asking:\n"
                    "- Which assets are highest risk right now?\n"
                    "- Summarise today's security alerts.\n"
                    "- Which CVEs should I patch first?\n"
                    "- Are there signs of account compromise?\n"
                    "- What is our current compliance posture?\n"
                    "- Which users or assets show unusual behaviour?"
                ),
                "sources": [],
                "suggested_actions": [
                    "Ask about your highest risk assets",
                    "Ask for a CVE remediation priority",
                    "Ask about recent AI alerts",
                ],
            }

        return None

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_platform_context(self, prompt: str) -> Dict[str, Any]:
        since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        since_7d = datetime.now(timezone.utc) - timedelta(days=7)
        pl = prompt.lower()

        ctx: Dict[str, Any] = {"sources": []}

        # Always include alert summary
        recent_alerts = (
            self.db.query(AIAlert)
            .order_by(desc(AIAlert.created_at))
            .limit(15)
            .all()
        )
        ctx["recent_alerts"] = [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "type": a.alert_type,
                "confidence": a.confidence,
                "status": a.status,
                "entities": a.entities or [],
                "summary": safe_truncate(a.summary or "", 200),
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in recent_alerts
        ]
        if recent_alerts:
            ctx["sources"].append({"type": "ai_alerts", "count": len(recent_alerts)})

        # Asset context
        if any(kw in pl for kw in ["asset", "host", "server", "device", "risk", "highest", "top"]):
            assets = (
                self.db.query(CanonicalAsset)
                .order_by(desc(CanonicalAsset.id))
                .limit(10)
                .all()
            )
            ctx["top_assets"] = [
                {
                    "name": a.hostname or a.agent_id,
                    "ip": (a.ips or [None])[0] if a.ips else None,
                    "os": getattr(a, "os_family", None),
                    "risk_score": 0,
                    "risk_level": "unknown",
                    "open_cves": 0,
                    "compliance_score": None,
                }
                for a in assets
            ]
            if assets:
                ctx["sources"].append({"type": "assets", "count": len(assets)})

        # CVE/vulnerability context
        if any(kw in pl for kw in ["cve", "vuln", "patch", "critical", "exploit", "software"]):
            vulns = (
                self.db.query(VulnerabilityFinding)
                .filter(VulnerabilityFinding.status == "open")
                .order_by(desc(VulnerabilityFinding.cvss_score))
                .limit(15)
                .all()
            )
            ctx["open_vulnerabilities"] = [
                {
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "cvss": float(v.cvss_score) if v.cvss_score else None,
                    "software": v.software_name,
                    "version": v.software_version,
                    "agent_id": v.agent_id,
                }
                for v in vulns
            ]
            ctx["vuln_summary"] = {
                "total_open": len(vulns),
                "critical": sum(1 for v in vulns if v.severity == "critical"),
                "high": sum(1 for v in vulns if v.severity == "high"),
            }
            if vulns:
                ctx["sources"].append({"type": "vulnerabilities", "count": len(vulns)})

        # Dark web context
        if any(kw in pl for kw in ["dark web", "darkweb", "leak", "breach", "credential", "exposure"]):
            dw = (
                self.db.query(DarkWebFinding)
                .order_by(desc(DarkWebFinding.created_at))
                .limit(10)
                .all()
            )
            ctx["dark_web_findings"] = [
                {
                    "matched_value": getattr(f, "matched_value", None),
                    "severity": getattr(f, "severity", None),
                    "source": getattr(f, "source", None),
                    "found_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in dw
            ]
            if dw:
                ctx["sources"].append({"type": "dark_web", "count": len(dw)})

        # AI events context
        recent_events = (
            self.db.query(AIEvent)
            .order_by(desc(AIEvent.created_at))
            .limit(20)
            .all()
        )
        ctx["recent_events"] = [
            {
                "title": e.title,
                "type": e.event_type,
                "severity": e.severity,
                "source": e.source,
                "asset": e.asset_name or e.hostname or e.ip_address,
                "risk_score": e.risk_score,
                "tags": e.tags or [],
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in recent_events
        ]
        if recent_events:
            ctx["sources"].append({"type": "ai_events", "count": len(recent_events)})

        return ctx

    # ------------------------------------------------------------------
    # LLM message composer
    # ------------------------------------------------------------------

    def _compose_user_message(self, prompt: str, ctx: Dict[str, Any]) -> str:
        ctx_safe = redact_dict({k: v for k, v in ctx.items() if k != "sources"})
        ctx_json = safe_truncate(json.dumps(ctx_safe, default=str, indent=2), max_chars=6000)
        return (
            f"User question: {prompt}\n\n"
            f"Platform context (CyberAssetIQ live data):\n{ctx_json}\n\n"
            f"Answer the user's question using only the platform context above."
        )

    # ------------------------------------------------------------------
    # Fallback (no LLM configured)
    # ------------------------------------------------------------------

    def _fallback_response(self, prompt: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        summary = self._data_summary(ctx)
        return {
            "answer": (
                f"AI Copilot LLM not configured — showing data summary.\n\n"
                f"To enable AI responses, add ANTHROPIC_API_KEY to your .env file and restart the backend.\n\n"
                f"Data relevant to your query:\n\n{summary}"
            ),
            "sources": ctx.get("sources", []),
            "suggested_actions": self._suggest_actions(prompt),
        }

    def _data_summary(self, ctx: Dict[str, Any]) -> str:
        lines = []
        if ctx.get("recent_alerts"):
            c = len(ctx["recent_alerts"])
            crit = sum(1 for a in ctx["recent_alerts"] if (a.get("severity") or "").lower() == "critical")
            lines.append(f"AI Alerts: {c} total, {crit} critical.")
        if ctx.get("top_assets"):
            top = ctx["top_assets"][0]
            lines.append(f"Highest risk asset: {top.get('name')} (risk score {top.get('risk_score')}).")
        if ctx.get("vuln_summary"):
            v = ctx["vuln_summary"]
            lines.append(f"Open CVEs: {v.get('total_open')} total, {v.get('critical')} critical.")
        if ctx.get("dark_web_findings"):
            lines.append(f"Dark web findings: {len(ctx['dark_web_findings'])} matched.")
        return "\n".join(lines) if lines else "No relevant platform data found."

    def _suggest_actions(self, prompt: str) -> List[str]:
        pl = prompt.lower()
        if "risk" in pl or "asset" in pl:
            return ["Review Risk Intelligence", "Open top asset detail", "Trigger a CVE scan"]
        if "alert" in pl:
            return ["Open AI Alerts panel", "Investigate top alert", "Check Attack Timeline"]
        if "cve" in pl or "patch" in pl or "vuln" in pl:
            return ["Open Vulnerabilities tab", "Sort by CVSS score", "Patch critical CVEs first"]
        if "compliance" in pl or "cyber essential" in pl:
            return ["Open Compliance tab", "Run CE assessment", "Review failing controls"]
        return [
            "Ask about highest risk assets",
            "Ask for today's top CVEs",
            "Ask about recent AI alerts",
        ]
