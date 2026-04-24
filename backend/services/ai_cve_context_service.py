import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc
from sqlalchemy.orm import Session
from models.telemetry import VulnerabilityFinding
from models.asset import CanonicalAsset
from models.network_extensions import ExposureFinding
from services.ai_provider_service import AIProviderService
from services.ai_redaction_service import redact_text, safe_truncate

logger = logging.getLogger(__name__)

KNOWN_EXPLOITED_PATTERNS = [
    r"CVE-2021-44228", r"CVE-2021-45046", r"CVE-2017-0144", r"CVE-2017-0145",
    r"CVE-2019-0708", r"CVE-2021-34527", r"CVE-2021-26855", r"CVE-2022-30190",
    r"CVE-2022-26134", r"CVE-2023-44487", r"CVE-2023-23397", r"CVE-2024-3400",
    r"log4j", r"log4shell", r"eternalblue", r"bluekeep", r"printnightmare",
]
INTERNET_FACING = {"apache","nginx","iis","httpd","tomcat","openssh","ssh","rdp",
    "exchange","confluence","jira","gitlab","jenkins","wordpress","drupal","vpn","fortinet"}
INTERNAL_ONLY = {"microsoft office","word","excel","powerpoint","outlook","adobe reader",
    "7-zip","winrar","vlc","notepad","chrome","firefox","edge"}
SYSTEM_PROMPT = """You are a senior cybersecurity analyst at CyberAssetIQ specialising in vulnerability assessment for UK SMEs.
Explain whether a CVE is actually dangerous in the customer's specific environment — not just what the CVSS score says.
Be direct and practical. Distinguish theoretical risk (CVSS) from actual risk in this environment.
Always end with 3 numbered remediation steps specific to this software and version.
Write in professional UK English. Keep under 300 words."""


class AICVEContextService:
    def __init__(self, db: Session):
        self.db = db
        self._provider = AIProviderService()

    def explain_finding(self, finding_id: int, tenant_id: str) -> Dict[str, Any]:
        finding = self._get_finding(finding_id, tenant_id)
        if not finding:
            return {"error": "Finding not found"}
        asset = self._get_asset(finding.agent_id, tenant_id)
        exposure = self._get_exposure(asset, tenant_id) if asset else []
        ctx = self._build_context(finding, asset, exposure)
        analysis = self._deterministic_analysis(finding, asset, exposure, ctx)
        result = {
            "finding_id": finding_id, "cve_id": finding.cve_id,
            "software": f"{finding.software_name} {finding.software_version or ''}".strip(),
            "cvss_score": float(finding.cvss_score) if finding.cvss_score else None,
            "severity": finding.severity, "asset": ctx.get("asset_name"),
            "analysis": analysis, "ai_configured": self._provider.is_configured(),
        }
        if self._provider.is_configured():
            result["explanation"] = self._generate_explanation(finding, asset, ctx, analysis)
        else:
            result["explanation"] = self._fallback_explanation(finding, analysis)
        return result

    def batch_prioritise(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        findings = (self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.tenant_id == tenant_id, VulnerabilityFinding.status == "open")
            .order_by(desc(VulnerabilityFinding.cvss_score)).limit(100).all())

        # ── Bulk-load all assets and exposures in 2 queries instead of N×2 ──
        agent_ids = list({f.agent_id for f in findings if f.agent_id})
        assets_by_agent: Dict[str, Any] = {}
        if agent_ids:
            for a in self.db.query(CanonicalAsset).filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.agent_id.in_(agent_ids),
            ).all():
                assets_by_agent[a.agent_id] = a

        asset_ids = [a.id for a in assets_by_agent.values()]
        from collections import defaultdict
        exposures_by_asset: Dict[int, list] = defaultdict(list)
        if asset_ids:
            from models.network_extensions import ExposureFinding as EF
            for e in self.db.query(EF).filter(
                EF.tenant_id == tenant_id,
                EF.asset_id.in_(asset_ids),
            ).limit(500).all():
                exposures_by_asset[e.asset_id].append(e)

        results = []
        for f in findings:
            asset = assets_by_agent.get(f.agent_id)
            exposure = exposures_by_asset.get(asset.id, []) if asset else []
            ctx = self._build_context(f, asset, exposure)
            analysis = self._deterministic_analysis(f, asset, exposure, ctx)
            results.append({
                "finding_id": f.id, "cve_id": f.cve_id,
                "software": f"{f.software_name} {f.software_version or ''}".strip(),
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "severity": f.severity, "asset": ctx.get("asset_name"),
                "adjusted_priority": analysis["adjusted_priority"],
                "priority_reason": analysis["priority_reason"],
                "patch_urgency": analysis["patch_urgency"],
                "patch_urgency_label": analysis["patch_urgency_label"],
                "risk_vs_cvss": analysis["risk_vs_cvss"],
                "risk_label": analysis["risk_label"],
                "adjustments": analysis["adjustments"],
                "has_known_exploit": analysis["has_known_exploit"],
                "internet_exposure_likely": analysis["internet_exposure_likely"],
                "is_rce": analysis["is_rce"],
                "is_priv_esc": analysis["is_priv_esc"],
                "requires_auth": analysis["requires_auth"],
            })
        results.sort(key=lambda x: x["adjusted_priority"], reverse=True)
        return results[:limit]

    def _build_context(self, finding, asset, exposure):
        ctx = {}
        if asset:
            ctx["asset_name"] = asset.hostname or asset.fqdn or finding.agent_id
            ctx["os_family"] = asset.os_family or "Unknown"
            ctx["os_version"] = asset.os_version or "Unknown"
            posture = asset.security_posture_json or {}
            ctx["firewall_enabled"] = posture.get("firewall_enabled")
            ctx["av_installed"] = posture.get("av_installed")
        else:
            ctx["asset_name"] = finding.agent_id
            ctx["os_family"] = "Unknown"
            ctx["os_version"] = "Unknown"
            ctx["firewall_enabled"] = None
            ctx["av_installed"] = None
        desc_lower = (finding.description or "").lower()
        ctx["is_rce"] = any(k in desc_lower for k in ["remote code execution","rce","execute arbitrary"])
        ctx["is_priv_esc"] = any(k in desc_lower for k in ["privilege escalation","elevat"])
        ctx["is_dos"] = any(k in desc_lower for k in ["denial of service","dos","crash"])
        ctx["requires_auth"] = any(k in desc_lower for k in ["authenticated","requires authentication"])
        ctx["requires_local"] = any(k in desc_lower for k in ["local access","physical access"])
        cve_lower = (finding.cve_id or "").lower()
        svc_name = (finding.software_name or "").lower()
        ctx["has_known_exploit"] = any(
            re.search(p, cve_lower, re.I) or re.search(p, svc_name, re.I)
            for p in KNOWN_EXPLOITED_PATTERNS)
        ctx["internet_facing_likely"] = any(s in svc_name for s in INTERNET_FACING)
        ctx["internal_only_likely"] = any(s in svc_name for s in INTERNAL_ONLY)
        return ctx

    def _deterministic_analysis(self, finding, asset, exposure, ctx):
        cvss = float(finding.cvss_score or 0)
        priority = cvss * 10
        adjustments = []
        if ctx["has_known_exploit"]:
            priority = min(100, priority + 20)
            adjustments.append("Known public exploit exists — priority increased")
        if ctx["is_rce"]:
            priority = min(100, priority + 15)
            adjustments.append("Remote code execution — highest impact class")
        if ctx["internet_facing_likely"]:
            priority = min(100, priority + 10)
            adjustments.append("Service is commonly internet-facing")
        if ctx["requires_auth"] and not ctx["has_known_exploit"]:
            priority = max(0, priority - 15)
            adjustments.append("Requires authentication — reduces remote exploitability")
        if ctx["requires_local"]:
            priority = max(0, priority - 20)
            adjustments.append("Requires local access — not remotely exploitable")
        if ctx["internal_only_likely"] and not ctx["has_known_exploit"]:
            priority = max(0, priority - 10)
            adjustments.append("Client software — exploitable via phishing not direct attack")
        if ctx.get("firewall_enabled") is False:
            priority = min(100, priority + 10)
            adjustments.append("No firewall detected on this asset")
        if priority >= 85: urgency, urgency_label = "immediate", "Patch immediately (24-48 hours)"
        elif priority >= 70: urgency, urgency_label = "urgent", "Patch urgently (within 7 days)"
        elif priority >= 50: urgency, urgency_label = "standard", "Patch on next maintenance window"
        elif priority >= 30: urgency, urgency_label = "low", "Schedule for next patch cycle"
        else: urgency, urgency_label = "monitor", "Monitor and patch when convenient"
        if priority >= cvss * 10 + 15: risk_vs_cvss = "higher_than_cvss"; risk_label = f"Real risk HIGHER than CVSS {cvss} suggests"
        elif priority <= cvss * 10 - 15: risk_vs_cvss = "lower_than_cvss"; risk_label = f"Real risk LOWER than CVSS {cvss} suggests"
        else: risk_vs_cvss = "matches_cvss"; risk_label = f"Real risk matches CVSS {cvss}"
        if not adjustments:
            adjustments.append("No environmental factors found to adjust risk")
        return {
            "adjusted_priority": round(priority, 1), "cvss_priority": round(cvss * 10, 1),
            "risk_vs_cvss": risk_vs_cvss, "risk_label": risk_label,
            "patch_urgency": urgency, "patch_urgency_label": urgency_label,
            "priority_reason": adjustments[0], "adjustments": adjustments,
            "has_known_exploit": ctx["has_known_exploit"],
            "internet_exposure_likely": ctx["internet_facing_likely"],
            "is_rce": ctx["is_rce"], "is_priv_esc": ctx["is_priv_esc"],
            "requires_auth": ctx["requires_auth"], "requires_local": ctx["requires_local"],
            "firewall_enabled": ctx.get("firewall_enabled"),
        }

    def _generate_explanation(self, finding, asset, ctx, analysis):
        prompt_ctx = {
            "cve_id": finding.cve_id,
            "software": f"{finding.software_name} {finding.software_version or ''}".strip(),
            "cvss_score": float(finding.cvss_score) if finding.cvss_score else "unknown",
            "severity": finding.severity,
            "description": (finding.description or "")[:400],
            "asset_name": ctx.get("asset_name"), "os": ctx.get("os_family"),
            "firewall": ctx.get("firewall_enabled"), "is_rce": ctx["is_rce"],
            "requires_auth": ctx["requires_auth"], "known_exploit": ctx["has_known_exploit"],
            "internet_facing": ctx["internet_facing_likely"],
            "adjusted_priority": analysis["adjusted_priority"],
            "patch_urgency": analysis["patch_urgency_label"],
            "risk_label": analysis["risk_label"],
        }
        prompt = (f"Explain this CVE to an IT manager at a UK SME.\n\nData:\n{json.dumps(prompt_ctx, default=str)}\n\n"
                  f"Structure: WHAT THIS MEANS, WHY THIS PRIORITY, BUSINESS IMPACT, REMEDIATION (3 steps).")
        try:
            r = self._provider.call(system_prompt=SYSTEM_PROMPT, user_message=prompt, max_tokens=400)
            return r.content.strip()
        except Exception as exc:
            logger.error("CVE explanation error: %s", exc)
            return self._fallback_explanation(finding, analysis)

    def _fallback_explanation(self, finding, analysis):
        lines = [
            f"{finding.cve_id} affects {finding.software_name} {finding.software_version or ''}.",
            f"CVSS: {finding.cvss_score} ({finding.severity}). Adjusted priority: {analysis['adjusted_priority']}/100.",
            f"Recommendation: {analysis['patch_urgency_label']}.",
        ]
        if analysis["has_known_exploit"]: lines.append("WARNING: Known public exploit exists.")
        if analysis["is_rce"]: lines.append("This vulnerability allows remote code execution.")
        return "\n".join(lines)

    def _get_finding(self, finding_id, tenant_id):
        return self.db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.id == finding_id,
            VulnerabilityFinding.tenant_id == tenant_id).first()

    def _get_asset(self, agent_id, tenant_id):
        return self.db.query(CanonicalAsset).filter(
            CanonicalAsset.agent_id == agent_id,
            CanonicalAsset.tenant_id == tenant_id).first()

    def _get_exposure(self, asset, tenant_id):
        if not asset: return []
        return self.db.query(ExposureFinding).filter(
            ExposureFinding.tenant_id == tenant_id,
            ExposureFinding.asset_id == asset.id).limit(10).all()
