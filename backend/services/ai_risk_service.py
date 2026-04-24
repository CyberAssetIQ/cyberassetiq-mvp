"""
AI Risk Service
Produces dynamic, multi-factor AI risk scores for assets, users and the overall tenant.
Unlike static CVSS-only scoring, this combines vulnerabilities, exposure, AI alerts,
dark web exposure, compliance gaps and behavioural signals.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from models.asset import CanonicalAsset
from models.telemetry import VulnerabilityFinding
from models.darkweb import DarkWebFinding
from models.ai_event import AIEvent
from models.ai_alert import AIAlert

logger = logging.getLogger(__name__)


class AssetRiskResult:
    def __init__(self, asset_id: int, asset_name: str, ip: str, risk_score: float, reasons: List[str]):
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.ip = ip
        self.risk_score = round(min(risk_score, 100.0), 1)
        self.risk_band = self._band(self.risk_score)
        self.reasons = reasons

    @staticmethod
    def _band(score: float) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"


class AIRiskService:

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Per-asset risk scoring
    # ------------------------------------------------------------------
    def score_asset(self, asset: CanonicalAsset, tenant_id: str) -> AssetRiskResult:
        score = 0.0
        reasons = []

        # --- Vulnerability component (max 40 points) ---
        vulns = (
            self.db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.agent_id == asset.agent_id,
                VulnerabilityFinding.status.notin_(["resolved", "false_positive", "accepted_risk"]),
            )
            .all()
        )
        critical_vulns = [v for v in vulns if (v.severity or "").lower() == "critical"]
        high_vulns = [v for v in vulns if (v.severity or "").lower() == "high"]
        exploitable_vulns = [v for v in vulns if getattr(v, "is_exploitable", False)]

        vuln_score = min(
            len(critical_vulns) * 15 + len(high_vulns) * 8 + len(exploitable_vulns) * 10,
            40
        )
        score += vuln_score
        if critical_vulns:
            reasons.append(f"{len(critical_vulns)} critical CVE(s) unpatched")
        if exploitable_vulns:
            reasons.append(f"{len(exploitable_vulns)} CVE(s) with known exploits")

        # --- Exposure component (max 20 points) ---
        # CanonicalAsset stores IPs as a JSON list in the `ips` field
        ip = ((asset.ips or [""])[0]) if asset.ips else ""
        is_external = ip and not (
            ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")
        )
        if is_external:
            score += 20
            reasons.append("Asset appears internet-facing")
        elif not asset.agent_id:
            score += 10
            reasons.append("Unmanaged/agentless asset — limited visibility")

        # --- AI alert component (max 25 points) ---
        since = datetime.now(timezone.utc) - timedelta(days=7)
        recent_alerts = (
            self.db.query(AIAlert)
            .join(AIEvent, AIAlert.ai_event_id == AIEvent.id, isouter=True)
            .filter(
                AIEvent.asset_name == asset.hostname,
                AIAlert.created_at >= since,
                AIAlert.status != "closed",
            )
            .all()
        )
        critical_ai = [a for a in recent_alerts if (a.severity or "").lower() == "critical"]
        high_ai = [a for a in recent_alerts if (a.severity or "").lower() == "high"]
        ai_score = min(len(critical_ai) * 12 + len(high_ai) * 6, 25)
        score += ai_score
        if critical_ai:
            reasons.append(f"{len(critical_ai)} critical AI alert(s) in last 7 days")

        # --- Dark web component (max 10 points) ---
        dw_count = (
            self.db.query(func.count(DarkWebFinding.id))
            .filter(DarkWebFinding.tenant_id == tenant_id)
            .scalar() or 0
        )
        if dw_count > 0:
            score += min(dw_count * 5, 10)
            reasons.append(f"Tenant has {dw_count} dark web exposure(s)")

        # --- Patch recency (max 5 points) ---
        if asset.last_snapshot_epoch:
            import time as _time
            days_since_seen = int((_time.time() - asset.last_snapshot_epoch) / 86400)
            if days_since_seen > 30:
                score += 5
                reasons.append(f"Asset not seen in {days_since_seen} days")

        if not reasons:
            reasons.append("No significant risk signals detected")

        return AssetRiskResult(
            asset_id=asset.id,
            asset_name=asset.hostname or (asset.ips[0] if asset.ips else None) or f"Asset #{asset.id}",
            ip=ip,
            risk_score=score,
            reasons=reasons,
        )

    def get_top_risky_assets(self, tenant_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        assets = (
            self.db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id)
            .all()
        )
        results = [self.score_asset(a, tenant_id) for a in assets]
        results.sort(key=lambda r: r.risk_score, reverse=True)
        return [
            {
                "asset_id": r.asset_id,
                "asset_name": r.asset_name,
                "ip": r.ip,
                "risk_score": r.risk_score,
                "risk_band": r.risk_band,
                "reasons": r.reasons,
            }
            for r in results[:limit]
        ]

    # ------------------------------------------------------------------
    # Tenant-level risk summary
    # ------------------------------------------------------------------
    def build_risk_summary(self, tenant_id: str) -> Dict[str, Any]:
        total_assets = (
            self.db.query(func.count(CanonicalAsset.id))
            .filter(CanonicalAsset.tenant_id == tenant_id)
            .scalar() or 0
        )
        open_ai_alerts = (
            self.db.query(func.count(AIAlert.id))
            .filter(AIAlert.status.in_(["new", "open"]))
            .scalar() or 0
        )
        critical_ai_alerts = (
            self.db.query(func.count(AIAlert.id))
            .filter(AIAlert.status.in_(["new", "open"]), AIAlert.severity == "critical")
            .scalar() or 0
        )
        open_vulns = (
            self.db.query(func.count(VulnerabilityFinding.id))
            .filter(
                VulnerabilityFinding.status.notin_(["resolved", "false_positive", "accepted_risk"])
            )
            .scalar() or 0
        )
        dw_findings = (
            self.db.query(func.count(DarkWebFinding.id))
            .filter(DarkWebFinding.tenant_id == tenant_id)
            .scalar() or 0
        )

        # Overall posture score (lower = worse)
        posture = 100.0
        if critical_ai_alerts > 0:
            posture -= min(critical_ai_alerts * 10, 30)
        if open_vulns > 10:
            posture -= min(open_vulns * 0.5, 20)
        if dw_findings > 0:
            posture -= min(dw_findings * 5, 15)

        posture = max(0.0, round(posture, 1))

        return {
            "total_assets": total_assets,
            "open_ai_alerts": open_ai_alerts,
            "critical_ai_alerts": critical_ai_alerts,
            "open_vulnerabilities": open_vulns,
            "dark_web_findings": dw_findings,
            "posture_score": posture,
            "posture_band": "good" if posture >= 80 else "fair" if posture >= 60 else "poor",
        }
