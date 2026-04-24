"""
AI Correlation Service
Joins AI events and alerts into attack chains and correlated incidents.
Enriches correlations with asset, vulnerability, and dark web context.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from models.ai_event import AIEvent
from models.ai_alert import AIAlert
from models.ai_correlation import AICorrelation
from models.asset import CanonicalAsset
from models.telemetry import VulnerabilityFinding
from services.ai_mitre_service import AIMitreService

logger = logging.getLogger(__name__)
_mitre = AIMitreService()


class AICorrelationService:

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Main entry: run all correlation passes
    # ------------------------------------------------------------------
    def run_correlation_pass(self, tenant_id: str, lookback_hours: int = 4) -> List[AICorrelation]:
        """
        Run all correlation rules against recent alerts and events.
        Returns newly created correlations.
        """
        created = []
        since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

        created += self._correlate_brute_force_chains(tenant_id, since)
        created += self._correlate_impossible_travel(tenant_id, since)
        created += self._correlate_attack_chains(tenant_id, since)

        if created:
            try:
                self.db.commit()
            except Exception as ex:
                logger.error("Correlation commit failed: %s", ex)
                self.db.rollback()

        return created

    # ------------------------------------------------------------------
    # Rule: brute force → success → post-access
    # ------------------------------------------------------------------
    def _correlate_brute_force_chains(
        self, tenant_id: str, since: datetime
    ) -> List[AICorrelation]:
        results = []

        bf_alerts = (
            self.db.query(AIAlert)
            .filter(
                AIAlert.alert_type.in_(["brute_force_success", "brute_force"]),
                AIAlert.created_at >= since,
                AIAlert.status != "false_positive",
            )
            .all()
        )

        for alert in bf_alerts:
            # Check if already correlated
            existing = (
                self.db.query(AICorrelation)
                .filter(
                    AICorrelation.correlation_type == "brute_force_chain",
                    AICorrelation.alert_refs_json.contains([alert.id]),
                )
                .first()
            )
            if existing:
                continue

            asset_context = self._get_asset_context(alert)
            vuln_context = self._get_vuln_context(alert)
            risk_score = 85.0 + (10.0 if vuln_context else 0.0)

            chain = [
                {"step": 1, "event": "Repeated failed login attempts", "tactic": "Credential Access"},
                {"step": 2, "event": "Successful login after brute force", "tactic": "Initial Access"},
            ]
            if asset_context and asset_context.get("critical_vulns"):
                chain.append({"step": 3, "event": f"Target has {asset_context['critical_vulns']} critical CVE(s)", "tactic": "Exploitation"})

            tactic, tid, tname = _mitre.map_detection("brute_force_success")
            corr = AICorrelation(
                tenant_id=tenant_id,
                correlation_type="brute_force_chain",
                title=f"Credential Brute Force Chain — {alert.entities[0] if alert.entities else 'Unknown Host'}",
                summary=(
                    f"Brute force attack with successful authentication detected. "
                    + (f"Target has {asset_context['critical_vulns']} critical vulnerabilities." if asset_context and asset_context.get('critical_vulns') else "")
                ),
                status="open",
                confidence_score=0.88,
                risk_score=round(min(risk_score, 100.0), 1),
                asset_name=alert.entities[0] if alert.entities else None,
                ip_address=alert.entities[1] if alert.entities and len(alert.entities) > 1 else None,
                alert_refs_json=[alert.id],
                attack_chain_json=chain,
                mitre_tactic=tactic,
                mitre_technique=tid,
                mitre_map_json=[{"tactic": tactic, "technique": tid, "technique_name": tname}],
            )
            self.db.add(corr)
            results.append(corr)

        return results

    # ------------------------------------------------------------------
    # Rule: impossible travel (same user, two distant IPs, short window)
    # ------------------------------------------------------------------
    def _correlate_impossible_travel(
        self, tenant_id: str, since: datetime
    ) -> List[AICorrelation]:
        results = []

        success_events = (
            self.db.query(AIEvent)
            .filter(
                AIEvent.event_type == "login_success",
                AIEvent.created_at >= since,
            )
            .all()
        )

        # Group by hostname
        by_host: Dict[str, List[AIEvent]] = {}
        for e in success_events:
            key = e.hostname or e.ip_address or "unknown"
            by_host.setdefault(key, []).append(e)

        for host, events in by_host.items():
            if len(events) < 2:
                continue

            unique_ips = list(set(e.ip_address for e in events if e.ip_address))
            external_ips = [ip for ip in unique_ips if ip and not self._is_internal(ip)]

            if len(external_ips) < 2:
                continue

            # Two different external source IPs within the window = impossible travel
            tactic, tid, tname = _mitre.map_detection("impossible_travel")
            corr = AICorrelation(
                tenant_id=tenant_id,
                correlation_type="impossible_travel",
                title=f"Impossible Travel — {host}",
                summary=(
                    f"User or service on {host} authenticated from {len(external_ips)} distinct external locations "
                    f"within {int((since - datetime.now(timezone.utc)).total_seconds() / -3600)} hours. "
                    f"Source IPs: {', '.join(external_ips[:3])}."
                ),
                status="open",
                confidence_score=0.82,
                risk_score=75.0,
                asset_name=host,
                event_refs_json=[e.id for e in events],
                attack_chain_json=[
                    {"step": 1, "event": f"Login from {external_ips[0]}", "tactic": "Initial Access"},
                    {"step": 2, "event": f"Login from {external_ips[1]}", "tactic": "Initial Access"},
                    {"step": 3, "event": "Geographically impossible travel — possible credential theft", "tactic": "Credential Access"},
                ],
                mitre_tactic=tactic,
                mitre_technique=tid,
                mitre_map_json=[{"tactic": tactic, "technique": tid, "technique_name": tname}],
            )
            self.db.add(corr)
            results.append(corr)

        return results

    # ------------------------------------------------------------------
    # Rule: multi-stage attack chain (CVE + external login + sensitive action)
    # ------------------------------------------------------------------
    def _correlate_attack_chains(
        self, tenant_id: str, since: datetime
    ) -> List[AICorrelation]:
        results = []

        high_alerts = (
            self.db.query(AIAlert)
            .filter(
                AIAlert.severity.in_(["critical", "high"]),
                AIAlert.created_at >= since,
                AIAlert.alert_type.notin_(["brute_force_chain", "impossible_travel"]),
            )
            .all()
        )

        if len(high_alerts) < 2:
            return results

        # Simple: group multiple high/critical alerts by overlapping entities
        entity_map: Dict[str, List[AIAlert]] = {}
        for a in high_alerts:
            for entity in (a.entities or []):
                entity_map.setdefault(entity, []).append(a)

        for entity, entity_alerts in entity_map.items():
            if len(entity_alerts) < 2:
                continue

            alert_types = list(set(a.alert_type for a in entity_alerts))
            risk_score = min(65.0 + len(entity_alerts) * 5.0, 100.0)

            tactic, tid, tname = _mitre.map_detection("attack_chain")
            chain = [
                {"step": i + 1, "event": a.title, "tactic": (a.metadata_json or {}).get("mitre_tactic", "Unknown")}
                for i, a in enumerate(sorted(entity_alerts, key=lambda x: x.created_at))
            ]

            corr = AICorrelation(
                tenant_id=tenant_id,
                correlation_type="multi_stage_attack",
                title=f"Multi-Stage Attack Chain — {entity}",
                summary=(
                    f"{len(entity_alerts)} correlated security alerts on the same entity ({entity}): "
                    + ", ".join(alert_types[:4]) + "."
                ),
                status="open",
                confidence_score=0.75,
                risk_score=round(risk_score, 1),
                asset_name=entity,
                alert_refs_json=[a.id for a in entity_alerts],
                attack_chain_json=chain,
                mitre_tactic=tactic,
                mitre_technique=tid,
                mitre_map_json=[{"tactic": tactic, "technique": tid, "technique_name": tname}],
            )
            self.db.add(corr)
            results.append(corr)

        return results

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------
    def _get_asset_context(self, alert: AIAlert) -> Optional[Dict[str, Any]]:
        if not alert.entities:
            return None
        hostname = alert.entities[0]
        asset = (
            self.db.query(CanonicalAsset)
            .filter(CanonicalAsset.hostname == hostname)
            .first()
        )
        if not asset:
            return None
        vulns = (
            self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.agent_id == asset.agent_id)
            .all()
        )
        critical = sum(1 for v in vulns if (v.severity or "").lower() == "critical")
        return {"hostname": hostname, "critical_vulns": critical, "total_vulns": len(vulns)}

    def _get_vuln_context(self, alert: AIAlert) -> bool:
        ctx = self._get_asset_context(alert)
        return bool(ctx and ctx.get("critical_vulns", 0) > 0)

    def _is_internal(self, ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
            or ip in ("127.0.0.1", "::1")
        )
