"""
caf_mapping_service.py

NCSC Cyber Assessment Framework (CAF) Mapping Engine.
Maps CyberAssetIQ platform data to all 14 CAF principles across 4 objectives.

CAF Reference (NCSC, current version):
  Objective A: Managing security risk
    A.1  Governance
    A.2  Risk management
    A.3  Asset management
    A.4  Supply chain
  Objective B: Protecting against cyber attack
    B.1  Service protection policies and processes
    B.2  Identity and access control
    B.3  Data security
    B.4  System security
    B.5  Resilient networks and systems
    B.6  Staff awareness and training
  Objective C: Detecting cyber security events
    C.1  Security monitoring
    C.2  Proactive security event discovery
  Objective D: Minimising the impact of cyber security incidents
    D.1  Response and recovery planning
    D.2  Improvements

Each principle is scored: ACHIEVED | PARTIALLY_ACHIEVED | NOT_ACHIEVED | NOT_ASSESSED
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

FRAMEWORK_NAME = "NCSC Cyber Assessment Framework (CAF)"
CAF_VERSION    = "CAF v3.2"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CAFPrinciple:
    principle_id:   str    # e.g. "A.1"
    principle_name: str
    objective:      str    # A | B | C | D
    objective_name: str
    status:         str    # ACHIEVED | PARTIALLY_ACHIEVED | NOT_ACHIEVED | NOT_ASSESSED
    score:          float  # 0.0 – 1.0
    contributing_indicators: list[str]
    gaps:           list[str]
    guidance:       list[str] = field(default_factory=list)


@dataclass
class CAFReport:
    tenant_id:    str
    framework:    str
    assessed_at:  str
    objectives:   dict[str, dict]  # A/B/C/D → {score, status, principles}
    overall_score: float
    overall_status: str
    principle_count: int
    achieved_count:  int
    partial_count:   int
    not_achieved_count: int
    top_gaps:       list[str]
    as_posture_domains: list[dict]  # formatted for posture record controls_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _caf_status(score: float) -> str:
    if score >= 0.80:
        return "ACHIEVED"
    if score >= 0.45:
        return "PARTIALLY_ACHIEVED"
    return "NOT_ACHIEVED"


def _score_from_db(db: Session, tenant_id: str) -> dict[str, Any]:
    """Pull aggregated platform metrics once for all principle evaluations."""
    from models.asset import CanonicalAsset
    from models.telemetry import VulnerabilityFinding
    from models.darkweb import DarkWebFinding
    from models.drift import AssetDriftEvent

    asset_count = db.query(func.count(CanonicalAsset.id)).filter(
        CanonicalAsset.tenant_id == tenant_id
    ).scalar() or 0

    managed_count = db.query(func.count(CanonicalAsset.id)).filter(
        CanonicalAsset.tenant_id == tenant_id,
        CanonicalAsset.agent_id.isnot(None),
    ).scalar() or 0

    critical_vulns = db.query(func.count(VulnerabilityFinding.id)).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.severity == "critical",
        VulnerabilityFinding.status == "open",
    ).scalar() or 0

    high_vulns = db.query(func.count(VulnerabilityFinding.id)).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.severity == "high",
        VulnerabilityFinding.status == "open",
    ).scalar() or 0

    darkweb = db.query(func.count(DarkWebFinding.id)).filter(
        DarkWebFinding.tenant_id == tenant_id,
        DarkWebFinding.status == "active",
    ).scalar() or 0

    drift = db.query(func.count(AssetDriftEvent.id)).filter(
        AssetDriftEvent.tenant_id == tenant_id,
        AssetDriftEvent.status == "open",
    ).scalar() or 0

    # Pull notification config as proxy for monitoring
    notif_active = 0
    try:
        from models.notification import NotificationConfig
        notif_active = db.query(func.count(NotificationConfig.id)).filter(
            NotificationConfig.tenant_id == tenant_id,
            NotificationConfig.is_active == True,
        ).scalar() or 0
    except Exception:
        pass

    # Supply chain
    supply_chain_registered = 0
    try:
        from models.supply_chain import SupplierRelationship
        supply_chain_registered = db.query(func.count(SupplierRelationship.id)).filter(
            SupplierRelationship.supplier_tenant_id == tenant_id,
        ).scalar() or 0
    except Exception:
        pass

    # Compliance score
    compliance_score = 0.0
    try:
        from models.compliance_run import ComplianceRun
        latest_run = (
            db.query(ComplianceRun)
            .filter(ComplianceRun.tenant_id == tenant_id)
            .order_by(ComplianceRun.id.desc())
            .first()
        )
        if latest_run:
            compliance_score = (latest_run.tenant_overall_score or 0) / 100.0
    except Exception:
        pass

    return {
        "asset_count": asset_count,
        "managed_count": managed_count,
        "managed_ratio": managed_count / asset_count if asset_count else 0,
        "critical_vulns": critical_vulns,
        "high_vulns": high_vulns,
        "darkweb_active": darkweb,
        "drift_open": drift,
        "notif_active": notif_active,
        "supply_chain_registered": supply_chain_registered,
        "compliance_score": compliance_score,
    }


# ---------------------------------------------------------------------------
# Objective A: Managing security risk
# ---------------------------------------------------------------------------

def _a1_governance(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.5  # Governance requires human process — start partial

    if metrics["asset_count"] > 0:
        indicators.append(f"{metrics['asset_count']} assets in managed inventory")
        score += 0.1
    if metrics["compliance_score"] > 0:
        indicators.append(f"CE compliance programme active (score: {round(metrics['compliance_score']*100)}%)")
        score += 0.15

    gaps.append("Governance documentation (policies, risk appetite statement) requires human verification — CyberAssetIQ provides the technical evidence layer.")
    guidance.append("Maintain a documented information security policy approved by senior management.")
    guidance.append("Assign a named Information Security Officer or equivalent role with board-level reporting.")
    guidance.append("Conduct annual security reviews against CE v4 Danzell and CAF objectives.")

    return CAFPrinciple(
        principle_id="A.1", principle_name="Governance",
        objective="A", objective_name="Managing security risk",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _a2_risk_management(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.4

    if metrics["critical_vulns"] == 0:
        indicators.append("No critical vulnerabilities open — effective vulnerability risk management")
        score += 0.25
    else:
        gaps.append(f"{metrics['critical_vulns']} critical CVEs open — risk management process not fully reducing technical risk")

    if metrics["darkweb_active"] == 0:
        indicators.append("No active dark web exposures detected")
        score += 0.15
    else:
        gaps.append(f"{metrics['darkweb_active']} active dark web findings — credential exposure risk not mitigated")

    guidance.append("Maintain a risk register updated at least quarterly.")
    guidance.append("Map CyberAssetIQ vulnerability findings to your risk register entries.")
    guidance.append("Define risk acceptance criteria and document risk treatment decisions.")

    return CAFPrinciple(
        principle_id="A.2", principle_name="Risk Management",
        objective="A", objective_name="Managing security risk",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _a3_asset_management(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.0

    ratio = metrics["managed_ratio"]
    if ratio >= 0.9:
        score = 0.9
        indicators.append(f"{round(ratio*100)}% of assets under managed inventory")
    elif ratio >= 0.7:
        score = 0.65
        indicators.append(f"{round(ratio*100)}% of assets managed — improvement needed")
        gaps.append(f"{metrics['asset_count'] - metrics['managed_count']} unmanaged assets detected")
    else:
        score = 0.3
        gaps.append(f"Only {round(ratio*100)}% of assets managed — significant inventory gap")

    guidance.append("Enrol all organisation devices in CyberAssetIQ agent management.")
    guidance.append("Maintain asset ownership records — assign a named owner to each business-critical asset.")
    guidance.append("Review asset inventory against HR records quarterly to identify departed-employee devices.")

    return CAFPrinciple(
        principle_id="A.3", principle_name="Asset Management",
        objective="A", objective_name="Managing security risk",
        status=_caf_status(score), score=score,
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _a4_supply_chain(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.2

    if metrics["supply_chain_registered"] > 0:
        score = 0.6
        indicators.append(f"{metrics['supply_chain_registered']} supplier relationships registered in supply chain portal")
    else:
        gaps.append("No supplier relationships registered — supply chain risk is unquantified")
        gaps.append("A.4 requires all critical suppliers to be identified, assessed, and subject to contractual security requirements")

    guidance.append("Register all critical third-party suppliers in the Supply Chain Assurance portal.")
    guidance.append("Conduct annual security assessments of tier-1 suppliers. Request CE certification as minimum.")
    guidance.append("Include security clauses in all supplier contracts: breach notification, right-to-audit, CE requirement.")

    return CAFPrinciple(
        principle_id="A.4", principle_name="Supply Chain",
        objective="A", objective_name="Managing security risk",
        status=_caf_status(score), score=score,
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


# ---------------------------------------------------------------------------
# Objective B: Protecting against cyber attack
# ---------------------------------------------------------------------------

def _b1_service_protection(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = metrics["compliance_score"] * 0.8 + 0.1

    if metrics["compliance_score"] > 0.6:
        indicators.append(f"CE compliance programme demonstrates service protection policies (score: {round(metrics['compliance_score']*100)}%)")
    else:
        gaps.append("CE compliance score below 60% — service protection policies may be incomplete")

    guidance.append("Document security policies for each in-scope service.")
    guidance.append("Implement change management for all modifications to in-scope systems.")

    return CAFPrinciple(
        principle_id="B.1", principle_name="Service Protection Policies",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _b2_identity_access(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    # Score based on CE compliance as proxy
    score = 0.4 + metrics["compliance_score"] * 0.4

    gaps.append("MFA coverage and privileged access management require CE-D3 assessment results for full CAF B.2 scoring")
    guidance.append("Enforce MFA for all privileged and cloud accounts (see CE-D3 Danzell assessment).")
    guidance.append("Implement least-privilege access — review and remove unnecessary admin rights quarterly.")
    guidance.append("Deploy Privileged Access Workstations (PAWs) for domain administrator tasks.")

    return CAFPrinciple(
        principle_id="B.2", principle_name="Identity and Access Control",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _b3_data_security(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.5

    if metrics["darkweb_active"] == 0:
        score += 0.2
        indicators.append("No active dark web credential exposures")
    else:
        score -= 0.2
        gaps.append(f"{metrics['darkweb_active']} active dark web exposures — data may be compromised")

    guidance.append("Classify all data assets and apply appropriate protection controls.")
    guidance.append("Encrypt sensitive data at rest and in transit.")
    guidance.append("Enable DLP (Data Loss Prevention) for cloud services handling sensitive data.")

    return CAFPrinciple(
        principle_id="B.3", principle_name="Data Security",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _b4_system_security(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    vuln_burden = metrics["critical_vulns"] + metrics["high_vulns"] * 0.5
    score = max(0.1, 1.0 - min(vuln_burden * 0.05, 0.8))

    if metrics["critical_vulns"] > 0:
        gaps.append(f"{metrics['critical_vulns']} critical CVEs unpatched — system security is actively compromised")
    if metrics["high_vulns"] > 0:
        gaps.append(f"{metrics['high_vulns']} high CVEs open — system hardening is incomplete")
    if vuln_burden == 0:
        indicators.append("No critical or high vulnerabilities open")

    guidance.append("Apply all critical and high patches within CE-D5 Danzell timelines (14/30 days).")
    guidance.append("Implement application control to prevent unauthorised software execution.")
    guidance.append("Harden system configurations against CIS Benchmark or NCSC guidance.")

    return CAFPrinciple(
        principle_id="B.4", principle_name="System Security",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(score), score=score,
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _b5_resilient_networks(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.55

    if metrics["drift_open"] == 0:
        score += 0.2
        indicators.append("No unresolved configuration drift events")
    else:
        score -= 0.1
        gaps.append(f"{metrics['drift_open']} open configuration drift events — network configuration may be inconsistent")

    guidance.append("Implement network segmentation — separate user, server, and IoT zones.")
    guidance.append("Design for resilience: redundant paths for critical services, documented failover procedures.")
    guidance.append("Test network resilience annually through structured exercises.")

    return CAFPrinciple(
        principle_id="B.5", principle_name="Resilient Networks and Systems",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _b6_staff_awareness(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.35  # Cannot be fully verified from technical data

    gaps.append("Staff security awareness training requires human process verification — no automated proxy available in platform data.")
    guidance.append("Conduct annual security awareness training for all staff. Include phishing simulation exercises.")
    guidance.append("Provide role-specific training for IT administrators and privileged users.")
    guidance.append("Measure training effectiveness via phishing simulation pass rates.")

    return CAFPrinciple(
        principle_id="B.6", principle_name="Staff Awareness and Training",
        objective="B", objective_name="Protecting against cyber attack",
        status=_caf_status(score), score=score,
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


# ---------------------------------------------------------------------------
# Objective C: Detecting cyber security events
# ---------------------------------------------------------------------------

def _c1_security_monitoring(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.3

    if metrics["notif_active"] > 0:
        score += 0.3
        indicators.append(f"{metrics['notif_active']} active notification channel(s) configured for security alerts")
    else:
        gaps.append("No active alert channels — security events will not be detected and notified in real time")

    if metrics["asset_count"] > 0 and metrics["managed_ratio"] > 0.7:
        score += 0.2
        indicators.append("Majority of assets under continuous agent monitoring")
    else:
        gaps.append("Incomplete asset monitoring coverage — not all devices feeding security telemetry")

    guidance.append("Configure CyberAssetIQ notification channels for critical security events.")
    guidance.append("Implement a SIEM or log aggregation solution for centralised event monitoring.")
    guidance.append("Define log retention periods: minimum 3 months online, 12 months archived.")
    guidance.append("Monitor for indicators of compromise from the dark web exposure module.")

    return CAFPrinciple(
        principle_id="C.1", principle_name="Security Monitoring",
        objective="C", objective_name="Detecting cyber security events",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _c2_proactive_discovery(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.4

    if metrics["critical_vulns"] < 5:
        score += 0.2
        indicators.append("Low critical vulnerability count suggests active scanning and remediation")
    else:
        gaps.append(f"{metrics['critical_vulns']} critical CVEs open — proactive vulnerability discovery may not be closing findings fast enough")

    if metrics["darkweb_active"] == 0:
        score += 0.2
        indicators.append("Dark web monitoring active with no current exposures")

    guidance.append("Schedule regular vulnerability scans — minimum monthly for all in-scope assets.")
    guidance.append("Subscribe to threat intelligence feeds relevant to your sector.")
    guidance.append("Conduct annual penetration tests against critical assets.")
    guidance.append("Use the CyberAssetIQ dark web monitoring module to proactively identify credential exposures.")

    return CAFPrinciple(
        principle_id="C.2", principle_name="Proactive Security Event Discovery",
        objective="C", objective_name="Detecting cyber security events",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


# ---------------------------------------------------------------------------
# Objective D: Minimising impact
# ---------------------------------------------------------------------------

def _d1_response_recovery(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.3  # Requires process verification

    gaps.append("Incident Response and Recovery plans require human process verification.")
    guidance.append("Create a documented IR plan. Reference CE-D9 Danzell requirements for minimum capability.")
    guidance.append("Test recovery procedures at least annually via tabletop exercise or full DR test.")
    guidance.append("Ensure backup coverage for all critical assets — review CyberAssetIQ Backup Resilience module.")
    guidance.append("Register with NCSC Early Warning service for threat notifications.")

    return CAFPrinciple(
        principle_id="D.1", principle_name="Response and Recovery Planning",
        objective="D", objective_name="Minimising the impact of cyber security incidents",
        status=_caf_status(score), score=score,
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


def _d2_improvements(metrics: dict) -> CAFPrinciple:
    indicators, gaps, guidance = [], [], []
    score = 0.4

    if metrics["compliance_score"] > 0:
        score += 0.2
        indicators.append("Active compliance tracking demonstrates continuous improvement programme")

    guidance.append("Conduct post-incident reviews and feed lessons learned back into policies.")
    guidance.append("Track security improvement actions in a register with owners and deadlines.")
    guidance.append("Re-run CyberAssetIQ posture rebuild after each remediation cycle to measure improvement.")
    guidance.append("Report security improvement metrics to senior management quarterly.")

    return CAFPrinciple(
        principle_id="D.2", principle_name="Improvements",
        objective="D", objective_name="Minimising the impact of cyber security incidents",
        status=_caf_status(min(score, 1.0)), score=min(score, 1.0),
        contributing_indicators=indicators, gaps=gaps, guidance=guidance,
    )


# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------

def assess_caf(db: Session, tenant_id: str) -> CAFReport:
    """Run full NCSC CAF assessment for a tenant and return structured report."""
    from datetime import datetime, timezone

    metrics = _score_from_db(db, tenant_id)

    principles = [
        _a1_governance(metrics),
        _a2_risk_management(metrics),
        _a3_asset_management(metrics),
        _a4_supply_chain(metrics),
        _b1_service_protection(metrics),
        _b2_identity_access(metrics),
        _b3_data_security(metrics),
        _b4_system_security(metrics),
        _b5_resilient_networks(metrics),
        _b6_staff_awareness(metrics),
        _c1_security_monitoring(metrics),
        _c2_proactive_discovery(metrics),
        _d1_response_recovery(metrics),
        _d2_improvements(metrics),
    ]

    objectives: dict[str, dict] = {}
    for obj_id, obj_name in [
        ("A", "Managing security risk"),
        ("B", "Protecting against cyber attack"),
        ("C", "Detecting cyber security events"),
        ("D", "Minimising the impact of cyber security incidents"),
    ]:
        obj_principles = [p for p in principles if p.objective == obj_id]
        obj_score = sum(p.score for p in obj_principles) / len(obj_principles)
        objectives[obj_id] = {
            "objective_id":   obj_id,
            "objective_name": obj_name,
            "score":          round(obj_score * 100),
            "status":         _caf_status(obj_score),
            "principles": [
                {
                    "id": p.principle_id,
                    "name": p.principle_name,
                    "status": p.status,
                    "score": round(p.score * 100),
                    "gaps": p.gaps[:3],
                    "guidance": p.guidance[:2],
                    "contributing_indicators": p.contributing_indicators,
                }
                for p in obj_principles
            ],
        }

    overall_score = sum(p.score for p in principles) / len(principles)

    achieved = sum(1 for p in principles if p.status == "ACHIEVED")
    partial  = sum(1 for p in principles if p.status == "PARTIALLY_ACHIEVED")
    not_ach  = sum(1 for p in principles if p.status == "NOT_ACHIEVED")

    top_gaps = [
        g
        for p in sorted(principles, key=lambda x: x.score)
        for g in p.gaps[:1]
    ][:6]

    as_posture_domains = [
        {
            "framework": FRAMEWORK_NAME,
            "version":   CAF_VERSION,
            "overall_score": round(overall_score * 100),
            "overall_status": _caf_status(overall_score),
            "objectives": {
                obj_id: {
                    "score": obj_data["score"],
                    "status": obj_data["status"],
                }
                for obj_id, obj_data in objectives.items()
            },
            "principle_summary": {
                "total": len(principles),
                "achieved": achieved,
                "partially_achieved": partial,
                "not_achieved": not_ach,
            },
        }
    ]

    return CAFReport(
        tenant_id=tenant_id,
        framework=FRAMEWORK_NAME,
        assessed_at=datetime.now(timezone.utc).isoformat(),
        objectives=objectives,
        overall_score=overall_score,
        overall_status=_caf_status(overall_score),
        principle_count=len(principles),
        achieved_count=achieved,
        partial_count=partial,
        not_achieved_count=not_ach,
        top_gaps=top_gaps,
        as_posture_domains=as_posture_domains,
    )
