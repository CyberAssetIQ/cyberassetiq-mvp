from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger("cyberassetiq.posture.snapshot")


def _clamp_score(value: Any) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return 0


def _risk_band(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Medium"
    if score >= 50:
        return "High"
    return "Critical"


def _append_evidence(bucket: list[dict[str, Any]], evidence_type: str, source_module: str, title: str,
                     description: str, severity: str, raw_json: dict[str, Any], asset_ref: str = "",
                     control_ref: str = "", external_ref: str = "") -> None:
    bucket.append({
        "evidence_type": evidence_type,
        "source_module": source_module,
        "title": title,
        "description": description,
        "severity": severity,
        "asset_ref": asset_ref,
        "control_ref": control_ref,
        "external_ref": external_ref,
        "raw_json": raw_json,
    })


def build_posture_snapshot(db: Session, tenant_id: str) -> dict[str, Any]:
    from models.asset import CanonicalAsset
    from models.business_context import AssetBusinessContext
    from models.compliance_run import ComplianceRun
    from models.darkweb import DarkWebFinding
    from models.drift import AssetDriftEvent
    from models.external_exposure import ExternalFinding
    from models.patch import PatchReport
    from models.telemetry import VulnerabilityFinding, LocalFindingsEvent
    from services.attack_graph_service import get_attack_graph_summary
    from services.backup_resilience_service import get_backup_summary
    from models.shadow_it import ShadowITFinding
    from services.cloud_posture_service import get_cloud_posture_summary
    from services.executive_service import get_executive_summary
    from services.identity_service import analyse_identity_risk
    from services.insurance_service import calculate_readiness
    from services.risk_engine_service import get_risk_summary

    evidence: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []

    asset_count = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).count()

    latest_compliance = (
        db.query(ComplianceRun)
        .filter(ComplianceRun.tenant_id == tenant_id)
        .order_by(ComplianceRun.id.desc())
        .first()
    )
    compliance_score = _clamp_score(getattr(latest_compliance, "tenant_overall_score", 0) or 0)
    if latest_compliance:
        _append_evidence(
            evidence, "control", "compliance_service", "Latest Cyber Essentials aligned assessment",
            f"Most recent tenant compliance score is {compliance_score}%.",
            "medium" if compliance_score < 70 else "info",
            {"run_id": latest_compliance.id, "score": compliance_score}, control_ref="CyberEssentials"
        )

    critical_cves = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.severity == "CRITICAL",
        VulnerabilityFinding.status == "open",
    ).count()
    high_cves = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.severity == "HIGH",
        VulnerabilityFinding.status == "open",
    ).count()
    open_cves_count = critical_cves + high_cves
    exposure_score = _clamp_score(100 - min(critical_cves * 8 + high_cves * 3, 100))
    if open_cves_count:
        _append_evidence(
            evidence, "finding", "vulnerability_findings", "Open exploitable vulnerabilities detected",
            f"{critical_cves} critical and {high_cves} high open vulnerabilities remain unresolved.",
            "critical" if critical_cves else "high",
            {"critical": critical_cves, "high": high_cves}, external_ref="vuln-scan"
        )

    darkweb_count = db.query(DarkWebFinding).filter(
        DarkWebFinding.tenant_id == tenant_id,
        DarkWebFinding.status != "resolved",
    ).count()
    darkweb_score = _clamp_score(100 - min(darkweb_count * 12, 100))
    if darkweb_count:
        _append_evidence(
            evidence, "finding", "darkweb_service", "Dark web exposure remains active",
            f"{darkweb_count} active dark web findings could impact trust with insurers and supply-chain buyers.",
            "critical" if darkweb_count >= 2 else "high",
            {"active_findings": darkweb_count}, external_ref="darkweb"
        )

    external_critical = db.query(ExternalFinding).filter(
        ExternalFinding.tenant_id == tenant_id,
        func.lower(ExternalFinding.severity) == "critical",
    ).count()
    external_high = db.query(ExternalFinding).filter(
        ExternalFinding.tenant_id == tenant_id,
        func.lower(ExternalFinding.severity) == "high",
    ).count()
    internet_exposure_score = _clamp_score(100 - min(external_critical * 15 + external_high * 6, 100))
    if external_critical + external_high:
        _append_evidence(
            evidence, "finding", "external_exposure_service", "Internet-facing risks detected",
            f"{external_critical} critical and {external_high} high external exposure findings are present.",
            "critical" if external_critical else "high",
            {"critical": external_critical, "high": external_high}, external_ref="external-exposure"
        )

    identity_summary = {}
    try:
        identity_summary = analyse_identity_risk(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("identity summary failed: %s", exc)
    identity_score = _clamp_score(identity_summary.get("identity_score", identity_summary.get("score", 0)))
    identity_risk_findings = int(identity_summary.get("open_findings", identity_summary.get("finding_count", 0)) or 0)
    if identity_risk_findings:
        _append_evidence(
            evidence, "finding", "identity_service", "Identity security gaps detected",
            f"Identity risk engine reports {identity_risk_findings} active identity findings.",
            "high" if identity_score < 70 else "medium",
            identity_summary, external_ref="identity"
        )

    drift_count = db.query(AssetDriftEvent).filter(
        AssetDriftEvent.tenant_id == tenant_id,
        AssetDriftEvent.status == "open",
    ).count()
    drift_score = _clamp_score(100 - min(drift_count * 8, 100))
    if drift_count:
        _append_evidence(
            evidence, "finding", "drift_detection_service", "Configuration drift requires review",
            f"{drift_count} open drift events indicate configuration drift from approved baselines.",
            "medium" if drift_count < 5 else "high",
            {"open_drift_events": drift_count}, external_ref="drift"
        )

    latest_patch = (
        db.query(PatchReport)
        .filter(PatchReport.tenant_id == tenant_id)
        .order_by(PatchReport.id.desc())
        .first()
    )
    patch_score = _clamp_score(getattr(latest_patch, "score", getattr(latest_patch, "compliance_score", 0)) or 0)
    if latest_patch:
        _append_evidence(
            evidence, "control", "patch_service", "Patch management posture assessed",
            f"Most recent patch score is {patch_score}/100.",
            "medium" if patch_score < 70 else "info",
            {"patch_report_id": latest_patch.id, "patch_score": patch_score}, external_ref="patch"
        )

    insurance = calculate_readiness(db, tenant_id)
    insurance_score = _clamp_score(insurance.get("readiness_score", 0))
    insurance_band = insurance.get("risk_band", _risk_band(insurance_score))

    cloud_summary = {}
    try:
        cloud_summary = get_cloud_posture_summary(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("cloud posture summary failed: %s", exc)
    cloud_findings = int(cloud_summary.get("open_findings", 0) or 0)
    cloud_critical = int(cloud_summary.get("critical_findings", 0) or 0)
    unapproved_saas = int(cloud_summary.get("unapproved_saas_apps", 0) or 0)
    cloud_score = _clamp_score(100 - min(cloud_findings * 7 + cloud_critical * 10 + unapproved_saas * 4, 100))
    if cloud_summary and (cloud_findings or unapproved_saas or cloud_summary.get("accounts_configured")):
        _append_evidence(
            evidence, "finding", "cloud_posture_service", "Cloud posture and SaaS exposure assessed",
            f"{cloud_findings} open cloud findings and {unapproved_saas} unapproved SaaS app(s) are currently recorded.",
            "critical" if cloud_critical else ("high" if cloud_findings else "medium"),
            cloud_summary, external_ref="cloud-posture"
        )

    shadow_findings = db.query(ShadowITFinding).filter(ShadowITFinding.tenant_id == tenant_id).count()
    shadow_score = _clamp_score(100 - min(shadow_findings * 9, 100))
    if shadow_findings:
        _append_evidence(
            evidence, "finding", "shadow_it_service", "Shadow IT exposures identified",
            f"{shadow_findings} shadow IT finding(s) require review and supplier-trust remediation.",
            "high" if shadow_findings < 5 else "critical",
            {"shadow_it_findings": shadow_findings}, external_ref="shadow-it"
        )

    backup_summary = {}
    try:
        backup_summary = get_backup_summary(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("backup summary failed: %s", exc)
    resilience_score = _clamp_score(
        backup_summary.get("recovery_confidence_score")
        or backup_summary.get("resilience_score")
        or backup_summary.get("score")
        or 0
    )
    if backup_summary:
        _append_evidence(
            evidence, "control", "backup_resilience_service", "Backup resilience assessed",
            f"Recovery confidence is {resilience_score}/100 for the latest resilience profile.",
            "medium" if resilience_score < 70 else "info",
            backup_summary, external_ref="backup"
        )

    attack_summary = {}
    try:
        attack_summary = get_attack_graph_summary(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("attack graph summary failed: %s", exc)
    attack_path_count = int(attack_summary.get("attack_path_count", attack_summary.get("paths", 0)) or 0)
    crown_jewel_assets_count = int(attack_summary.get("crown_jewel_assets", attack_summary.get("crown_jewel_count", 0)) or 0)
    attack_path_score = _clamp_score(100 - min(attack_path_count * 12, 100))
    if attack_path_count:
        _append_evidence(
            evidence, "finding", "attack_graph_service", "Attack paths to critical assets identified",
            f"{attack_path_count} attack path(s) and {crown_jewel_assets_count} crown-jewel asset(s) require attention.",
            "critical" if attack_path_count >= 2 else "high",
            attack_summary, external_ref="attack-graph"
        )

    risk_summary = {}
    try:
        risk_summary = get_risk_summary(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("risk summary failed: %s", exc)

    secret_events = db.query(LocalFindingsEvent).filter(LocalFindingsEvent.tenant_id == tenant_id).order_by(LocalFindingsEvent.id.desc()).limit(20).all()
    credential_exposure_count = 0
    for evt in secret_events:
        payload = evt.payload_json
        try:
            findings = payload if isinstance(payload, list) else json.loads(payload or "[]")
        except Exception:
            findings = []
        credential_exposure_count += sum(1 for item in findings if (item.get("severity") or "").upper() in {"CRITICAL", "HIGH"})
    if credential_exposure_count:
        _append_evidence(
            evidence, "finding", "scanner_service", "Sensitive credential or secret exposure findings exist",
            f"{credential_exposure_count} critical/high local secret findings were detected.",
            "critical",
            {"credential_exposure_count": credential_exposure_count}, external_ref="credential-scanner"
        )

    from sqlalchemy import func as sa_func
    criticality_count = db.query(sa_func.count(AssetBusinessContext.id)).filter(
        AssetBusinessContext.tenant_id == tenant_id,
        AssetBusinessContext.sla_tier == "gold",
    ).scalar() or 0

    executive_summary = {}
    try:
        executive_summary = get_executive_summary(db, tenant_id) or {}
    except Exception as exc:
        logger.warning("executive summary failed: %s", exc)

    domains = [
        {
            "domain_name": "asset_visibility",
            "score": _clamp_score(100 if asset_count >= 1 else 35),
            "risk_band": _risk_band(_clamp_score(100 if asset_count >= 1 else 35)),
            "summary": f"{asset_count} asset(s) are represented in the canonical posture dataset.",
            "details_json": {"asset_count": asset_count},
            "evidence_count": 1,
        },
        {
            "domain_name": "vulnerability_exposure",
            "score": exposure_score,
            "risk_band": _risk_band(exposure_score),
            "summary": f"{open_cves_count} high/critical open vulnerabilities influence the exposure picture.",
            "details_json": {"critical_cves": critical_cves, "high_cves": high_cves},
            "evidence_count": 1 if open_cves_count else 0,
        },
        {
            "domain_name": "identity_security",
            "score": identity_score,
            "risk_band": _risk_band(identity_score),
            "summary": f"Identity posture reflects {identity_risk_findings} active identity findings.",
            "details_json": identity_summary,
            "evidence_count": 1 if identity_summary else 0,
        },
        {
            "domain_name": "backup_resilience",
            "score": resilience_score,
            "risk_band": _risk_band(resilience_score),
            "summary": f"Recovery confidence currently stands at {resilience_score}/100.",
            "details_json": backup_summary,
            "evidence_count": 1 if backup_summary else 0,
        },
        {
            "domain_name": "cloud_posture",
            "score": cloud_score,
            "risk_band": _risk_band(cloud_score),
            "summary": f"{cloud_findings} cloud finding(s) and {unapproved_saas} unapproved SaaS app(s) are represented in the cloud posture layer.",
            "details_json": cloud_summary,
            "evidence_count": 1 if cloud_summary else 0,
        },
        {
            "domain_name": "shadow_it",
            "score": shadow_score,
            "risk_band": _risk_band(shadow_score),
            "summary": f"{shadow_findings} shadow IT finding(s) are currently associated with this tenant.",
            "details_json": {"shadow_it_findings": shadow_findings},
            "evidence_count": 1 if shadow_findings else 0,
        },
        {
            "domain_name": "external_exposure",
            "score": internet_exposure_score,
            "risk_band": _risk_band(internet_exposure_score),
            "summary": f"{external_critical + external_high} external exposure findings are influencing public attack surface risk.",
            "details_json": {"critical": external_critical, "high": external_high},
            "evidence_count": 1 if (external_critical + external_high) else 0,
        },
        {
            "domain_name": "compliance",
            "score": compliance_score,
            "risk_band": _risk_band(compliance_score),
            "summary": f"The latest Cyber Essentials aligned score is {compliance_score}%.",
            "details_json": {"run_id": getattr(latest_compliance, "id", None), "score": compliance_score},
            "evidence_count": 1 if latest_compliance else 0,
        },
        {
            "domain_name": "attack_paths",
            "score": attack_path_score,
            "risk_band": _risk_band(attack_path_score),
            "summary": f"{attack_path_count} attack path(s) currently exist in the attack graph model.",
            "details_json": attack_summary,
            "evidence_count": 1 if attack_summary else 0,
        },
        {
            "domain_name": "control_drift",
            "score": drift_score,
            "risk_band": _risk_band(drift_score),
            "summary": f"{drift_count} configuration drift event(s) remain unresolved.",
            "details_json": {"open_drift_events": drift_count},
            "evidence_count": 1 if drift_count else 0,
        },
    ]

    score_breakdown = {
        "compliance": compliance_score,
        "identity": identity_score,
        "exposure": max(exposure_score, internet_exposure_score),
        "resilience": resilience_score,
        "patch": patch_score,
        "drift": drift_score,
        "insurance_readiness": insurance_score,
        "attack_paths": attack_path_score,
        "cloud_posture": cloud_score,
        "shadow_it": shadow_score,
        "darkweb": darkweb_score,
    }

    overall_score = _clamp_score(
        0.14 * compliance_score +
        0.12 * identity_score +
        0.12 * max(exposure_score, internet_exposure_score) +
        0.10 * resilience_score +
        0.09 * patch_score +
        0.09 * drift_score +
        0.10 * insurance_score +
        0.08 * attack_path_score +
        0.08 * cloud_score +
        0.04 * shadow_score +
        0.04 * darkweb_score
    )
    supply_chain_score = _clamp_score(
        0.22 * compliance_score +
        0.13 * identity_score +
        0.14 * resilience_score +
        0.08 * patch_score +
        0.08 * drift_score +
        0.10 * max(exposure_score, internet_exposure_score) +
        0.12 * attack_path_score +
        0.08 * cloud_score +
        0.05 * shadow_score
    )

    severity_counter = Counter(item["severity"] for item in evidence)
    critical_findings_count = severity_counter.get("critical", 0) + severity_counter.get("high", 0)

    top_risks = [item["title"] for item in sorted(
        evidence,
        key=lambda x: {"critical": 4, "high": 3, "medium": 2, "info": 1}.get(x["severity"], 0),
        reverse=True,
    )[:8]]

    summary_json = {
        "headline": f"CyberAssetIQ posture record built for tenant {tenant_id}",
        "executive_summary": executive_summary,
        "insurance_band": insurance_band,
        "risk_engine": risk_summary,
        "market_ready_message": (
            "This posture record is suitable for broker review, supplier assurance workflows, "
            "and a verifiable external trust signal."
        ),
    }

    evidence_summary_json = {
        "evidence_count": len(evidence),
        "critical": severity_counter.get("critical", 0),
        "high": severity_counter.get("high", 0),
        "medium": severity_counter.get("medium", 0),
        "info": severity_counter.get("info", 0),
    }

    # ── Multi-framework assessment: CE v4 Danzell, NCSC CAF, CS&R Bill ──────
    danzell_score = 0
    danzell_status = "NOT_ASSESSED"
    danzell_v4_gaps = []
    try:
        from services.ce_danzell_service import assess_tenant_danzell
        danzell_report = assess_tenant_danzell(db, tenant_id)
        danzell_score = round(danzell_report.overall_score * 100)
        danzell_status = danzell_report.overall_status
        danzell_v4_gaps = danzell_report.v4_new_gaps[:5]
    except Exception as _exc:
        logger.warning("CE Danzell assessment failed in snapshot: %s", _exc)

    caf_score = 0
    caf_status = "NOT_ASSESSED"
    caf_objectives = {}
    try:
        from services.caf_mapping_service import assess_caf
        caf_report = assess_caf(db, tenant_id)
        caf_score = round(caf_report.overall_score * 100)
        caf_status = caf_report.overall_status
        caf_objectives = {
            obj_id: {"score": data["score"], "status": data["status"]}
            for obj_id, data in caf_report.objectives.items()
        }
    except Exception as _exc:
        logger.warning("CAF assessment failed in snapshot: %s", _exc)

    csr_score = 0
    csr_status = "NOT_ASSESSED"
    csr_supply_chain_met = False
    csr_incident_ready = False
    try:
        from services.csr_bill_service import assess_csr_bill
        csr_report = assess_csr_bill(db, tenant_id)
        csr_score = round(csr_report.overall_score * 100)
        csr_status = csr_report.overall_status
        csr_supply_chain_met = csr_report.supply_chain_obligation_met
        csr_incident_ready = csr_report.incident_reporting_ready
    except Exception as _exc:
        logger.warning("CS&R Bill assessment failed in snapshot: %s", _exc)

    controls_json = {
        "frameworks": [
            "CE v4 Danzell (April 2026)",
            "NCSC Cyber Assessment Framework (CAF)",
            "UK CS&R Bill",
            "Supply-chain assurance controls",
        ],
        "ce_danzell": {
            "framework": "Cyber Essentials v4 Danzell",
            "score": danzell_score,
            "status": danzell_status,
            "v4_new_gaps": danzell_v4_gaps,
            "note": "Successor to CE v3.2 Willow — April 2026 update adds supply chain, remote working, and incident readiness controls.",
        },
        "ncsc_caf": {
            "framework": "NCSC Cyber Assessment Framework",
            "score": caf_score,
            "status": caf_status,
            "objectives": caf_objectives,
            "note": "14 CAF principles across 4 objectives: Managing risk, Protecting, Detecting, Minimising impact.",
        },
        "csr_bill": {
            "framework": "UK Cyber Security and Resilience Bill",
            "score": csr_score,
            "status": csr_status,
            "supply_chain_obligation_met": csr_supply_chain_met,
            "incident_reporting_ready": csr_incident_ready,
            "note": "First major update to UK cyber legislation since NIS Regulations 2018.",
        },
        "coverage": {
            "assets": asset_count,
            "critical_business_assets": criticality_count,
            "internet_exposure_findings": external_critical + external_high,
            "attack_path_count": attack_path_count,
            "credential_exposure_count": credential_exposure_count,
        },
    }

    metadata_json = {
        "tenant_id": tenant_id,
        "schema": "cyberassetiq.posture_record.v1",
        "generated_for": ["tenant", "broker", "buyer", "insurer"],
    }

    return {
        "tenant_id": tenant_id,
        "overall_score": overall_score,
        "risk_band": _risk_band(overall_score),
        "insurance_readiness_score": insurance_score,
        "supply_chain_score": supply_chain_score,
        "compliance_score": compliance_score,
        "identity_score": identity_score,
        "exposure_score": max(exposure_score, internet_exposure_score),
        "resilience_score": resilience_score,
        "patch_score": patch_score,
        "drift_score": drift_score,
        "asset_count": asset_count,
        "critical_findings_count": critical_findings_count,
        "open_cves_count": open_cves_count,
        "darkweb_findings_count": darkweb_count,
        "attack_path_count": attack_path_count,
        "crown_jewel_assets_count": crown_jewel_assets_count,
        "credential_exposure_count": credential_exposure_count,
        "summary_json": summary_json,
        "score_breakdown_json": score_breakdown,
        "top_risks_json": top_risks,
        "evidence_summary_json": evidence_summary_json,
        "controls_json": controls_json,
        "metadata_json": metadata_json,
        "domains": domains,
        "evidence": evidence,
    }
