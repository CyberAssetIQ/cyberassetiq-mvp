"""
csr_bill_service.py

UK Cyber Security and Resilience (CS&R) Bill Compliance Mapping Engine.

The CS&R Bill (expected Royal Assent mid-2026) is the first major update
to UK cyber legislation since the NIS Regulations 2018. It extends compliance
obligations into supply chains, expands the definition of regulated entities,
and introduces new incident reporting requirements.

This service maps CyberAssetIQ platform data to the Bill's key obligations
across five compliance domains:

  CSR-1  Supply chain security obligations
  CSR-2  Incident reporting and notification
  CSR-3  Network and information systems security
  CSR-4  Managed service provider obligations
  CSR-5  Security governance and accountability

Each domain evaluates to: COMPLIANT | PARTIALLY_COMPLIANT | NON_COMPLIANT | NOT_ASSESSED
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

FRAMEWORK_NAME    = "UK Cyber Security and Resilience Bill"
FRAMEWORK_SHORT   = "CS&R Bill"
FRAMEWORK_VERSION = "CS&R Bill 2025 (pre-Royal Assent)"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CSRDomainResult:
    domain_id:    str
    domain_name:  str
    status:       str    # COMPLIANT | PARTIALLY_COMPLIANT | NON_COMPLIANT | NOT_ASSESSED
    score:        float  # 0.0 – 1.0
    obligations:  list[dict]  # {obligation, met: bool, evidence: str, gap: str}
    gaps:         list[str]
    remediation:  list[str]
    bill_ref:     str    # e.g. "Part 2, Section 5"
    is_new_obligation: bool = False


@dataclass
class CSRBillReport:
    tenant_id:    str
    framework:    str
    assessed_at:  str
    overall_score: float
    overall_status: str
    domains:      list[CSRDomainResult]
    supply_chain_obligation_met: bool
    incident_reporting_ready:    bool
    nis_upgrade_gaps:            list[str]  # gaps vs old NIS 2018 baseline
    top_obligations_to_address:  list[str]
    as_posture_controls:         dict      # formatted for posture record


def _csr_status(score: float) -> str:
    if score >= 0.80:
        return "COMPLIANT"
    if score >= 0.45:
        return "PARTIALLY_COMPLIANT"
    return "NON_COMPLIANT"


# ---------------------------------------------------------------------------
# CSR-1: Supply Chain Security Obligations
# ---------------------------------------------------------------------------

def _csr1_supply_chain(db: Session, tenant_id: str) -> CSRDomainResult:
    """
    The CS&R Bill's most consequential new provision: regulated entities must
    assess and manage the cyber posture of their own suppliers. SMEs supplying
    to regulated organisations will face indirect compliance requirements
    flowing down through contractual channels.
    """
    gaps, remediation = [], []
    obligations = []
    score = 0.0

    try:
        from models.supply_chain import SupplierRelationship, AssuranceRequest, SupplierAttestation

        # Obligation 1: Supplier inventory
        supplier_count = db.query(func.count(SupplierRelationship.id)).filter(
            SupplierRelationship.supplier_tenant_id == tenant_id,
        ).scalar() or 0

        inv_met = supplier_count > 0
        obligations.append({
            "obligation": "Maintain an inventory of critical third-party suppliers",
            "met": inv_met,
            "evidence": f"{supplier_count} supplier relationships registered",
            "gap": "" if inv_met else "No suppliers registered — Bill requires documented supply chain inventory",
        })
        if inv_met:
            score += 0.25
        else:
            gaps.append("No supplier inventory — CS&R Bill requires all regulated entities to maintain a documented supplier list.")
            remediation.append("Register all critical third-party suppliers in the CyberAssetIQ Supply Chain portal.")

        # Obligation 2: Supplier assurance
        assurance_count = db.query(func.count(AssuranceRequest.id)).filter(
            AssuranceRequest.supplier_tenant_id == tenant_id,
        ).scalar() or 0

        assurance_met = assurance_count > 0
        obligations.append({
            "obligation": "Conduct security assessments of critical suppliers",
            "met": assurance_met,
            "evidence": f"{assurance_count} assurance assessments completed",
            "gap": "" if assurance_met else "No supplier security assessments on record",
        })
        if assurance_met:
            score += 0.25
        else:
            gaps.append("No supplier security assessments — CS&R Bill requires evidence of supplier risk assessment.")
            remediation.append("Complete a supply chain assurance request for each critical supplier. Require CE v4 or equivalent certification.")

        # Obligation 3: Verifiable posture for supply chain trust
        try:
            from models.verification import VerificationCredential
            cred = db.query(VerificationCredential).filter(
                VerificationCredential.tenant_id == tenant_id,
                VerificationCredential.status == "valid",
            ).first()
            cred_met = cred is not None
        except Exception:
            cred_met = False

        obligations.append({
            "obligation": "Provide verifiable security posture credentials to enterprise buyers",
            "met": cred_met,
            "evidence": "Live verification credential issued" if cred_met else "No active verification credential",
            "gap": "" if cred_met else "No verifiable credential — supply chain buyers cannot confirm your posture",
        })
        if cred_met:
            score += 0.3
        else:
            gaps.append("No live verification credential — under the CS&R Bill, suppliers must be able to demonstrate cyber posture to buyers.")
            remediation.append("Issue a verification credential from the CyberAssetIQ Verification tab and share the token with enterprise buyers.")

    except Exception as exc:
        logger.warning("CSR-1 assessment error: %s", exc)
        gaps.append("Supply chain module not fully configured.")
        score = 0.1

    # Obligation 4: Contractual security requirements (advisory)
    obligations.append({
        "obligation": "Include security clauses in supplier contracts (breach notification, CE requirement)",
        "met": False,
        "evidence": "Cannot be automatically verified — requires contract review",
        "gap": "Contractual security obligations require manual verification",
    })
    gaps.append("CS&R Bill requires contractual security obligations with all critical suppliers — requires legal review of existing contracts.")
    remediation.append("Review supplier contracts to include: CE v4 certification requirement, 72-hour breach notification, right-to-audit clause.")
    score = min(score, 0.80)  # Cannot be fully COMPLIANT without contract verification

    return CSRDomainResult(
        domain_id="CSR-1", domain_name="Supply Chain Security Obligations",
        status=_csr_status(score), score=score,
        obligations=obligations, gaps=gaps, remediation=remediation,
        bill_ref="CS&R Bill — Part 3 (Supply Chain Provisions)",
        is_new_obligation=True,
    )


# ---------------------------------------------------------------------------
# CSR-2: Incident Reporting and Notification
# ---------------------------------------------------------------------------

def _csr2_incident_reporting(db: Session, tenant_id: str) -> CSRDomainResult:
    """
    CS&R Bill introduces 72-hour incident reporting requirement for regulated entities
    (aligning with NIS2 in the EU). Significant incidents must be reported to DSIT
    and relevant sectoral regulators.
    """
    gaps, remediation = [], []
    obligations = []
    score = 0.3  # Process-heavy — start at partial

    # Check notification infrastructure as proxy for reporting capability
    notif_active = 0
    try:
        from models.notification import NotificationConfig
        notif_active = db.query(func.count(NotificationConfig.id)).filter(
            NotificationConfig.tenant_id == tenant_id,
            NotificationConfig.is_active == True,
        ).scalar() or 0
    except Exception:
        pass

    notif_met = notif_active > 0
    obligations.append({
        "obligation": "Configure security event alerting to enable timely incident detection",
        "met": notif_met,
        "evidence": f"{notif_active} active notification channels",
        "gap": "" if notif_met else "No notification channels — incidents may not be detected within 72-hour window",
    })
    if notif_met:
        score += 0.2
    else:
        gaps.append("No alerting configured — CS&R Bill's 72-hour reporting window requires rapid incident detection.")
        remediation.append("Configure CyberAssetIQ notification channels for critical security events immediately.")

    # 72-hour reporting process (advisory)
    obligations.append({
        "obligation": "Maintain a documented 72-hour incident reporting process to DSIT",
        "met": False,
        "evidence": "Requires human process verification",
        "gap": "72-hour reporting process requires documented procedure and named contacts",
    })
    gaps.append("CS&R Bill requires a documented 72-hour incident reporting process — report to DSIT and relevant sectoral regulator.")
    remediation.append(
        "Document a 72-hour incident reporting procedure: "
        "(1) Incident classification criteria, "
        "(2) Named reporter with DSIT notification contact, "
        "(3) Template incident notification form, "
        "(4) Escalation path to legal/DPO for GDPR cross-reporting."
    )

    # ICO/GDPR cross-reporting
    obligations.append({
        "obligation": "Cross-report to ICO where breach involves personal data (72 hours)",
        "met": False,
        "evidence": "Cannot be automatically verified",
        "gap": "GDPR/CS&R cross-reporting procedure requires documentation",
    })
    gaps.append("Where incidents involve personal data, parallel 72-hour ICO reporting is required under UK GDPR alongside CS&R Bill notification.")
    remediation.append("Ensure IR plan includes ICO notification trigger criteria and a template notification to the Information Commissioner.")

    return CSRDomainResult(
        domain_id="CSR-2", domain_name="Incident Reporting and Notification",
        status=_csr_status(score), score=score,
        obligations=obligations, gaps=gaps, remediation=remediation,
        bill_ref="CS&R Bill — Part 2 (Incident Reporting)",
        is_new_obligation=True,
    )


# ---------------------------------------------------------------------------
# CSR-3: Network and Information Systems Security
# ---------------------------------------------------------------------------

def _csr3_nis_security(db: Session, tenant_id: str) -> CSRDomainResult:
    """
    CS&R Bill extends and strengthens the NIS Regulations 2018 requirements for
    security of network and information systems. Key improvement: stricter
    technical requirements and broader scope of regulated entities.
    """
    gaps, remediation = [], []
    obligations = []
    score = 0.0

    # Use existing platform data as evidence
    try:
        from models.telemetry import VulnerabilityFinding
        from models.asset import CanonicalAsset
        from models.compliance_run import ComplianceRun

        asset_count = db.query(func.count(CanonicalAsset.id)).filter(
            CanonicalAsset.tenant_id == tenant_id
        ).scalar() or 0

        critical_vulns = db.query(func.count(VulnerabilityFinding.id)).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "critical",
            VulnerabilityFinding.status == "open",
        ).scalar() or 0

        latest_run = (
            db.query(ComplianceRun)
            .filter(ComplianceRun.tenant_id == tenant_id)
            .order_by(ComplianceRun.id.desc())
            .first()
        )
        ce_score = (latest_run.tenant_overall_score or 0) if latest_run else 0

        # Obligation: Risk-appropriate security measures
        nis_met = ce_score >= 60 and critical_vulns == 0
        obligations.append({
            "obligation": "Implement risk-appropriate security measures for NIS/CS&R compliance",
            "met": nis_met,
            "evidence": f"CE compliance score: {ce_score}%, Critical CVEs: {critical_vulns}",
            "gap": "" if nis_met else f"CE score {ce_score}% with {critical_vulns} critical CVEs — NIS security measures inadequate",
        })
        if nis_met:
            score += 0.35
        else:
            if critical_vulns > 0:
                gaps.append(f"{critical_vulns} critical vulnerabilities — CS&R Bill requires security measures that prevent vulnerabilities from being exploited in NIS-regulated services.")
                remediation.append("Patch all critical CVEs immediately. CS&R Bill enforcement will scrutinise unpatched vulnerabilities in regulated service providers.")
            if ce_score < 60:
                gaps.append("CE compliance score below 60% — CS&R Bill baseline requires CE certification or equivalent controls.")
                remediation.append("Achieve CE v4 Danzell certification. This satisfies the CS&R Bill's baseline NIS security measure requirement.")

        # Obligation: Asset inventory for NIS scope
        inventory_met = asset_count > 0
        obligations.append({
            "obligation": "Maintain accurate inventory of all in-scope network and information systems",
            "met": inventory_met,
            "evidence": f"{asset_count} assets in managed inventory",
            "gap": "" if inventory_met else "No assets in inventory — NIS/CS&R requires documented NIS scope",
        })
        if inventory_met:
            score += 0.25
        else:
            gaps.append("No asset inventory — CS&R Bill requires regulated entities to know what systems are in scope.")
            remediation.append("Complete asset discovery to identify all systems delivering in-scope services.")

        # Obligation: Continuous monitoring
        obligations.append({
            "obligation": "Implement continuous monitoring of in-scope systems",
            "met": asset_count > 0,
            "evidence": "CyberAssetIQ continuous monitoring active" if asset_count > 0 else "No monitoring configured",
            "gap": "" if asset_count > 0 else "Continuous monitoring not in place",
        })
        if asset_count > 0:
            score += 0.2

    except Exception as exc:
        logger.warning("CSR-3 assessment error: %s", exc)
        score = 0.2
        gaps.append("NIS security assessment partially unavailable — platform data required.")

    remediation.append("Map your service delivery architecture to the CS&R Bill's NIS scope definition. Document which systems are in scope for regulation.")

    return CSRDomainResult(
        domain_id="CSR-3", domain_name="Network and Information Systems Security",
        status=_csr_status(score), score=score,
        obligations=obligations, gaps=gaps, remediation=remediation,
        bill_ref="CS&R Bill — Part 1 (NIS Strengthening)",
        is_new_obligation=False,
    )


# ---------------------------------------------------------------------------
# CSR-4: Managed Service Provider Obligations
# ---------------------------------------------------------------------------

def _csr4_msp_obligations(db: Session, tenant_id: str) -> CSRDomainResult:
    """
    CS&R Bill significantly expands MSP obligations. MSPs providing services
    to regulated entities are now directly subject to NIS requirements,
    creating obligations for both the MSP and their clients.
    """
    gaps, remediation = [], []
    obligations = []
    score = 0.4

    # Check if this tenant has MSP capabilities configured
    is_msp = False
    msp_client_count = 0
    try:
        from models.msp import MSPAccount
        msp = db.query(MSPAccount).filter(
            MSPAccount.tenant_id == tenant_id,
            MSPAccount.is_active == True,
        ).first()
        is_msp = msp is not None
        if msp:
            msp_client_count = getattr(msp, "client_count", 0) or 0
    except Exception:
        pass

    if is_msp:
        obligations.append({
            "obligation": "MSP: Register as CS&R Bill regulated entity with DSIT",
            "met": False,
            "evidence": f"MSP account active with {msp_client_count} clients — requires DSIT registration",
            "gap": "MSPs are now directly regulated under CS&R Bill — DSIT registration required",
        })
        gaps.append("As an MSP, you are now a regulated entity under the CS&R Bill. DSIT registration and direct NIS obligations apply.")
        remediation.append("Register with DSIT as an MSP regulated entity. Appoint a named compliance contact for CS&R Bill obligations.")
        score = 0.3  # Reduce score as MSP has additional obligations
    else:
        obligations.append({
            "obligation": "Assess whether MSP suppliers are CS&R Bill regulated entities",
            "met": False,
            "evidence": "MSP relationship review required",
            "gap": "Verify if any of your IT service providers are newly regulated under the CS&R Bill",
        })
        gaps.append("Verify whether your managed IT service providers (MSPs, cloud providers) are subject to CS&R Bill obligations — their compliance directly affects your security.")
        remediation.append("Ask all MSPs and IT service providers for their CS&R Bill compliance status. Include CS&R Bill clause in MSP contracts.")
        score = 0.5

    obligations.append({
        "obligation": "Ensure MSP contracts include CS&R Bill security and reporting obligations",
        "met": False,
        "evidence": "Requires contract review",
        "gap": "MSP contracts must be reviewed against CS&R Bill obligations",
    })
    gaps.append("MSP contracts must be updated to reflect CS&R Bill obligations: security standards, incident reporting, right-to-audit.")
    remediation.append("Engage legal counsel to review and update all MSP contracts for CS&R Bill compliance clauses.")

    return CSRDomainResult(
        domain_id="CSR-4", domain_name="Managed Service Provider Obligations",
        status=_csr_status(score), score=score,
        obligations=obligations, gaps=gaps, remediation=remediation,
        bill_ref="CS&R Bill — Part 4 (MSP Provisions)",
        is_new_obligation=True,
    )


# ---------------------------------------------------------------------------
# CSR-5: Security Governance and Accountability
# ---------------------------------------------------------------------------

def _csr5_governance(db: Session, tenant_id: str) -> CSRDomainResult:
    gaps, remediation = [], []
    obligations = []
    score = 0.4

    # Check posture record as evidence of governance programme
    try:
        from models.posture_record import PostureRecord
        posture = db.query(PostureRecord).filter(
            PostureRecord.tenant_id == tenant_id,
        ).first()
        posture_met = posture is not None
    except Exception:
        posture_met = False

    obligations.append({
        "obligation": "Maintain documented security governance programme with board accountability",
        "met": posture_met,
        "evidence": "Active posture record programme" if posture_met else "No posture governance programme",
        "gap": "" if posture_met else "No formal governance programme — CS&R Bill requires board accountability for cyber security",
    })
    if posture_met:
        score += 0.25
        gaps.append("Posture record active — governance programme evidence generated. Board-level reporting cadence requires human confirmation.")
    else:
        gaps.append("CS&R Bill requires senior management accountability for cyber security. A named board member must own security obligations.")
        remediation.append("Assign a named board member or equivalent as Security Accountable Person for CS&R Bill compliance.")

    obligations.append({
        "obligation": "Designate a named Accountable Person for CS&R Bill compliance",
        "met": False,
        "evidence": "Requires organisational confirmation",
        "gap": "Named Accountable Person designation requires human process",
    })
    remediation.append("Document: (1) Named Accountable Person, (2) Their CS&R Bill obligations, (3) Escalation path to DSIT if required.")

    obligations.append({
        "obligation": "Maintain audit trail of security decisions for regulatory inspection",
        "met": posture_met,
        "evidence": "CyberAssetIQ posture history and compliance runs provide audit trail" if posture_met else "No audit trail",
        "gap": "" if posture_met else "No audit trail — regulators may inspect security decision records",
    })
    if posture_met:
        score += 0.15

    remediation.append("Use CyberAssetIQ posture record history as your primary technical audit trail for CS&R Bill regulatory inspection.")
    remediation.append("Supplement with board minutes documenting security risk decisions and approvals.")

    return CSRDomainResult(
        domain_id="CSR-5", domain_name="Security Governance and Accountability",
        status=_csr_status(score), score=score,
        obligations=obligations, gaps=gaps, remediation=remediation,
        bill_ref="CS&R Bill — Part 1 (Governance Duties)",
        is_new_obligation=False,
    )


# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------

def assess_csr_bill(db: Session, tenant_id: str) -> CSRBillReport:
    """Run full CS&R Bill compliance assessment for a tenant."""

    domains = [
        _csr1_supply_chain(db, tenant_id),
        _csr2_incident_reporting(db, tenant_id),
        _csr3_nis_security(db, tenant_id),
        _csr4_msp_obligations(db, tenant_id),
        _csr5_governance(db, tenant_id),
    ]

    overall_score = sum(d.score for d in domains) / len(domains)

    supply_chain_met = domains[0].status in ("COMPLIANT", "PARTIALLY_COMPLIANT")
    incident_ready   = domains[1].score >= 0.5

    nis_gaps = [
        g for d in domains
        for g in d.gaps
        if "NIS" in g or "reporting" in g.lower() or "notification" in g.lower()
    ]

    top_obligations = [
        g for d in sorted(domains, key=lambda x: x.score)
        for g in d.gaps[:1]
    ][:5]

    as_posture_controls = {
        "framework": FRAMEWORK_NAME,
        "version": FRAMEWORK_VERSION,
        "overall_score": round(overall_score * 100),
        "overall_status": _csr_status(overall_score),
        "supply_chain_obligation_met": supply_chain_met,
        "incident_reporting_ready": incident_ready,
        "domain_scores": {
            d.domain_id: {
                "name": d.domain_name,
                "score": round(d.score * 100),
                "status": d.status,
                "is_new_obligation": d.is_new_obligation,
            }
            for d in domains
        },
        "new_obligations_count": sum(1 for d in domains if d.is_new_obligation),
        "compliant_domains": sum(1 for d in domains if d.status == "COMPLIANT"),
    }

    return CSRBillReport(
        tenant_id=tenant_id,
        framework=FRAMEWORK_NAME,
        assessed_at=datetime.now(timezone.utc).isoformat(),
        overall_score=overall_score,
        overall_status=_csr_status(overall_score),
        domains=domains,
        supply_chain_obligation_met=supply_chain_met,
        incident_reporting_ready=incident_ready,
        nis_upgrade_gaps=nis_gaps[:5],
        top_obligations_to_address=top_obligations,
        as_posture_controls=as_posture_controls,
    )
