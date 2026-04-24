from __future__ import annotations

"""
CyberAssetIQ — Adversarial Lab

Deterministic attack chain simulation engine. Takes an API description,
auth type, data classification, and optional linked asset/scan — returns:
  - Three scores: attack surface, exploitability, business impact
  - Step-by-step attack chain with technique, outcome, severity
  - Plain-English attack story narrative
  - CE v3.2 control mapping per attack step
"""

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db
from models.mixins import Base, TimestampMixin

router = APIRouter()


# ---------------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------------

class AdversarialSimulation(TimestampMixin, Base):
    __tablename__ = "adversarial_simulations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    sim_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sim_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_api: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data_classification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    internet_exposed: Mapped[bool] = mapped_column(default=False)
    personal_data: Mapped[bool] = mapped_column(default=False)
    attack_surface_score: Mapped[int] = mapped_column(default=0)
    exploitability_score: Mapped[int] = mapped_column(default=0)
    business_impact_score: Mapped[int] = mapped_column(default=0)
    overall_risk: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


# ---------------------------------------------------------------------------
# CE v3.2 control mapping
# ---------------------------------------------------------------------------

_CE_CONTROLS = {
    "A1": "Asset Management",
    "A2": "User Access Control",
    "A3": "Secure Configuration",
    "A4": "Vulnerability Management",
    "A5": "Patch Management",
    "A6": "Malware Protection",
    "A7": "Network Security",
    "A8": "Removable Media Controls",
}

# ---------------------------------------------------------------------------
# Attack technique library
# ---------------------------------------------------------------------------

_TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "RECON-01",
        "name": "Passive Reconnaissance",
        "condition": lambda i: i["internet_exposed"],
        "description": "Attacker scans public sources (Shodan, Certificate Transparency, LinkedIn) to map the target API surface, technology stack, and employee roles.",
        "outcome": "API endpoint patterns, technology versions, and employee email formats confirmed.",
        "severity": "medium",
        "ce_controls": ["A1", "A7"],
        "ce_explanations": {
            "A1": "Incomplete asset inventory means the organisation does not know what is publicly visible.",
            "A7": "No boundary controls prevent reconnaissance of exposed services.",
        },
        "recommendations": [
            "Audit all public-facing endpoints and remove unnecessary exposure.",
            "Enable network perimeter monitoring to detect reconnaissance activity.",
            "Review what information is exposed in job postings, GitHub repos, and DNS records.",
        ],
    },
    {
        "id": "AUTH-01",
        "name": "Token / Key Enumeration",
        "condition": lambda i: i["auth_type"] in ("JWT", "API key", "None"),
        "description": "Attacker attempts to enumerate or brute-force authentication tokens using known patterns for the detected auth mechanism.",
        "outcome": "Valid API key or JWT token obtained through enumeration or credential reuse from previous breaches.",
        "severity": "high",
        "ce_controls": ["A2", "A3"],
        "ce_explanations": {
            "A2": "Weak or absent access controls allow unauthorised authentication.",
            "A3": "Default or weak authentication configuration increases enumeration risk.",
        },
        "recommendations": [
            "Implement rate limiting on authentication endpoints.",
            "Use short-lived JWT tokens (max 15 minutes) with refresh token rotation.",
            "Enable account lockout after 5 failed attempts.",
            "Audit all API keys for age and rotate any older than 90 days.",
        ],
    },
    {
        "id": "AUTH-02",
        "name": "No Authentication Bypass",
        "condition": lambda i: i["auth_type"] == "None",
        "description": "API has no authentication mechanism. Attacker accesses all endpoints directly without credentials.",
        "outcome": "Full unauthenticated access to all API resources.",
        "severity": "critical",
        "ce_controls": ["A2", "A3"],
        "ce_explanations": {
            "A2": "No access control in place — CE A2 requirement completely unmet.",
            "A3": "Unauthenticated APIs are a fundamental secure configuration failure.",
        },
        "recommendations": [
            "Implement authentication immediately — JWT or OAuth2 are recommended.",
            "Add an API gateway to enforce authentication at the perimeter.",
            "Conduct an urgent review of all data accessible without credentials.",
        ],
    },
    {
        "id": "CRED-01",
        "name": "Credential Reuse from Breach Data",
        "condition": lambda i: i.get("linked_scan_findings", 0) > 0,
        "description": f"Attacker uses credentials found in linked credential scan directly against the API.",
        "outcome": "Authentication succeeded using credentials extracted from scanned config files.",
        "severity": "critical",
        "ce_controls": ["A2", "A3", "A4"],
        "ce_explanations": {
            "A2": "Hardcoded credentials bypass intended access controls entirely.",
            "A3": "Credentials in config files indicate misconfigured secrets management.",
            "A4": "Failure to detect and rotate exposed credentials is a vulnerability management gap.",
        },
        "recommendations": [
            "Revoke all credentials found in the linked scan immediately.",
            "Implement a secrets management solution (HashiCorp Vault, AWS Secrets Manager).",
            "Add pre-commit hooks to prevent secrets from entering version control.",
            "Run credential scans on all config files before deployment.",
        ],
    },
    {
        "id": "AUTHZ-01",
        "name": "Horizontal Privilege Escalation",
        "condition": lambda i: i["auth_type"] in ("JWT", "Session cookie", "OAuth2"),
        "description": "Attacker manipulates resource identifiers (IDs, UUIDs) in API requests to access data belonging to other users.",
        "outcome": "Attacker accesses records belonging to other users by iterating resource IDs.",
        "severity": "high",
        "ce_controls": ["A2", "A3"],
        "ce_explanations": {
            "A2": "Missing object-level authorisation checks allow cross-user data access.",
            "A3": "API does not enforce resource ownership checks — secure configuration gap.",
        },
        "recommendations": [
            "Implement object-level authorisation on every endpoint.",
            "Use unpredictable UUIDs rather than sequential integer IDs.",
            "Add automated tests specifically targeting IDOR vulnerabilities.",
        ],
    },
    {
        "id": "AUTHZ-02",
        "name": "Vertical Privilege Escalation",
        "condition": lambda i: i["auth_type"] in ("JWT", "API key"),
        "description": "Attacker modifies JWT claims or API key scope to gain admin-level access from a standard user token.",
        "outcome": "Admin API endpoints accessed using a modified standard user token.",
        "severity": "critical",
        "ce_controls": ["A2", "A3"],
        "ce_explanations": {
            "A2": "Role enforcement absent at the API level — admin functions accessible to standard users.",
            "A3": "JWT signature not validated server-side — critical configuration failure.",
        },
        "recommendations": [
            "Validate JWT signature and claims server-side on every request.",
            "Never trust client-supplied role or permission claims without server verification.",
            "Implement role-based access control (RBAC) enforced at the API gateway layer.",
        ],
    },
    {
        "id": "DATA-01",
        "name": "Sensitive Data Exfiltration",
        "condition": lambda i: i["data_classification"] in ("Customer", "Financial", "Health", "PII"),
        "description": "With authenticated access established, attacker exports bulk sensitive data through the API export endpoint.",
        "outcome": f"Bulk data export completed. Personal and sensitive records exfiltrated.",
        "severity": "critical",
        "ce_controls": ["A1", "A2", "A7"],
        "ce_explanations": {
            "A1": "Without a complete asset inventory, data flows cannot be monitored or controlled.",
            "A2": "Bulk export available to authenticated users without elevated approval.",
            "A7": "No egress controls or data loss prevention to detect bulk export.",
        },
        "recommendations": [
            "Implement rate limiting and anomaly detection on data export endpoints.",
            "Require additional authentication (MFA) for bulk data exports.",
            "Log and alert on export requests exceeding defined thresholds.",
            "Mask or tokenise PII in API responses where full values are not required.",
        ],
    },
    {
        "id": "ASSET-01",
        "name": "Exploitation of Unpatched Asset",
        "condition": lambda i: i.get("linked_asset_outdated", False),
        "description": "The linked asset is marked as outdated. Attacker exploits known CVEs in the unpatched OS or application stack hosting this API.",
        "outcome": "Remote code execution achieved via known CVE in unpatched dependency.",
        "severity": "critical",
        "ce_controls": ["A4", "A5"],
        "ce_explanations": {
            "A4": "Known vulnerabilities not remediated — CE A4 requirement unmet.",
            "A5": "Asset not patched within the 14-day CE requirement window.",
        },
        "recommendations": [
            "Apply all outstanding security patches to the linked asset immediately.",
            "Implement automated patch management with a maximum 14-day window.",
            "Run a CVE scan against all software on this asset.",
            "Isolate the asset from other network segments until patched.",
        ],
    },
    {
        "id": "PERSIST-01",
        "name": "Persistence via API Key Creation",
        "condition": lambda i: i["auth_type"] != "None",
        "description": "Having gained access, attacker creates a new long-lived API key or admin account to maintain persistent access even after the original compromised credential is rotated.",
        "outcome": "Backdoor API key created. Attacker retains access after incident response.",
        "severity": "high",
        "ce_controls": ["A2", "A3"],
        "ce_explanations": {
            "A2": "No controls prevent creation of additional privileged credentials.",
            "A3": "API key lifecycle management not enforced — backdoor creation possible.",
        },
        "recommendations": [
            "Implement alerts for any new admin-level API key creation.",
            "Enforce MFA for credential management operations.",
            "Audit all API keys after any suspected compromise — revoke all and rotate.",
            "Set maximum API key lifetimes and enforce automatic expiry.",
        ],
    },
    {
        "id": "IMPACT-01",
        "name": "Data Manipulation or Destruction",
        "condition": lambda i: i["auth_type"] != "None" and i["data_classification"] != "Public",
        "description": "With persistent access established, attacker modifies or deletes critical records to cause operational disruption or cover their tracks.",
        "outcome": "Critical data modified or deleted. Business operations disrupted.",
        "severity": "critical",
        "ce_controls": ["A1", "A2", "A3"],
        "ce_explanations": {
            "A1": "Without asset management, data integrity cannot be guaranteed or audited.",
            "A2": "Write access not restricted to authorised users only.",
            "A3": "No audit logging in place to detect or reconstruct unauthorised changes.",
        },
        "recommendations": [
            "Implement immutable audit logs for all data modification operations.",
            "Apply principle of least privilege — most users should have read-only access.",
            "Enable point-in-time recovery for all critical databases.",
            "Implement change approval workflows for sensitive data modifications.",
        ],
    },
]


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

def _run_simulation(inputs: dict[str, Any]) -> dict[str, Any]:
    steps = []
    for technique in _TECHNIQUES:
        try:
            if technique["condition"](inputs):
                steps.append({
                    "step_id": technique["id"],
                    "name": technique["name"],
                    "description": technique["description"],
                    "outcome": technique["outcome"],
                    "severity": technique["severity"],
                    "ce_controls": technique["ce_controls"],
                    "ce_explanations": technique["ce_explanations"],
                    "recommendations": technique["recommendations"],
                })
        except Exception:
            continue

    # Score calculation
    sev_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    raw_surface = sum(sev_weights.get(s["severity"], 5) for s in steps)
    attack_surface = min(100, raw_surface)

    critical_count = sum(1 for s in steps if s["severity"] == "critical")
    exploitability = min(100, critical_count * 30 + len(steps) * 5)

    impact_base = 20
    if inputs["personal_data"]:
        impact_base += 30
    if inputs["data_classification"] in ("Financial", "Health"):
        impact_base += 20
    if inputs["internet_exposed"]:
        impact_base += 15
    if inputs.get("linked_asset_outdated"):
        impact_base += 15
    business_impact = min(100, impact_base)

    avg = (attack_surface + exploitability + business_impact) / 3
    if avg >= 75:
        overall_risk = "CRITICAL"
    elif avg >= 60:
        overall_risk = "HIGH"
    elif avg >= 40:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Build attack story
    story_lines = []
    for i, step in enumerate(steps, 1):
        story_lines.append(f"Step {i} — {step['name']}: {step['description']} {step['outcome']}")

    blast_radius_parts = []
    if inputs["personal_data"]:
        blast_radius_parts.append("personal data of all users")
    if inputs["data_classification"] != "Public":
        blast_radius_parts.append(f"{inputs['data_classification'].lower()} records")
    if inputs.get("linked_asset_outdated"):
        blast_radius_parts.append("the host server and potentially adjacent systems")
    blast_radius = "Potential breach of " + (", ".join(blast_radius_parts) or "internal API data") + "."

    business_impact_statement = (
        f"A successful attack chain against this API would result in {'a notifiable data breach under UK GDPR, ' if inputs['personal_data'] else ''}"
        f"reputational damage, and potential regulatory fines. "
        f"Recovery would require incident response, forensic investigation, and customer notification. "
        f"CE v3.2 certification would be blocked until all identified gaps are remediated."
    )

    # CE compliance translation
    ce_summary: dict[str, dict] = {}
    for step in steps:
        for ctrl_id in step["ce_controls"]:
            if ctrl_id not in ce_summary:
                ce_summary[ctrl_id] = {
                    "control_id": ctrl_id,
                    "control_name": _CE_CONTROLS.get(ctrl_id, ctrl_id),
                    "weakened_by": [],
                    "business_consequence": "",
                }
            ce_summary[ctrl_id]["weakened_by"].append({
                "technique": step["name"],
                "explanation": step["ce_explanations"].get(ctrl_id, ""),
            })

    for ctrl_id, ctrl in ce_summary.items():
        count = len(ctrl["weakened_by"])
        ctrl["business_consequence"] = (
            f"{ctrl['control_name']} is weakened by {count} attack technique(s) in this chain. "
            f"Address the recommendations for each technique to restore CE compliance for this control."
        )

    return {
        "steps": steps,
        "attack_surface_score": attack_surface,
        "exploitability_score": exploitability,
        "business_impact_score": business_impact,
        "overall_risk": overall_risk,
        "attack_story": {
            "summary": f"A {overall_risk.lower()}-risk attack chain of {len(steps)} technique(s) was identified against {inputs.get('target_api', 'this API')}.",
            "steps": story_lines,
            "blast_radius": blast_radius,
            "business_impact": business_impact_statement,
        },
        "ce_compliance_translation": list(ce_summary.values()),
    }


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SimulationRequest(BaseModel):
    sim_name: str | None = None
    target_api: str | None = None
    api_description: str | None = None
    auth_type: str = "API key"  # JWT | API key | OAuth2 | Session cookie | None
    data_classification: str = "Internal"  # Public | Internal | Customer | Financial | Health | PII
    internet_exposed: bool = False
    personal_data: bool = False
    linked_asset_id: str | None = None
    linked_scan_id: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/simulate")
def run_simulation(
    payload: SimulationRequest,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    # Check linked asset for outdated status
    linked_asset_outdated = False
    if payload.linked_asset_id:
        from models.telemetry import SecurityPostureEvent
        posture = (
            db.query(SecurityPostureEvent)
            .filter(
                SecurityPostureEvent.tenant_id == auth.tenant_id,
                SecurityPostureEvent.agent_id == payload.linked_asset_id,
            )
            .order_by(SecurityPostureEvent.id.desc())
            .first()
        )
        if posture and posture.posture_json:
            patch = posture.posture_json.get("patch_status", "")
            linked_asset_outdated = patch.lower() in ("outdated", "unknown", "missing")

    # Check linked scan for findings
    linked_scan_findings = 0
    if payload.linked_scan_id:
        scan = (
            db.query(AdversarialSimulation)
            .filter(AdversarialSimulation.sim_id == payload.linked_scan_id)
            .first()
        )
        # Try credential scan instead
        from api.routes.scanner import CredentialScan
        cred_scan = (
            db.query(CredentialScan)
            .filter(
                CredentialScan.tenant_id == auth.tenant_id,
                CredentialScan.scan_id == payload.linked_scan_id,
            )
            .first()
        )
        if cred_scan:
            linked_scan_findings = cred_scan.finding_count

    inputs = {
        "target_api": payload.target_api or "unknown endpoint",
        "auth_type": payload.auth_type,
        "data_classification": payload.data_classification,
        "internet_exposed": payload.internet_exposed,
        "personal_data": payload.personal_data,
        "linked_asset_outdated": linked_asset_outdated,
        "linked_scan_findings": linked_scan_findings,
    }

    result = _run_simulation(inputs)
    sim_id = f"sim_{uuid.uuid4().hex[:16]}"

    record = AdversarialSimulation(
        tenant_id=auth.tenant_id,
        sim_id=sim_id,
        sim_name=payload.sim_name,
        target_api=payload.target_api,
        auth_type=payload.auth_type,
        data_classification=payload.data_classification,
        internet_exposed=payload.internet_exposed,
        personal_data=payload.personal_data,
        attack_surface_score=result["attack_surface_score"],
        exploitability_score=result["exploitability_score"],
        business_impact_score=result["business_impact_score"],
        overall_risk=result["overall_risk"],
        result_json=result,
    )
    db.add(record)
    db.commit()

    return {"sim_id": sim_id, **result}


@router.get("/simulations")
def list_simulations(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    sims = (
        db.query(AdversarialSimulation)
        .filter(AdversarialSimulation.tenant_id == auth.tenant_id)
        .order_by(AdversarialSimulation.id.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": s.id,
            "sim_id": s.sim_id,
            "sim_name": s.sim_name or "Unnamed simulation",
            "target_api": s.target_api,
            "overall_risk": s.overall_risk,
            "attack_surface_score": s.attack_surface_score,
            "exploitability_score": s.exploitability_score,
            "business_impact_score": s.business_impact_score,
            "created_at": str(s.created_at),
        }
        for s in sims
    ]


@router.get("/simulations/{sim_id}")
def get_simulation(
    sim_id: str,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    sim = (
        db.query(AdversarialSimulation)
        .filter(
            AdversarialSimulation.tenant_id == auth.tenant_id,
            AdversarialSimulation.sim_id == sim_id,
        )
        .first()
    )
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return {"sim_id": sim.sim_id, **(sim.result_json or {})}
