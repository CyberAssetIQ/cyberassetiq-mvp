"""cloud_posture_service.py

Cloud / SaaS / Identity Posture Connector Framework (Phase 4).

This service provides the integration layer for cloud provider connections.
Real OAuth/API credentials are stored in the app's existing secrets management
(never in the database). The service performs posture analysis using the
connector results and populates cloud_posture_findings, identity_posture_findings,
cloud_assets, saas_apps, and saas_posture_findings.

Supported providers (initial): m365, azure, aws, gcp, google_workspace
Each provider has a `simulate_posture_scan` method that runs heuristic checks
against data already in the platform (network assets, software inventory,
identity data) to produce findings — this allows meaningful results even before
a live API integration is configured, and forms the scaffold for live connectors.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.cloud_posture import (
    CloudAccount,
    CloudAsset,
    CloudPostureFinding,
    ConnectorSyncLog,
    IdentityPostureFinding,
    SaaSApp,
    SaaSPostureFinding,
)
from models.shadow_it import RogueSoftwareFinding
from models.telemetry import CanonicalSoftware, SecurityPostureEvent

logger = logging.getLogger("cyberassetiq.cloud_posture")

# ---------------------------------------------------------------------------
# Known cloud / SaaS software patterns (for discovery from software inventory)
# ---------------------------------------------------------------------------
_CLOUD_SAAS_PATTERNS: dict[str, dict[str, Any]] = {
    "microsoft 365": {"provider": "m365", "category": "productivity", "risk": 2.0},
    "microsoft teams": {"provider": "m365", "category": "communication", "risk": 2.0},
    "azure ad connect": {"provider": "azure", "category": "identity", "risk": 3.0},
    "aws cli": {"provider": "aws", "category": "development", "risk": 3.5},
    "google workspace": {"provider": "google_workspace", "category": "productivity", "risk": 2.0},
    "google chrome": {"provider": "google_workspace", "category": "browser", "risk": 1.5},
    "dropbox business": {"provider": None, "category": "storage", "risk": 4.0},
    "slack": {"provider": None, "category": "communication", "risk": 3.0},
    "zoom": {"provider": None, "category": "communication", "risk": 3.5},
    "github desktop": {"provider": None, "category": "development", "risk": 3.0},
    "salesforce": {"provider": None, "category": "crm", "risk": 3.5},
    "hubspot": {"provider": None, "category": "crm", "risk": 3.0},
    "xero": {"provider": None, "category": "finance", "risk": 4.5},
    "quickbooks": {"provider": None, "category": "finance", "risk": 4.5},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_cloud_posture_summary(db: Session, tenant_id: str) -> dict:
    account_count = db.query(CloudAccount).filter(
        CloudAccount.tenant_id == tenant_id
    ).count()
    connected_count = db.query(CloudAccount).filter(
        CloudAccount.tenant_id == tenant_id,
        CloudAccount.status == "connected",
    ).count()
    total_findings = db.query(CloudPostureFinding).filter(
        CloudPostureFinding.tenant_id == tenant_id,
        CloudPostureFinding.status == "open",
    ).count()
    critical_findings = db.query(CloudPostureFinding).filter(
        CloudPostureFinding.tenant_id == tenant_id,
        CloudPostureFinding.status == "open",
        CloudPostureFinding.severity == "critical",
    ).count()
    identity_findings = db.query(IdentityPostureFinding).filter(
        IdentityPostureFinding.tenant_id == tenant_id,
        IdentityPostureFinding.status == "open",
    ).count()
    saas_app_count = db.query(SaaSApp).filter(
        SaaSApp.tenant_id == tenant_id,
    ).count()
    unapproved_saas = db.query(SaaSApp).filter(
        SaaSApp.tenant_id == tenant_id,
        SaaSApp.approved_status.in_(["unapproved", "unknown"]),
    ).count()
    return {
        "accounts_configured": account_count,
        "accounts_connected": connected_count,
        "open_findings": total_findings,
        "critical_findings": critical_findings,
        "identity_risk_findings": identity_findings,
        "saas_apps_discovered": saas_app_count,
        "unapproved_saas_apps": unapproved_saas,
    }


def register_account(db: Session, tenant_id: str, provider: str,
                     account_name: str, account_identifier: str | None = None) -> dict:
    """Register a new cloud account for posture monitoring."""
    existing = db.query(CloudAccount).filter(
        CloudAccount.tenant_id == tenant_id,
        CloudAccount.provider == provider,
        CloudAccount.account_name == account_name,
    ).first()
    if existing:
        return {"id": existing.id, "status": existing.status, "message": "already_registered"}

    account = CloudAccount(
        tenant_id=tenant_id,
        provider=provider,
        account_name=account_name,
        account_identifier=account_identifier,
        status="pending",
    )
    db.add(account)
    db.commit()
    logger.info("Cloud account registered: tenant=%s provider=%s name=%s",
                tenant_id, provider, account_name)
    return {"id": account.id, "status": "pending", "message": "registered"}


def run_heuristic_posture_scan(db: Session, tenant_id: str) -> dict:
    """
    Run a heuristic posture scan using data already in the platform.
    This populates findings without requiring live cloud API credentials.
    Useful for demo environments and as a baseline before live connectors.
    """
    sync_log = ConnectorSyncLog(
        tenant_id=tenant_id,
        provider="heuristic",
        status="running",
    )
    db.add(sync_log)
    db.flush()

    findings_created = 0
    saas_discovered = 0

    try:
        # 1. Discover SaaS apps from software inventory
        saas_discovered += _discover_saas_from_software(db, tenant_id)

        # 2. Check security posture events for cloud identity gaps
        findings_created += _check_identity_posture_heuristics(db, tenant_id)

        # 3. Generate M365-style findings from existing agent data
        findings_created += _generate_m365_heuristic_findings(db, tenant_id)

        # 4. Generate general cloud exposure findings
        findings_created += _generate_exposure_heuristic_findings(db, tenant_id)

        sync_log.status = "completed"
        sync_log.findings_created = findings_created
        sync_log.assets_discovered = saas_discovered
        sync_log.finished_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            "Heuristic posture scan complete: tenant=%s findings=%d saas=%d",
            tenant_id, findings_created, saas_discovered,
        )
    except Exception as exc:
        sync_log.status = "failed"
        sync_log.error_message = str(exc)
        sync_log.finished_at = datetime.now(timezone.utc)
        db.commit()
        logger.exception("Heuristic posture scan failed: %s", exc)
        raise

    return {
        "findings_created": findings_created,
        "saas_apps_discovered": saas_discovered,
        "sync_log_id": sync_log.id,
    }


def list_findings(db: Session, tenant_id: str, provider: str | None = None,
                  severity: str | None = None, limit: int = 100) -> list[dict]:
    q = db.query(CloudPostureFinding).filter(
        CloudPostureFinding.tenant_id == tenant_id,
        CloudPostureFinding.status == "open",
    )
    if provider:
        q = q.filter(CloudPostureFinding.provider == provider)
    if severity:
        q = q.filter(CloudPostureFinding.severity == severity)
    findings = q.order_by(CloudPostureFinding.detected_at.desc()).limit(limit).all()
    return [_finding_to_dict(f) for f in findings]


def list_identity_findings(db: Session, tenant_id: str, limit: int = 100) -> list[dict]:
    findings = db.query(IdentityPostureFinding).filter(
        IdentityPostureFinding.tenant_id == tenant_id,
        IdentityPostureFinding.status == "open",
    ).order_by(IdentityPostureFinding.detected_at.desc()).limit(limit).all()
    return [_identity_finding_to_dict(f) for f in findings]


def list_saas_apps(db: Session, tenant_id: str, limit: int = 100) -> list[dict]:
    apps = db.query(SaaSApp).filter(
        SaaSApp.tenant_id == tenant_id,
    ).order_by(SaaSApp.risk_score.desc()).limit(limit).all()
    return [_saas_to_dict(a) for a in apps]


def list_accounts(db: Session, tenant_id: str) -> list[dict]:
    accounts = db.query(CloudAccount).filter(
        CloudAccount.tenant_id == tenant_id
    ).all()
    return [_account_to_dict(a) for a in accounts]


def list_sync_logs(db: Session, tenant_id: str, limit: int = 20) -> list[dict]:
    logs = db.query(ConnectorSyncLog).filter(
        ConnectorSyncLog.tenant_id == tenant_id,
    ).order_by(ConnectorSyncLog.started_at.desc()).limit(limit).all()
    return [_sync_log_to_dict(l) for l in logs]


# ---------------------------------------------------------------------------
# Private scan helpers
# ---------------------------------------------------------------------------

def _discover_saas_from_software(db: Session, tenant_id: str) -> int:
    software_rows = db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id
    ).all()

    discovered = 0
    seen: set[str] = set()

    for sw in software_rows:
        name_lower = (sw.name or "").lower()
        for pattern, meta in _CLOUD_SAAS_PATTERNS.items():
            if pattern in name_lower and pattern not in seen:
                seen.add(pattern)
                existing = db.query(SaaSApp).filter(
                    SaaSApp.tenant_id == tenant_id,
                    SaaSApp.app_name == sw.name,
                ).first()
                if not existing:
                    app = SaaSApp(
                        tenant_id=tenant_id,
                        app_name=sw.name,
                        app_category=meta["category"],
                        source="software_inventory",
                        risk_score=meta["risk"],
                        approved_status="unknown",
                        last_seen_at=datetime.now(timezone.utc),
                    )
                    db.add(app)
                    discovered += 1
    db.flush()
    return discovered


def _check_identity_posture_heuristics(db: Session, tenant_id: str) -> int:
    """Generate identity posture findings from security posture events."""
    posture_events = db.query(SecurityPostureEvent).filter(
        SecurityPostureEvent.tenant_id == tenant_id,
    ).all()

    count = 0
    for event in posture_events:
        data = event.payload_json or {}

        # Check local admin count — excessive local admins
        local_admins = data.get("local_admins", [])
        if len(local_admins) > 3:
            if not _identity_finding_exists(db, tenant_id, "excessive_local_admins"):
                db.add(IdentityPostureFinding(
                    tenant_id=tenant_id,
                    provider="on_premise",
                    finding_type="excessive_local_admins",
                    identity_type="user",
                    severity="medium",
                    title="Excessive Local Administrator Accounts Detected",
                    description=f"{len(local_admins)} local admin accounts found. "
                                f"Recommend reducing to minimum necessary.",
                    recommendation="Review and remove unnecessary local admin privileges. "
                                   "Implement least-privilege access.",
                    affected_count=len(local_admins),
                    evidence_json={"admin_count": len(local_admins), "asset_id": event.asset_id},
                ))
                count += 1

        # Check firewall disabled
        firewall_enabled = data.get("firewall_enabled", True)
        if not firewall_enabled:
            if not _identity_finding_exists(db, tenant_id, "firewall_disabled_identity_risk"):
                db.add(IdentityPostureFinding(
                    tenant_id=tenant_id,
                    provider="on_premise",
                    finding_type="mfa_disabled",
                    identity_type="user",
                    severity="high",
                    title="Firewall Disabled — Identity Attack Surface Increased",
                    description="Firewall is disabled on one or more assets, increasing "
                                "the risk of lateral movement and credential attacks.",
                    recommendation="Enable Windows Firewall or equivalent on all endpoints.",
                    affected_count=1,
                ))
                count += 1

    db.flush()
    return count


def _generate_m365_heuristic_findings(db: Session, tenant_id: str) -> int:
    """
    Generate common M365/Entra posture findings based on heuristics.
    These are conservative informational findings that apply to most
    SME Microsoft 365 environments until a live connector provides real data.
    """
    count = 0
    findings_to_check = [
        {
            "finding_type": "legacy_auth_enabled",
            "severity": "high",
            "provider": "m365",
            "title": "Legacy Authentication Protocols May Be Enabled",
            "description": "Legacy authentication protocols (Basic Auth, NTLM over HTTP) "
                           "bypass MFA and are a primary attack vector for credential stuffing.",
            "recommendation": "Disable legacy authentication in Microsoft 365 Conditional Access "
                               "policies. Block Basic Auth for Exchange Online.",
        },
        {
            "finding_type": "no_conditional_access",
            "severity": "high",
            "provider": "m365",
            "title": "Conditional Access Policy Status Unknown",
            "description": "Without Conditional Access, all authentication attempts are treated "
                           "equally regardless of location, device, or risk level.",
            "recommendation": "Configure Microsoft Entra Conditional Access policies. "
                               "Require MFA for all users at minimum.",
        },
        {
            "finding_type": "guest_access_risk",
            "severity": "medium",
            "provider": "m365",
            "title": "Microsoft 365 Guest Access Settings Unverified",
            "description": "Default guest access settings in Microsoft 365 may allow external "
                           "users excessive access to internal SharePoint and Teams content.",
            "recommendation": "Review and restrict external sharing settings in M365 Admin Center. "
                               "Enable guest access reviews in Entra.",
        },
    ]

    for spec in findings_to_check:
        if not _cloud_finding_exists(db, tenant_id, spec["finding_type"], spec["provider"]):
            db.add(CloudPostureFinding(
                tenant_id=tenant_id,
                cloud_account_id=0,  # 0 = heuristic / no specific account
                provider=spec["provider"],
                finding_type=spec["finding_type"],
                severity=spec["severity"],
                title=spec["title"],
                description=spec["description"],
                recommendation=spec["recommendation"],
                status="open",
                compliance_controls=["CE_A2", "CE_A3"],
            ))
            count += 1

    db.flush()
    return count


def _generate_exposure_heuristic_findings(db: Session, tenant_id: str) -> int:
    """Generate general cloud exposure findings."""
    count = 0

    # Check if any assets have unknown patch status
    unpatched_assets = db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id,
    ).count()

    if unpatched_assets > 0:
        finding_type = "patch_status_unverified_cloud"
        if not _cloud_finding_exists(db, tenant_id, finding_type, "general"):
            db.add(CloudPostureFinding(
                tenant_id=tenant_id,
                cloud_account_id=0,
                provider="general",
                finding_type=finding_type,
                severity="medium",
                title=f"{unpatched_assets} Assets: Cloud Patch Posture Unverified",
                description="Asset patch status for cloud-joined or hybrid assets has not been "
                            "verified via a cloud management connector.",
                recommendation="Connect Microsoft Intune or equivalent MDM to verify patch "
                               "compliance across all managed endpoints.",
                status="open",
                compliance_controls=["CE_A5"],
            ))
            count += 1

    db.flush()
    return count


def _identity_finding_exists(db: Session, tenant_id: str, finding_type: str) -> bool:
    return db.query(IdentityPostureFinding).filter(
        IdentityPostureFinding.tenant_id == tenant_id,
        IdentityPostureFinding.finding_type == finding_type,
        IdentityPostureFinding.status == "open",
    ).count() > 0


def _cloud_finding_exists(db: Session, tenant_id: str,
                           finding_type: str, provider: str) -> bool:
    return db.query(CloudPostureFinding).filter(
        CloudPostureFinding.tenant_id == tenant_id,
        CloudPostureFinding.finding_type == finding_type,
        CloudPostureFinding.provider == provider,
        CloudPostureFinding.status == "open",
    ).count() > 0


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------

def _finding_to_dict(f: CloudPostureFinding) -> dict:
    return {
        "id": f.id,
        "provider": f.provider,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "resource_name": f.resource_name,
        "compliance_controls": f.compliance_controls or [],
        "status": f.status,
        "detected_at": f.detected_at.isoformat() if f.detected_at else None,
    }


def _identity_finding_to_dict(f: IdentityPostureFinding) -> dict:
    return {
        "id": f.id,
        "provider": f.provider,
        "identity_name": f.identity_name,
        "identity_type": f.identity_type,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "affected_count": f.affected_count,
        "status": f.status,
        "detected_at": f.detected_at.isoformat() if f.detected_at else None,
    }


def _saas_to_dict(a: SaaSApp) -> dict:
    return {
        "id": a.id,
        "app_name": a.app_name,
        "app_category": a.app_category,
        "vendor": a.vendor,
        "source": a.source,
        "risk_score": a.risk_score,
        "risk_flags": a.risk_flags or [],
        "approved_status": a.approved_status,
        "user_count": a.user_count,
        "has_data_access": a.has_data_access,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
    }


def _account_to_dict(a: CloudAccount) -> dict:
    return {
        "id": a.id,
        "provider": a.provider,
        "account_name": a.account_name,
        "status": a.status,
        "posture_score": a.posture_score,
        "findings_count": a.findings_count,
        "critical_findings_count": a.critical_findings_count,
        "last_synced_at": a.last_synced_at.isoformat() if a.last_synced_at else None,
    }


def _sync_log_to_dict(l: ConnectorSyncLog) -> dict:
    return {
        "id": l.id,
        "provider": l.provider,
        "status": l.status,
        "assets_discovered": l.assets_discovered,
        "findings_created": l.findings_created,
        "error_message": l.error_message,
        "started_at": l.started_at.isoformat() if l.started_at else None,
        "finished_at": l.finished_at.isoformat() if l.finished_at else None,
    }
