"""msp_portfolio_service.py

MSP Portfolio Management (Phase 5).

Reads from:  canonical_assets, vulnerability_findings, exposure_findings,
             drift events, criticality profiles, risk snapshots, backup findings,
             cloud posture findings, compliance runs — all existing + new tables.
Writes to:   msp_accounts, msp_tenant_map, tenant_health_scores, portfolio_alerts.

The tenant health score is a composite 0–100 metric (higher = better security posture)
aggregated from risk, exposure, resilience, compliance, identity, patch, and drift signals.
It is cached in tenant_health_scores to avoid expensive real-time JOINs.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.backup_resilience import BackupRiskFinding
from models.cloud_posture import CloudPostureFinding
from models.compliance_run import ComplianceRun
from models.criticality import CrownJewelAsset
from models.drift import AssetDriftEvent
from models.msp import MSPAccount, MSPTenantMap, PortfolioAlert, TenantHealthScore
from models.network_extensions import ExposureFinding
from models.telemetry import VulnerabilityFinding

logger = logging.getLogger("cyberassetiq.msp")

# ---------------------------------------------------------------------------
# Scoring weights (must sum to 1.0)
# ---------------------------------------------------------------------------
_WEIGHTS = {
    "exposure":    0.25,
    "patch":       0.20,
    "compliance":  0.20,
    "resilience":  0.15,
    "drift":       0.10,
    "identity":    0.10,
}

_BAND_THRESHOLDS = [
    (80, "healthy"),
    (60, "low"),
    (40, "medium"),
    (20, "high"),
    (0,  "critical"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_portfolio_summary(db: Session, msp_tenant_id: str) -> dict:
    """Top-level summary for the MSP portfolio dashboard."""
    msp = db.query(MSPAccount).filter(
        MSPAccount.tenant_id == msp_tenant_id
    ).first()
    if not msp:
        return {"error": "MSP account not found — register via POST /api/msp/register"}

    mappings = db.query(MSPTenantMap).filter(
        MSPTenantMap.msp_account_id == msp.id,
        MSPTenantMap.is_active == True,
    ).all()

    managed_ids = [m.managed_tenant_id for m in mappings]

    scores = db.query(TenantHealthScore).filter(
        TenantHealthScore.msp_account_id == msp.id,
    ).all()

    score_map = {s.tenant_id: s for s in scores}
    avg_score = sum(s.overall_score for s in scores) / len(scores) if scores else 0
    critical_count = sum(1 for s in scores if s.severity_band == "critical")
    high_count = sum(1 for s in scores if s.severity_band == "high")

    open_alerts = db.query(PortfolioAlert).filter(
        PortfolioAlert.msp_account_id == msp.id,
        PortfolioAlert.status == "open",
    ).count()

    tenants_data = []
    for mapping in mappings:
        score_obj = score_map.get(mapping.managed_tenant_id)
        tenants_data.append({
            "tenant_id": mapping.managed_tenant_id,
            "client_name": mapping.client_name,
            "client_industry": mapping.client_industry,
            "relationship_type": mapping.relationship_type,
            "health": _health_score_to_dict(score_obj) if score_obj else None,
        })

    return {
        "msp_name": msp.name,
        "managed_tenants_count": len(managed_ids),
        "average_health_score": round(avg_score, 1),
        "critical_tenants": critical_count,
        "high_risk_tenants": high_count,
        "open_portfolio_alerts": open_alerts,
        "tenants": tenants_data,
    }


def register_msp(db: Session, tenant_id: str, name: str,
                 contact_email: str | None = None, plan: str = "msp_standard") -> dict:
    existing = db.query(MSPAccount).filter(
        MSPAccount.tenant_id == tenant_id
    ).first()
    if existing:
        return {"id": existing.id, "message": "already_registered", "name": existing.name}

    msp = MSPAccount(
        tenant_id=tenant_id,
        name=name,
        contact_email=contact_email,
        plan=plan,
        is_active=True,
    )
    db.add(msp)
    db.commit()
    logger.info("MSP account registered: tenant=%s name=%s", tenant_id, name)
    return {"id": msp.id, "name": name, "status": "registered"}


def add_managed_tenant(db: Session, msp_tenant_id: str, managed_tenant_id: str,
                       client_name: str | None = None,
                       client_industry: str | None = None,
                       relationship_type: str = "managed") -> dict:
    msp = _get_msp(db, msp_tenant_id)
    if not msp:
        return {"error": "MSP account not found"}

    existing = db.query(MSPTenantMap).filter(
        MSPTenantMap.msp_account_id == msp.id,
        MSPTenantMap.managed_tenant_id == managed_tenant_id,
    ).first()
    if existing:
        return {"id": existing.id, "message": "already_mapped"}

    mapping = MSPTenantMap(
        msp_account_id=msp.id,
        managed_tenant_id=managed_tenant_id,
        client_name=client_name,
        client_industry=client_industry,
        relationship_type=relationship_type,
        is_active=True,
    )
    db.add(mapping)
    msp.managed_tenants_count = db.query(MSPTenantMap).filter(
        MSPTenantMap.msp_account_id == msp.id,
        MSPTenantMap.is_active == True,
    ).count() + 1
    db.commit()
    return {"id": mapping.id, "managed_tenant_id": managed_tenant_id, "status": "mapped"}


def refresh_tenant_health(db: Session, msp_tenant_id: str,
                          managed_tenant_id: str) -> dict:
    """Recalculate and persist the health score for one managed tenant."""
    msp = _get_msp(db, msp_tenant_id)
    if not msp:
        return {"error": "MSP account not found"}

    scores = _compute_health_scores(db, managed_tenant_id)
    overall = _weighted_score(scores)
    band = _score_to_band(overall)

    existing = db.query(TenantHealthScore).filter(
        TenantHealthScore.tenant_id == managed_tenant_id,
        TenantHealthScore.msp_account_id == msp.id,
    ).first()

    delta_7d = 0.0
    if existing:
        delta_7d = overall - existing.overall_score
        existing.overall_score = overall
        existing.exposure_score = scores["exposure"]
        existing.resilience_score = scores["resilience"]
        existing.compliance_score = scores["compliance"]
        existing.identity_score = scores["identity"]
        existing.patch_score = scores["patch"]
        existing.drift_score = scores["drift"]
        existing.severity_band = band
        existing.delta_7d = delta_7d
        existing.score_breakdown_json = scores
        existing.asset_count = scores["_asset_count"]
        existing.critical_findings_count = scores["_critical_findings"]
        existing.open_cves_count = scores["_open_cves"]
        existing.unresolved_drift_count = scores["_drift_count"]
        existing.ce_compliance_pct = scores["_ce_pct"]
        existing.updated_at = datetime.now(timezone.utc)
    else:
        ths = TenantHealthScore(
            tenant_id=managed_tenant_id,
            msp_account_id=msp.id,
            overall_score=overall,
            exposure_score=scores["exposure"],
            resilience_score=scores["resilience"],
            compliance_score=scores["compliance"],
            identity_score=scores["identity"],
            patch_score=scores["patch"],
            drift_score=scores["drift"],
            severity_band=band,
            delta_7d=0.0,
            score_breakdown_json=scores,
            asset_count=scores["_asset_count"],
            critical_findings_count=scores["_critical_findings"],
            open_cves_count=scores["_open_cves"],
            unresolved_drift_count=scores["_drift_count"],
            ce_compliance_pct=scores["_ce_pct"],
        )
        db.add(ths)

    # Raise portfolio alerts for critical tenants
    if band in ("critical", "high"):
        _raise_portfolio_alert(
            db, msp.id, managed_tenant_id,
            alert_type="score_drop" if delta_7d < -5 else "high_risk_tenant",
            severity=band,
            title=f"Tenant risk band: {band.upper()}",
            summary=f"Overall health score: {overall:.0f}/100. "
                    f"Critical findings: {scores['_critical_findings']}.",
        )

    db.commit()

    return {
        "tenant_id": managed_tenant_id,
        "overall_score": round(overall, 1),
        "severity_band": band,
        "domain_scores": {k: round(v, 1) for k, v in scores.items()
                          if not k.startswith("_")},
        "delta_7d": round(delta_7d, 1),
    }


def refresh_all_tenants(db: Session, msp_tenant_id: str) -> dict:
    """Refresh health scores for all managed tenants."""
    msp = _get_msp(db, msp_tenant_id)
    if not msp:
        return {"error": "MSP account not found"}

    mappings = db.query(MSPTenantMap).filter(
        MSPTenantMap.msp_account_id == msp.id,
        MSPTenantMap.is_active == True,
    ).all()

    results = []
    for mapping in mappings:
        try:
            r = refresh_tenant_health(db, msp_tenant_id, mapping.managed_tenant_id)
            results.append(r)
        except Exception as exc:
            logger.exception("Health refresh failed for tenant %s: %s",
                             mapping.managed_tenant_id, exc)

    return {"refreshed": len(results), "results": results}


def get_tenant_summary(db: Session, msp_tenant_id: str,
                       managed_tenant_id: str) -> dict:
    """Detailed summary for one managed tenant."""
    ths = db.query(TenantHealthScore).filter(
        TenantHealthScore.tenant_id == managed_tenant_id,
    ).order_by(TenantHealthScore.updated_at.desc()).first()

    alerts = db.query(PortfolioAlert).filter(
        PortfolioAlert.tenant_id == managed_tenant_id,
        PortfolioAlert.status == "open",
    ).order_by(PortfolioAlert.created_at.desc()).limit(5).all()

    return {
        "tenant_id": managed_tenant_id,
        "health": _health_score_to_dict(ths) if ths else None,
        "open_alerts": [_alert_to_dict(a) for a in alerts],
    }


def list_portfolio_alerts(db: Session, msp_tenant_id: str,
                          severity: str | None = None, limit: int = 50) -> list[dict]:
    msp = _get_msp(db, msp_tenant_id)
    if not msp:
        return []

    q = db.query(PortfolioAlert).filter(
        PortfolioAlert.msp_account_id == msp.id,
        PortfolioAlert.status == "open",
    )
    if severity:
        q = q.filter(PortfolioAlert.severity == severity)
    alerts = q.order_by(PortfolioAlert.created_at.desc()).limit(limit).all()
    return [_alert_to_dict(a) for a in alerts]


def acknowledge_alert(db: Session, msp_tenant_id: str, alert_id: int,
                      acknowledged_by: str = "admin") -> dict:
    msp = _get_msp(db, msp_tenant_id)
    if not msp:
        return {"error": "MSP account not found"}

    alert = db.query(PortfolioAlert).filter(
        PortfolioAlert.id == alert_id,
        PortfolioAlert.msp_account_id == msp.id,
    ).first()
    if not alert:
        return {"error": "Alert not found"}

    alert.status = "acknowledged"
    alert.acknowledged_by = acknowledged_by
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": alert_id, "status": "acknowledged"}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_msp(db: Session, tenant_id: str) -> MSPAccount | None:
    return db.query(MSPAccount).filter(
        MSPAccount.tenant_id == tenant_id
    ).first()


def _compute_health_scores(db: Session, tenant_id: str) -> dict:
    """Compute individual domain scores (0-100, higher = better) for a tenant."""

    # Exposure score — internet-facing assets, open critical CVEs
    asset_count = db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id
    ).count()

    critical_cves = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.cvss_score >= 9.0,
        VulnerabilityFinding.status == "open",
    ).count() if _table_exists(db, "vulnerability_findings") else 0

    high_cves = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.cvss_score >= 7.0,
        VulnerabilityFinding.cvss_score < 9.0,
        VulnerabilityFinding.status == "open",
    ).count() if _table_exists(db, "vulnerability_findings") else 0

    exposures = db.query(ExposureFinding).filter(
        ExposureFinding.tenant_id == tenant_id,
        ExposureFinding.severity.in_(["critical", "high"]),
    ).count() if _table_exists(db, "exposure_findings") else 0

    exposure_penalty = min(critical_cves * 8 + high_cves * 3 + exposures * 5, 100)
    exposure_score = max(100 - exposure_penalty, 0)

    # Patch score — proxy via CVE counts
    patch_penalty = min(critical_cves * 10 + high_cves * 5, 100)
    patch_score = max(100 - patch_penalty, 0)

    # Compliance score — CE compliance run result
    try:
        latest_run = db.query(ComplianceRun).filter(
            ComplianceRun.tenant_id == tenant_id,
        ).order_by(ComplianceRun.run_date.desc()).first()
        ce_pct = float(latest_run.overall_score or 0) if latest_run else 0.0
        compliance_score = ce_pct
    except Exception:
        ce_pct = 0.0
        compliance_score = 0.0

    # Resilience score — backup findings
    backup_findings = db.query(BackupRiskFinding).filter(
        BackupRiskFinding.tenant_id == tenant_id,
        BackupRiskFinding.status == "open",
    ).count() if _table_exists(db, "backup_risk_findings") else 0

    resilience_penalty = min(backup_findings * 15, 80)
    resilience_score = max(100 - resilience_penalty, 0)

    # Drift score — recent unresolved drift events
    drift_count = db.query(AssetDriftEvent).filter(
        AssetDriftEvent.tenant_id == tenant_id,
        AssetDriftEvent.status == "new",
    ).count() if _table_exists(db, "asset_drift_events") else 0

    drift_penalty = min(drift_count * 5, 80)
    drift_score = max(100 - drift_penalty, 0)

    # Identity score — cloud posture identity findings
    identity_findings = db.query(CloudPostureFinding).filter(
        CloudPostureFinding.tenant_id == tenant_id,
        CloudPostureFinding.status == "open",
        CloudPostureFinding.severity.in_(["critical", "high"]),
    ).count() if _table_exists(db, "cloud_posture_findings") else 0

    identity_penalty = min(identity_findings * 12, 80)
    identity_score = max(100 - identity_penalty, 0)

    return {
        "exposure":  round(exposure_score, 1),
        "patch":     round(patch_score, 1),
        "compliance": round(compliance_score, 1),
        "resilience": round(resilience_score, 1),
        "drift":     round(drift_score, 1),
        "identity":  round(identity_score, 1),
        # Private stats for the health score row
        "_asset_count":       asset_count,
        "_critical_findings": critical_cves,
        "_open_cves":         critical_cves + high_cves,
        "_drift_count":       drift_count,
        "_ce_pct":            ce_pct,
    }


def _weighted_score(scores: dict) -> float:
    total = 0.0
    for domain, weight in _WEIGHTS.items():
        total += scores.get(domain, 0.0) * weight
    return round(total, 1)


def _score_to_band(score: float) -> str:
    for threshold, band in _BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "critical"


def _raise_portfolio_alert(db: Session, msp_account_id: int, tenant_id: str,
                            alert_type: str, severity: str,
                            title: str, summary: str) -> None:
    # Avoid duplicate open alerts of the same type for the same tenant
    existing = db.query(PortfolioAlert).filter(
        PortfolioAlert.msp_account_id == msp_account_id,
        PortfolioAlert.tenant_id == tenant_id,
        PortfolioAlert.alert_type == alert_type,
        PortfolioAlert.status == "open",
    ).first()
    if existing:
        return

    db.add(PortfolioAlert(
        msp_account_id=msp_account_id,
        tenant_id=tenant_id,
        alert_type=alert_type,
        severity=severity,
        title=title,
        summary=summary,
    ))


def _table_exists(db: Session, table_name: str) -> bool:
    """Gracefully check if a table exists before querying it."""
    try:
        db.execute(
            __import__("sqlalchemy").text(
                f"SELECT 1 FROM {table_name} LIMIT 1"
            )
        )
        return True
    except Exception:
        return False


def _health_score_to_dict(s: TenantHealthScore) -> dict:
    return {
        "overall_score": s.overall_score,
        "severity_band": s.severity_band,
        "exposure_score": s.exposure_score,
        "resilience_score": s.resilience_score,
        "compliance_score": s.compliance_score,
        "identity_score": s.identity_score,
        "patch_score": s.patch_score,
        "drift_score": s.drift_score,
        "delta_7d": s.delta_7d,
        "asset_count": s.asset_count,
        "critical_findings_count": s.critical_findings_count,
        "open_cves_count": s.open_cves_count,
        "unresolved_drift_count": s.unresolved_drift_count,
        "ce_compliance_pct": s.ce_compliance_pct,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


def _alert_to_dict(a: PortfolioAlert) -> dict:
    return {
        "id": a.id,
        "tenant_id": a.tenant_id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "title": a.title,
        "summary": a.summary,
        "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
