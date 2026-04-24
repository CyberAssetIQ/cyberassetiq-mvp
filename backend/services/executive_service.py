from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

logger = logging.getLogger("cyberassetiq.executive")


# ---------------------------------------------------------------------------
# Score calculation helpers
# ---------------------------------------------------------------------------

def _ce_score(db: Session, tenant_id: str) -> float | None:
    try:
        from models.compliance_run import ComplianceRun
        r = db.query(ComplianceRun).filter(
            ComplianceRun.tenant_id == tenant_id
        ).order_by(desc(ComplianceRun.id)).first()
        return round(r.tenant_overall_score or 0, 1) if r else None
    except Exception:
        return None


def _patch_score(db: Session, tenant_id: str) -> int | None:
    try:
        from models.patch import PatchReport
        r = db.query(PatchReport).filter(
            PatchReport.tenant_id == tenant_id
        ).order_by(desc(PatchReport.id)).first()
        return r.patch_score if r else None
    except Exception:
        return None


def _identity_score(db: Session, tenant_id: str) -> int | None:
    try:
        from services.identity_service import analyse_identity_risk
        result = analyse_identity_risk(db, tenant_id)
        return result.get("avg_risk_score")
    except Exception:
        return None


def _insurance_score(db: Session, tenant_id: str) -> int | None:
    try:
        from services.insurance_service import calculate_readiness
        result = calculate_readiness(db, tenant_id)
        return result.get("readiness_score")
    except Exception:
        return None


def _cve_counts(db: Session, tenant_id: str) -> dict:
    try:
        from models.telemetry import VulnerabilityFinding
        critical = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "CRITICAL",
            VulnerabilityFinding.status == "open",
        ).count()
        high = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "HIGH",
            VulnerabilityFinding.status == "open",
        ).count()
        return {"critical": critical, "high": high}
    except Exception:
        return {"critical": 0, "high": 0}


def _asset_counts(db: Session, tenant_id: str) -> dict:
    try:
        from models.asset import CanonicalAsset
        from models.network import NetworkDiscoveredAsset
        managed = db.query(CanonicalAsset).filter(
            CanonicalAsset.tenant_id == tenant_id
        ).count()
        unmanaged = db.query(NetworkDiscoveredAsset).filter(
            NetworkDiscoveredAsset.tenant_id == tenant_id,
            NetworkDiscoveredAsset.is_active.is_(True),
        ).count()
        return {"managed": managed, "unmanaged": unmanaged, "total": managed + unmanaged}
    except Exception:
        return {"managed": 0, "unmanaged": 0, "total": 0}


def _darkweb_count(db: Session, tenant_id: str) -> int:
    try:
        from models.darkweb import DarkWebFinding
        return db.query(DarkWebFinding).filter(
            DarkWebFinding.tenant_id == tenant_id,
            DarkWebFinding.status != "resolved",
        ).count()
    except Exception:
        return 0


def _alert_count(db: Session, tenant_id: str) -> int:
    try:
        from models.ai_alert import AIAlert
        day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        return db.query(AIAlert).filter(
            AIAlert.tenant_id == tenant_id,
            AIAlert.severity.in_(["HIGH", "CRITICAL"]),
            AIAlert.created_at >= day_ago,
        ).count()
    except Exception:
        return 0


def _compute_overall_score(
    ce: float | None,
    patch: int | None,
    identity: int | None,
    insurance: int | None,
    critical_cves: int,
    darkweb: int,
) -> int:
    """Weighted composite score 0-100."""
    scores = []
    weights = []

    if ce is not None:
        scores.append(ce)
        weights.append(0.25)
    if patch is not None:
        scores.append(patch)
        weights.append(0.20)
    if identity is not None:
        scores.append(identity)
        weights.append(0.20)
    if insurance is not None:
        scores.append(insurance)
        weights.append(0.15)

    if not scores:
        base = 50
    else:
        total_weight = sum(weights)
        base = sum(s * w for s, w in zip(scores, weights)) / total_weight

    # Deduct for critical CVEs and dark web
    deduction = min(critical_cves * 2, 15) + min(darkweb * 3, 10)
    return max(0, min(100, round(base - deduction)))


# ---------------------------------------------------------------------------
# Snapshot creation
# ---------------------------------------------------------------------------

def create_snapshot(db: Session, tenant_id: str) -> dict:
    from models.risk_snapshot import RiskSnapshot

    ce       = _ce_score(db, tenant_id)
    patch    = _patch_score(db, tenant_id)
    identity = _identity_score(db, tenant_id)
    insurance = _insurance_score(db, tenant_id)
    cves     = _cve_counts(db, tenant_id)
    assets   = _asset_counts(db, tenant_id)
    darkweb  = _darkweb_count(db, tenant_id)
    alerts   = _alert_count(db, tenant_id)
    overall  = _compute_overall_score(ce, patch, identity, insurance, cves["critical"], darkweb)

    snap = RiskSnapshot(
        tenant_id       = tenant_id,
        overall_score   = overall,
        ce_score        = ce,
        patch_score     = patch,
        identity_score  = identity,
        insurance_score = insurance,
        total_assets    = assets["total"],
        managed_assets  = assets["managed"],
        critical_cves   = cves["critical"],
        high_cves       = cves["high"],
        open_darkweb    = darkweb,
        open_alerts     = alerts,
        breakdown_json  = {
            "assets": assets,
            "cves": cves,
            "scores": {
                "ce": ce, "patch": patch,
                "identity": identity, "insurance": insurance,
            }
        }
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    logger.info("Risk snapshot created: tenant=%s overall=%d", tenant_id, overall)
    return {"id": snap.id, "overall_score": overall, "captured_at": snap.captured_at.isoformat()}


# ---------------------------------------------------------------------------
# Executive summary (live)
# ---------------------------------------------------------------------------

def get_executive_summary(db: Session, tenant_id: str) -> dict:
    ce       = _ce_score(db, tenant_id)
    patch    = _patch_score(db, tenant_id)
    identity = _identity_score(db, tenant_id)
    insurance = _insurance_score(db, tenant_id)
    cves     = _cve_counts(db, tenant_id)
    assets   = _asset_counts(db, tenant_id)
    darkweb  = _darkweb_count(db, tenant_id)
    alerts   = _alert_count(db, tenant_id)
    overall  = _compute_overall_score(ce, patch, identity, insurance, cves["critical"], darkweb)

    # Risk band
    if overall >= 80:
        band, band_color = "Low Risk", "#1F7A4D"
    elif overall >= 60:
        band, band_color = "Medium Risk", "#C7600A"
    elif overall >= 40:
        band, band_color = "High Risk", "#B32D1F"
    else:
        band, band_color = "Critical Risk", "#7B0000"

    # Top recommendations
    recommendations = []
    if cves["critical"] > 0:
        recommendations.append(f"Patch {cves['critical']} critical CVE(s) — highest insurance and breach risk.")
    if ce is not None and ce < 70:
        recommendations.append(f"CE compliance at {ce:.0f}% — below 70% certification threshold.")
    if patch is not None and patch < 70:
        recommendations.append("Patch score below acceptable threshold — address pending Windows Updates.")
    if darkweb > 0:
        recommendations.append(f"{darkweb} active dark web exposure(s) — rotate affected credentials immediately.")
    if identity is not None and identity < 70:
        recommendations.append("Identity risk score low — review password policy and admin accounts.")
    if not recommendations:
        recommendations.append("Security posture is good — maintain current controls and re-assess quarterly.")

    # Timeline (last 30 snapshots)
    from models.risk_snapshot import RiskSnapshot
    snapshots = db.query(RiskSnapshot).filter(
        RiskSnapshot.tenant_id == tenant_id,
    ).order_by(desc(RiskSnapshot.id)).limit(30).all()

    timeline = [
        {
            "captured_at":   s.captured_at.isoformat() if s.captured_at else None,
            "overall_score": s.overall_score,
            "ce_score":      s.ce_score,
            "patch_score":   s.patch_score,
            "critical_cves": s.critical_cves,
        }
        for s in reversed(snapshots)
    ]

    return {
        "overall_score":     overall,
        "risk_band":         band,
        "band_color":        band_color,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "scores": {
            "ce_compliance":   ce,
            "patch_mgmt":      patch,
            "identity_risk":   identity,
            "insurance":       insurance,
        },
        "counts": {
            "total_assets":    assets["total"],
            "managed_assets":  assets["managed"],
            "unmanaged_assets": assets["unmanaged"],
            "critical_cves":   cves["critical"],
            "high_cves":       cves["high"],
            "darkweb_active":  darkweb,
            "ai_alerts_24h":   alerts,
        },
        "recommendations": recommendations,
        "timeline":          timeline,
    }


# ---------------------------------------------------------------------------
# Timeline history
# ---------------------------------------------------------------------------

def get_timeline(db: Session, tenant_id: str, days: int = 30) -> list[dict]:
    from models.risk_snapshot import RiskSnapshot

    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.query(RiskSnapshot).filter(
        RiskSnapshot.tenant_id == tenant_id,
        RiskSnapshot.captured_at >= since,
    ).order_by(RiskSnapshot.captured_at).all()

    return [
        {
            "captured_at":   r.captured_at.isoformat(),
            "overall_score": r.overall_score,
            "ce_score":      r.ce_score,
            "patch_score":   r.patch_score,
            "identity_score": r.identity_score,
            "critical_cves": r.critical_cves,
        }
        for r in rows
    ]
