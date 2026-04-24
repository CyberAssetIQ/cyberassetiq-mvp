"""risk_engine_service.py

Risk Engine 2.0 — composites signals from all existing modules into a
weighted, explainable per-tenant and per-asset risk score.

Reads from existing tables (vulns, exposure, darkweb, compliance, etc.).
Writes only to new risk_engine tables.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.risk_engine import (
    RiskFactorScore,
    RiskRecommendation,
    RiskScoreExplanation,
    RiskSnapshotV2,
)

logger = logging.getLogger("cyberassetiq.risk_engine")

# ---------------------------------------------------------------------------
# Factor weights — must sum to approximately 100
# ---------------------------------------------------------------------------
FACTOR_WEIGHTS: dict[str, float] = {
    "critical_cves":       20.0,
    "exposure":            18.0,
    "drift":               12.0,
    "identity_risk":       10.0,
    "patch_posture":       10.0,
    "dark_web":            10.0,
    "criticality":          8.0,
    "backup_resilience":    7.0,
    "compliance":           5.0,
}

SEVERITY_BANDS = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
    (0,  "minimal"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_risk_summary(db: Session, tenant_id: str) -> dict:
    """Latest tenant-level risk snapshot + top recommendations."""
    snapshot = _latest_tenant_snapshot(db, tenant_id)
    top_recs = (
        db.query(RiskRecommendation)
        .filter(
            RiskRecommendation.tenant_id == tenant_id,
            RiskRecommendation.status == "open",
            RiskRecommendation.asset_id.is_(None),
        )
        .order_by(RiskRecommendation.priority_rank.asc())
        .limit(5)
        .all()
    )
    return {
        "score": snapshot.total_score if snapshot else 0,
        "severity_band": snapshot.severity_band if snapshot else "unknown",
        "computed_at": snapshot.computed_at.isoformat() if snapshot else None,
        "top_recommendations": [_rec_to_dict(r) for r in top_recs],
    }


def get_risk_factors(db: Session, tenant_id: str) -> list[dict]:
    """Latest factor breakdown for the tenant."""
    latest = (
        db.query(RiskFactorScore)
        .filter(
            RiskFactorScore.tenant_id == tenant_id,
            RiskFactorScore.asset_id.is_(None),
        )
        .order_by(RiskFactorScore.computed_at.desc())
        .limit(len(FACTOR_WEIGHTS))
        .all()
    )
    return [_factor_to_dict(f) for f in latest]


def get_risk_recommendations(db: Session, tenant_id: str, limit: int = 10) -> list[dict]:
    recs = (
        db.query(RiskRecommendation)
        .filter(
            RiskRecommendation.tenant_id == tenant_id,
            RiskRecommendation.status == "open",
        )
        .order_by(RiskRecommendation.priority_rank.asc())
        .limit(limit)
        .all()
    )
    return [_rec_to_dict(r) for r in recs]


def get_risk_timeline(db: Session, tenant_id: str, days: int = 30) -> list[dict]:
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    snapshots = (
        db.query(RiskSnapshotV2)
        .filter(
            RiskSnapshotV2.tenant_id == tenant_id,
            RiskSnapshotV2.entity_type == "tenant",
            RiskSnapshotV2.computed_at >= cutoff,
        )
        .order_by(RiskSnapshotV2.computed_at.asc())
        .all()
    )
    return [
        {
            "computed_at": s.computed_at.isoformat(),
            "score": s.total_score,
            "severity_band": s.severity_band,
        }
        for s in snapshots
    ]


def recalculate(db: Session, tenant_id: str) -> dict:
    """Run a full risk recalculation for the tenant."""
    factors = _compute_factors(db, tenant_id)
    total_score = _composite_score(factors)
    severity = _severity_band(total_score)

    now = datetime.now(timezone.utc)

    # Persist factor rows
    for factor_name, data in factors.items():
        row = RiskFactorScore(
            tenant_id=tenant_id,
            asset_id=None,
            factor_name=factor_name,
            factor_weight=data["weight"],
            raw_score=data["raw"],
            normalized_score=data["weighted"],
            explanation=data.get("explanation"),
        )
        db.add(row)

    # Persist snapshot
    snapshot = RiskSnapshotV2(
        tenant_id=tenant_id,
        entity_type="tenant",
        entity_id=None,
        total_score=total_score,
        severity_band=severity,
        contributing_factors_json={k: v["weighted"] for k, v in factors.items()},
    )
    db.add(snapshot)
    db.flush()

    # Generate and persist recommendations
    recs = _generate_recommendations(db, tenant_id, factors)
    _persist_recommendations(db, tenant_id, recs)

    db.commit()
    return {
        "score": total_score,
        "severity_band": severity,
        "factors": {k: round(v["weighted"], 1) for k, v in factors.items()},
        "recommendations_generated": len(recs),
    }


# ---------------------------------------------------------------------------
# Internal: factor computation
# ---------------------------------------------------------------------------

def _compute_factors(db: Session, tenant_id: str) -> dict[str, dict]:
    factors: dict[str, dict] = {}

    # ── Critical CVEs ──────────────────────────────────────────────────────
    try:
        from models.telemetry import VulnerabilityFinding
        crit = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "CRITICAL",
        ).count()
        high = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.severity == "HIGH",
        ).count()
        raw = min(100, crit * 8 + high * 3)
        factors["critical_cves"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["critical_cves"],
            "weighted": raw * FACTOR_WEIGHTS["critical_cves"] / 100,
            "explanation": f"{crit} critical, {high} high CVEs",
        }
    except Exception as e:
        factors["critical_cves"] = _zero_factor("critical_cves", str(e))

    # ── Internet exposure ──────────────────────────────────────────────────
    try:
        from models.network_extensions import ExposureFinding
        open_exp = db.query(ExposureFinding).filter(
            ExposureFinding.tenant_id == tenant_id,
            ExposureFinding.status == "open",
        ).count()
        crit_exp = db.query(ExposureFinding).filter(
            ExposureFinding.tenant_id == tenant_id,
            ExposureFinding.status == "open",
            ExposureFinding.severity.in_(["critical", "high"]),
        ).count()
        raw = min(100, crit_exp * 10 + (open_exp - crit_exp) * 3)
        factors["exposure"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["exposure"],
            "weighted": raw * FACTOR_WEIGHTS["exposure"] / 100,
            "explanation": f"{crit_exp} critical/high exposure findings, {open_exp} total",
        }
    except Exception as e:
        factors["exposure"] = _zero_factor("exposure", str(e))

    # ── Drift ──────────────────────────────────────────────────────────────
    try:
        from models.drift import AssetDriftEvent
        open_high = db.query(AssetDriftEvent).filter(
            AssetDriftEvent.tenant_id == tenant_id,
            AssetDriftEvent.status == "open",
            AssetDriftEvent.severity.in_(["critical", "high"]),
        ).count()
        open_med = db.query(AssetDriftEvent).filter(
            AssetDriftEvent.tenant_id == tenant_id,
            AssetDriftEvent.status == "open",
            AssetDriftEvent.severity == "medium",
        ).count()
        raw = min(100, open_high * 10 + open_med * 4)
        factors["drift"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["drift"],
            "weighted": raw * FACTOR_WEIGHTS["drift"] / 100,
            "explanation": f"{open_high} high-severity drift events, {open_med} medium",
        }
    except Exception as e:
        factors["drift"] = _zero_factor("drift", str(e))

    # ── Identity risk ──────────────────────────────────────────────────────
    try:
        from models.darkweb import DarkWebFinding
        identity_findings = db.query(DarkWebFinding).filter(
            DarkWebFinding.tenant_id == tenant_id,
            DarkWebFinding.status == "open",
            DarkWebFinding.finding_type.in_(["credential", "password", "email_password"]),
        ).count()
        raw = min(100, identity_findings * 12)
        factors["identity_risk"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["identity_risk"],
            "weighted": raw * FACTOR_WEIGHTS["identity_risk"] / 100,
            "explanation": f"{identity_findings} exposed credential(s) on dark web",
        }
    except Exception as e:
        factors["identity_risk"] = _zero_factor("identity_risk", str(e))

    # ── Patch posture ──────────────────────────────────────────────────────
    try:
        from models.patch import PatchReport
        from sqlalchemy import func as sqlfunc
        latest_patch = db.query(PatchReport).filter(
            PatchReport.tenant_id == tenant_id,
        ).order_by(PatchReport.created_at.desc()).first()
        if latest_patch:
            data = latest_patch.report_json or {}
            missing_critical = data.get("missing_critical", 0)
            raw = min(100, missing_critical * 6)
        else:
            raw = 30  # No data = moderate concern
        factors["patch_posture"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["patch_posture"],
            "weighted": raw * FACTOR_WEIGHTS["patch_posture"] / 100,
            "explanation": f"Based on latest patch report data",
        }
    except Exception as e:
        factors["patch_posture"] = _zero_factor("patch_posture", str(e))

    # ── Dark web ───────────────────────────────────────────────────────────
    try:
        from models.darkweb import DarkWebFinding
        dw_open = db.query(DarkWebFinding).filter(
            DarkWebFinding.tenant_id == tenant_id,
            DarkWebFinding.status == "open",
        ).count()
        raw = min(100, dw_open * 8)
        factors["dark_web"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["dark_web"],
            "weighted": raw * FACTOR_WEIGHTS["dark_web"] / 100,
            "explanation": f"{dw_open} open dark web finding(s)",
        }
    except Exception as e:
        factors["dark_web"] = _zero_factor("dark_web", str(e))

    # ── Asset criticality ──────────────────────────────────────────────────
    try:
        from models.criticality import CrownJewelAsset, AssetCriticalityProfile
        crown_jewels = db.query(CrownJewelAsset).filter(
            CrownJewelAsset.tenant_id == tenant_id
        ).count()
        # Check for high-criticality assets with open vulnerabilities
        high_criticality_assets = db.query(AssetCriticalityProfile).filter(
            AssetCriticalityProfile.tenant_id == tenant_id,
            AssetCriticalityProfile.criticality_score >= 70,
        ).count()
        raw = min(100, crown_jewels * 15 + (high_criticality_assets - crown_jewels) * 3)
        factors["criticality"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["criticality"],
            "weighted": raw * FACTOR_WEIGHTS["criticality"] / 100,
            "explanation": f"{crown_jewels} crown jewel(s), {high_criticality_assets} high-criticality assets",
        }
    except Exception as e:
        factors["criticality"] = _zero_factor("criticality", str(e))

    # ── Backup resilience ──────────────────────────────────────────────────
    try:
        from models.asset import CanonicalAsset
        from models.telemetry import CanonicalSoftware
        total_assets = db.query(CanonicalAsset).filter(
            CanonicalAsset.tenant_id == tenant_id
        ).count()
        backup_keywords = ["veeam", "acronis", "backupexec", "dpm", "carbonite", "commvault"]
        # Count assets with any known backup software
        assets_with_backup = 0
        if total_assets:
            all_assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
            for asset in all_assets:
                software = db.query(CanonicalSoftware).filter(
                    CanonicalSoftware.tenant_id == tenant_id,
                    CanonicalSoftware.asset_id == asset.id,
                ).all()
                sw_names = {s.name.lower() for s in software}
                if any(kw in name for kw in backup_keywords for name in sw_names):
                    assets_with_backup += 1
            coverage_gap = max(0, 1.0 - (assets_with_backup / total_assets)) if total_assets else 1.0
            raw = int(coverage_gap * 100)
        else:
            raw = 0
        factors["backup_resilience"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["backup_resilience"],
            "weighted": raw * FACTOR_WEIGHTS["backup_resilience"] / 100,
            "explanation": f"{assets_with_backup}/{total_assets} assets have backup software detected",
        }
    except Exception as e:
        factors["backup_resilience"] = _zero_factor("backup_resilience", str(e))

    # ── Compliance ─────────────────────────────────────────────────────────
    try:
        from models.compliance_run import ComplianceRun
        latest_run = db.query(ComplianceRun).filter(
            ComplianceRun.tenant_id == tenant_id,
        ).order_by(ComplianceRun.created_at.desc()).first()
        if latest_run:
            run_data = latest_run.summary_json or {}
            fail_rate = run_data.get("fail_rate", 0.5)
            raw = int(fail_rate * 100)
        else:
            raw = 40
        factors["compliance"] = {
            "raw": raw,
            "weight": FACTOR_WEIGHTS["compliance"],
            "weighted": raw * FACTOR_WEIGHTS["compliance"] / 100,
            "explanation": "Based on latest CE compliance run",
        }
    except Exception as e:
        factors["compliance"] = _zero_factor("compliance", str(e))

    return factors


def _composite_score(factors: dict[str, dict]) -> int:
    total = sum(v["weighted"] for v in factors.values())
    return min(100, int(total))


def _severity_band(score: int) -> str:
    for threshold, band in SEVERITY_BANDS:
        if score >= threshold:
            return band
    return "minimal"


def _generate_recommendations(
    db: Session, tenant_id: str, factors: dict[str, dict]
) -> list[dict]:
    """Generate prioritised recommendations based on factor scores."""
    recs = []
    rank = 1

    sorted_factors = sorted(factors.items(), key=lambda x: x[1]["weighted"], reverse=True)
    for factor_name, data in sorted_factors[:5]:
        if data["raw"] < 10:
            continue
        title, rec_type = _rec_for_factor(factor_name, data)
        if title:
            recs.append({
                "recommendation_type": rec_type,
                "title": title,
                "expected_score_gain": int(data["weighted"] * 0.7),
                "priority_rank": rank,
            })
            rank += 1

    return recs


def _rec_for_factor(factor_name: str, data: dict) -> tuple[str, str]:
    mapping = {
        "critical_cves": ("Patch or mitigate critical and high CVEs on all assets", "patch_cvEs"),
        "exposure": ("Reduce internet-exposed attack surface — review open ports and services", "reduce_exposure"),
        "drift": ("Review and resolve high-severity asset configuration drift events", "resolve_drift"),
        "identity_risk": ("Rotate credentials exposed on dark web and enforce MFA", "identity_hardening"),
        "patch_posture": ("Apply missing critical patches across the asset estate", "patch_posture"),
        "dark_web": ("Investigate and respond to dark web exposure findings", "dark_web_response"),
        "backup_resilience": ("Deploy backup agents to assets that currently lack coverage", "backup_coverage"),
        "compliance": ("Remediate failing CE compliance controls", "compliance_remediation"),
        "criticality": ("Prioritise vulnerability remediation on crown jewel and critical assets", "crown_jewel_hardening"),
    }
    entry = mapping.get(factor_name)
    if entry:
        return entry
    return "", ""


def _persist_recommendations(db: Session, tenant_id: str, recs: list[dict]) -> None:
    """Close old open tenant-level recs and insert fresh ones."""
    (
        db.query(RiskRecommendation)
        .filter(
            RiskRecommendation.tenant_id == tenant_id,
            RiskRecommendation.asset_id.is_(None),
            RiskRecommendation.status == "open",
        )
        .update({"status": "superseded"}, synchronize_session=False)
    )
    for rec in recs:
        db.add(RiskRecommendation(
            tenant_id=tenant_id,
            asset_id=None,
            recommendation_type=rec["recommendation_type"],
            title=rec["title"],
            expected_score_gain=rec["expected_score_gain"],
            priority_rank=rec["priority_rank"],
            status="open",
        ))


def _latest_tenant_snapshot(db: Session, tenant_id: str) -> RiskSnapshotV2 | None:
    return (
        db.query(RiskSnapshotV2)
        .filter(
            RiskSnapshotV2.tenant_id == tenant_id,
            RiskSnapshotV2.entity_type == "tenant",
        )
        .order_by(RiskSnapshotV2.computed_at.desc())
        .first()
    )


def _zero_factor(name: str, reason: str) -> dict:
    return {
        "raw": 0,
        "weight": FACTOR_WEIGHTS.get(name, 1.0),
        "weighted": 0.0,
        "explanation": f"Data unavailable: {reason}",
    }


def _factor_to_dict(f: RiskFactorScore) -> dict:
    return {
        "factor_name": f.factor_name,
        "factor_weight": f.factor_weight,
        "raw_score": f.raw_score,
        "normalized_score": f.normalized_score,
        "explanation": f.explanation,
        "computed_at": f.computed_at.isoformat() if f.computed_at else None,
    }


def _rec_to_dict(r: RiskRecommendation) -> dict:
    return {
        "id": r.id,
        "recommendation_type": r.recommendation_type,
        "title": r.title,
        "expected_score_gain": r.expected_score_gain,
        "priority_rank": r.priority_rank,
        "status": r.status,
    }
