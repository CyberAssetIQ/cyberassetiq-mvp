"""backup_resilience_service.py

Detects backup coverage across the asset estate by analysing software
inventory for known backup agents. Identifies unprotected critical assets
and generates risk findings.

Reads from: canonical_assets, canonical_software, crown_jewel_assets,
            asset_criticality_profiles (Phase 1).
Writes to:  backup_profiles, backup_risk_findings, recovery_confidence_scores.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.backup_resilience import (
    BackupProfile,
    BackupRiskFinding,
    RecoveryConfidenceScore,
)
from models.telemetry import CanonicalSoftware

logger = logging.getLogger("cyberassetiq.backup_resilience")

# ---------------------------------------------------------------------------
# Known backup tool detection
# ---------------------------------------------------------------------------
_BACKUP_TOOLS: list[tuple[str, str, bool, bool]] = [
    # (keyword, tool_name, immutable, offline)
    ("veeam",         "Veeam Backup & Replication",     True,  True),
    ("acronis",       "Acronis Cyber Backup",            True,  False),
    ("backupexec",    "Veritas Backup Exec",             False, True),
    ("backup exec",   "Veritas Backup Exec",             False, True),
    ("dpm",           "Microsoft DPM",                   False, False),
    ("carbonite",     "Carbonite",                       False, False),
    ("backblaze",     "Backblaze",                       False, False),
    ("commvault",     "Commvault Complete",              True,  True),
    ("shadow protect","StorageCraft ShadowProtect",      False, False),
    ("macrium",       "Macrium Reflect",                 False, False),
    ("windows server backup", "Windows Server Backup",   False, False),
    ("azure backup",  "Azure Backup",                    True,  False),
    ("aws backup",    "AWS Backup",                      True,  False),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_backup_summary(db: Session, tenant_id: str) -> dict:
    total = db.query(BackupProfile).filter(BackupProfile.tenant_id == tenant_id).count()
    covered = db.query(BackupProfile).filter(
        BackupProfile.tenant_id == tenant_id,
        BackupProfile.has_backup == True,
    ).count()
    total_assets = db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id
    ).count()
    open_findings = db.query(BackupRiskFinding).filter(
        BackupRiskFinding.tenant_id == tenant_id,
        BackupRiskFinding.status == "open",
    ).count()
    recovery = _latest_recovery_score(db, tenant_id)

    return {
        "total_assets": total_assets,
        "profiled": total,
        "with_backup": covered,
        "without_backup": total_assets - covered,
        "coverage_pct": round((covered / total_assets * 100), 1) if total_assets else 0,
        "open_findings": open_findings,
        "recovery_confidence": recovery.score if recovery else 0,
        "recovery_band": recovery.confidence_band if recovery else "unknown",
    }


def get_backup_assets(
    db: Session,
    tenant_id: str,
    unprotected_only: bool = False,
) -> list[dict]:
    q = db.query(BackupProfile).filter(BackupProfile.tenant_id == tenant_id)
    if unprotected_only:
        q = q.filter(BackupProfile.has_backup == False)
    profiles = q.order_by(BackupProfile.has_backup.asc()).all()
    return [_profile_to_dict(p, db) for p in profiles]


def get_backup_findings(db: Session, tenant_id: str) -> list[dict]:
    findings = (
        db.query(BackupRiskFinding)
        .filter(
            BackupRiskFinding.tenant_id == tenant_id,
            BackupRiskFinding.status == "open",
        )
        .order_by(BackupRiskFinding.severity.asc())
        .all()
    )
    return [_finding_to_dict(f, db) for f in findings]


def recalculate(db: Session, tenant_id: str) -> dict:
    """Scan all assets, update backup profiles, regenerate findings."""
    assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()

    profiled = 0
    covered = 0
    for asset in assets:
        try:
            result = _profile_asset(db, tenant_id, asset)
            profiled += 1
            if result.get("has_backup"):
                covered += 1
        except Exception as exc:
            logger.warning("Backup profile failed for asset %d: %s", asset.id, exc)

    # Generate findings
    _generate_findings(db, tenant_id)

    # Compute tenant recovery confidence
    _compute_recovery_confidence(db, tenant_id, covered, len(assets))

    return {
        "assets_profiled": profiled,
        "assets_with_backup": covered,
        "coverage_pct": round((covered / len(assets) * 100), 1) if assets else 0,
    }


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _profile_asset(db: Session, tenant_id: str, asset: CanonicalAsset) -> dict:
    """Detect backup tools for a single asset, upsert profile."""
    software = db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id,
        CanonicalSoftware.asset_id == asset.id,
    ).all()
    sw_names = " ".join(s.name.lower() for s in software)

    detected_tool = None
    immutable = False
    offline = False
    backup_type = "agent"

    for keyword, tool_name, imm, off in _BACKUP_TOOLS:
        if keyword in sw_names:
            detected_tool = tool_name
            immutable = imm
            offline = off
            break

    has_backup = detected_tool is not None

    existing = db.query(BackupProfile).filter(
        BackupProfile.tenant_id == tenant_id,
        BackupProfile.asset_id == asset.id,
    ).first()

    if existing:
        existing.backup_tool = detected_tool
        existing.has_backup = has_backup
        existing.immutable_backup = immutable
        existing.offline_backup = offline
        existing.backup_type = backup_type if has_backup else None
    else:
        db.add(BackupProfile(
            tenant_id=tenant_id,
            asset_id=asset.id,
            backup_tool=detected_tool,
            has_backup=has_backup,
            immutable_backup=immutable,
            offline_backup=offline,
            backup_type=backup_type if has_backup else None,
        ))

    db.commit()
    return {"has_backup": has_backup, "tool": detected_tool}


def _generate_findings(db: Session, tenant_id: str) -> None:
    """Close stale open findings and generate fresh ones."""
    db.query(BackupRiskFinding).filter(
        BackupRiskFinding.tenant_id == tenant_id,
        BackupRiskFinding.status == "open",
    ).update({"status": "superseded"}, synchronize_session=False)

    profiles = db.query(BackupProfile).filter(BackupProfile.tenant_id == tenant_id).all()

    # Crown jewel IDs for elevated severity
    crown_ids: set[int] = set()
    try:
        from models.criticality import CrownJewelAsset
        crown_ids = {
            cj.asset_id for cj in db.query(CrownJewelAsset).filter(
                CrownJewelAsset.tenant_id == tenant_id
            ).all()
        }
    except Exception:
        pass

    # Criticality profiles for priority ordering
    criticality_map: dict[int, int] = {}
    try:
        from models.criticality import AssetCriticalityProfile
        for cp in db.query(AssetCriticalityProfile).filter(
            AssetCriticalityProfile.tenant_id == tenant_id
        ).all():
            criticality_map[cp.asset_id] = cp.criticality_score
    except Exception:
        pass

    for profile in profiles:
        asset_id = profile.asset_id
        crit_score = criticality_map.get(asset_id, 30)
        is_crown = asset_id in crown_ids

        if not profile.has_backup:
            severity = "critical" if is_crown else ("high" if crit_score >= 70 else "medium")
            db.add(BackupRiskFinding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                severity=severity,
                finding_type="no_backup" if not is_crown else "crown_jewel_unprotected",
                description=f"No backup agent or tool detected on this asset.",
                recommendation="Deploy a backup agent (Veeam, Acronis, or equivalent) and verify backup schedule.",
                status="open",
            ))

        elif profile.has_backup and not profile.immutable_backup:
            db.add(BackupRiskFinding(
                tenant_id=tenant_id,
                asset_id=asset_id,
                severity="medium",
                finding_type="no_immutable",
                description=f"{profile.backup_tool} detected but immutable backup storage is not confirmed.",
                recommendation="Configure immutable or air-gapped backup targets to protect against ransomware deletion.",
                status="open",
            ))

    db.commit()


def _compute_recovery_confidence(
    db: Session, tenant_id: str, covered: int, total: int
) -> None:
    if total == 0:
        score = 0
        band = "critical_gap"
    else:
        coverage_ratio = covered / total

        # Penalise for missing immutable backups
        immutable_count = db.query(BackupProfile).filter(
            BackupProfile.tenant_id == tenant_id,
            BackupProfile.immutable_backup == True,
        ).count()
        immutable_ratio = immutable_count / max(covered, 1) if covered else 0

        score = int((coverage_ratio * 60) + (immutable_ratio * 40))

        if score >= 80:
            band = "high"
        elif score >= 55:
            band = "medium"
        elif score >= 30:
            band = "low"
        else:
            band = "critical_gap"

    existing = db.query(RecoveryConfidenceScore).filter(
        RecoveryConfidenceScore.tenant_id == tenant_id,
        RecoveryConfidenceScore.asset_id.is_(None),
    ).order_by(RecoveryConfidenceScore.computed_at.desc()).first()

    reasons = [
        f"Backup coverage: {covered}/{total} assets",
        f"Recovery confidence band: {band}",
    ]

    db.add(RecoveryConfidenceScore(
        tenant_id=tenant_id,
        asset_id=None,
        score=score,
        confidence_band=band,
        reasons_json=reasons,
    ))
    db.commit()


def _latest_recovery_score(db: Session, tenant_id: str) -> RecoveryConfidenceScore | None:
    return (
        db.query(RecoveryConfidenceScore)
        .filter(
            RecoveryConfidenceScore.tenant_id == tenant_id,
            RecoveryConfidenceScore.asset_id.is_(None),
        )
        .order_by(RecoveryConfidenceScore.computed_at.desc())
        .first()
    )


def _profile_to_dict(p: BackupProfile, db: Session) -> dict:
    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == p.asset_id).first()
    return {
        "asset_id": p.asset_id,
        "hostname": asset.hostname if asset else None,
        "has_backup": p.has_backup,
        "backup_tool": p.backup_tool,
        "backup_type": p.backup_type,
        "immutable_backup": p.immutable_backup,
        "offline_backup": p.offline_backup,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _finding_to_dict(f: BackupRiskFinding, db: Session) -> dict:
    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == f.asset_id).first()
    return {
        "id": f.id,
        "asset_id": f.asset_id,
        "hostname": asset.hostname if asset else None,
        "severity": f.severity,
        "finding_type": f.finding_type,
        "description": f.description,
        "recommendation": f.recommendation,
        "status": f.status,
    }
