"""asset_criticality_service.py

Infers asset criticality from hostname patterns, installed software,
listening services, and business service mappings.

Reads only from existing tables. Writes only to new criticality tables.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.criticality import (
    AssetCriticalityProfile,
    AssetServiceMap,
    BusinessService,
    CrownJewelAsset,
)
from models.telemetry import CanonicalSoftware

logger = logging.getLogger("cyberassetiq.criticality")

# ---------------------------------------------------------------------------
# Role inference rules — hostname patterns
# ---------------------------------------------------------------------------
_ROLE_PATTERNS: list[tuple[str, str]] = [
    (r"dc\d*|domain.?controller|adds?server", "domain_controller"),
    (r"sql|mssql|mysql|postgres|db\d*|database", "database_server"),
    (r"web\d*|www|iis|nginx|apache|http", "web_server"),
    (r"mail|exchange|smtp|mx\d*", "mail_server"),
    (r"file.?server|nas|share\d*|fs\d*", "file_server"),
    (r"backup|bkp|veeam|acronis", "backup_server"),
    (r"vpn|firewall|gateway|gw\d*|router", "network_device"),
    (r"esx|esxi|hyper.?v|vmhost|kvm", "hypervisor"),
    (r"citrix|rdp.?gw|jump|bastion", "jump_host"),
    (r"print|prt\d*", "print_server"),
    (r"monitor|siem|splunk|elk|graylog", "monitoring_server"),
    (r"ad\d*|ldap|identity", "identity_server"),
]

# Software keywords that elevate criticality
_HIGH_CRITICALITY_SOFTWARE = {
    "sql server", "oracle", "mysql", "postgresql", "active directory",
    "exchange", "sharepoint", "veeam", "acronis", "backup exec",
    "vmware", "hyper-v", "citrix", "rdp",
}
_BACKUP_SOFTWARE = {
    "veeam", "acronis", "backupexec", "dpm", "carbonite", "backblaze", "commvault",
}

# Ports that indicate critical roles
_CRITICAL_PORTS = {389, 636, 3268, 3269}   # LDAP / LDAPS / Global Catalog
_DB_PORTS = {1433, 1521, 3306, 5432, 27017}
_WEB_PORTS = {80, 443, 8080, 8443}
_MGMT_PORTS = {22, 3389, 5985, 5986}       # SSH, RDP, WinRM


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_criticality_summary(db: Session, tenant_id: str) -> dict:
    from sqlalchemy import func as sqlfunc

    total = db.query(AssetCriticalityProfile).filter(
        AssetCriticalityProfile.tenant_id == tenant_id
    ).count()

    critical_count = db.query(AssetCriticalityProfile).filter(
        AssetCriticalityProfile.tenant_id == tenant_id,
        AssetCriticalityProfile.criticality_score >= 75,
    ).count()

    crown_jewels = db.query(CrownJewelAsset).filter(
        CrownJewelAsset.tenant_id == tenant_id
    ).count()

    return {
        "total_profiled": total,
        "critical_assets": critical_count,
        "crown_jewels": crown_jewels,
    }


def get_criticality_assets(db: Session, tenant_id: str, min_score: int = 0) -> list[dict]:
    profiles = (
        db.query(AssetCriticalityProfile)
        .filter(
            AssetCriticalityProfile.tenant_id == tenant_id,
            AssetCriticalityProfile.criticality_score >= min_score,
        )
        .order_by(AssetCriticalityProfile.criticality_score.desc())
        .all()
    )
    return [_profile_to_dict(p, db) for p in profiles]


def recalculate_all(db: Session, tenant_id: str) -> dict:
    """Recalculate criticality for all assets in the tenant."""
    assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    updated = 0
    for asset in assets:
        try:
            calculate_asset_criticality(db, tenant_id, asset.id)
            updated += 1
        except Exception as exc:
            logger.warning("Criticality calculation failed for asset %d: %s", asset.id, exc)
    return {"assets_updated": updated}


def calculate_asset_criticality(db: Session, tenant_id: str, asset_id: int) -> dict:
    """Infer and persist criticality profile for a single asset."""
    asset = db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id,
        CanonicalAsset.id == asset_id,
    ).first()
    if not asset:
        return {"error": "asset_not_found"}

    software = db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id,
        CanonicalSoftware.asset_id == asset_id,
    ).all()
    software_names = {s.name.lower() for s in software}

    meta = asset.raw_metadata_json or {}
    security = asset.security_posture_json or {}
    open_ports = set(meta.get("open_ports", []))

    # --- Role inference ---
    role = _infer_role(asset.hostname or "", software_names, open_ports)

    # --- Score components ---
    reasons: list[str] = []
    score = 0

    # Role-based base score
    role_scores = {
        "domain_controller": 90,
        "database_server": 80,
        "mail_server": 70,
        "identity_server": 85,
        "hypervisor": 75,
        "backup_server": 65,
        "jump_host": 70,
        "file_server": 60,
        "web_server": 55,
        "monitoring_server": 50,
        "network_device": 65,
        "print_server": 20,
        "workstation": 25,
        "unknown": 30,
    }
    score = role_scores.get(role, 30)
    reasons.append(f"Role inferred as {role} (base score {score})")

    # Internet-exposed: bump up
    is_exposed = bool(meta.get("is_internet_exposed") or security.get("is_internet_exposed"))
    if is_exposed:
        score = min(100, score + 15)
        reasons.append("Internet-exposed: +15")

    # Business service dependency
    service_map = db.query(AssetServiceMap).filter(
        AssetServiceMap.tenant_id == tenant_id,
        AssetServiceMap.asset_id == asset_id,
    ).all()
    if service_map:
        service_ids = [sm.service_id for sm in service_map]
        critical_services = db.query(BusinessService).filter(
            BusinessService.id.in_(service_ids),
            BusinessService.impact_level.in_(["critical", "high"]),
        ).count()
        if critical_services:
            score = min(100, score + 10)
            reasons.append(f"Supports {critical_services} critical/high business service(s): +10")

    # Crown jewel designation
    is_crown = db.query(CrownJewelAsset).filter(
        CrownJewelAsset.tenant_id == tenant_id,
        CrownJewelAsset.asset_id == asset_id,
    ).first()
    if is_crown:
        score = min(100, max(score, 85))
        reasons.append("Designated crown jewel: floor score 85")

    # High-criticality software
    high_sw = [sw for sw in _HIGH_CRITICALITY_SOFTWARE if sw in software_names]
    if high_sw:
        score = min(100, score + 5)
        reasons.append(f"High-criticality software detected: {', '.join(high_sw[:3])}: +5")

    # CIA component scores (simplified heuristics)
    conf_score = min(100, score + 5 if role in {"domain_controller", "database_server", "identity_server"} else score - 5)
    integ_score = min(100, score + 5 if role in {"database_server", "backup_server"} else score)
    avail_score = min(100, score + 10 if role in {"domain_controller", "mail_server", "hypervisor"} else score)
    confidence = 0.85 if role != "unknown" else 0.4

    # Upsert profile
    existing = db.query(AssetCriticalityProfile).filter(
        AssetCriticalityProfile.tenant_id == tenant_id,
        AssetCriticalityProfile.asset_id == asset_id,
    ).first()

    if existing:
        existing.asset_role = role
        existing.criticality_score = score
        existing.confidentiality_score = conf_score
        existing.integrity_score = integ_score
        existing.availability_score = avail_score
        existing.confidence = confidence
        existing.reasoning_json = {"score": score, "role": role, "reasons": reasons}
    else:
        profile = AssetCriticalityProfile(
            tenant_id=tenant_id,
            asset_id=asset_id,
            asset_role=role,
            criticality_score=score,
            confidentiality_score=conf_score,
            integrity_score=integ_score,
            availability_score=avail_score,
            confidence=confidence,
            reasoning_json={"score": score, "role": role, "reasons": reasons},
        )
        db.add(profile)

    db.commit()
    return {"asset_id": asset_id, "role": role, "criticality_score": score, "reasons": reasons}


def assign_service(
    db: Session,
    tenant_id: str,
    asset_id: int,
    service_id: int,
    dependency_type: str = "hosts",
) -> dict:
    """Map an asset to a business service."""
    existing = db.query(AssetServiceMap).filter(
        AssetServiceMap.tenant_id == tenant_id,
        AssetServiceMap.asset_id == asset_id,
        AssetServiceMap.service_id == service_id,
    ).first()
    if existing:
        existing.dependency_type = dependency_type
    else:
        db.add(AssetServiceMap(
            tenant_id=tenant_id,
            asset_id=asset_id,
            service_id=service_id,
            dependency_type=dependency_type,
        ))
    db.commit()
    # Recalculate after mapping changes
    calculate_asset_criticality(db, tenant_id, asset_id)
    return {"asset_id": asset_id, "service_id": service_id, "dependency_type": dependency_type}


def get_business_services(db: Session, tenant_id: str) -> list[dict]:
    services = db.query(BusinessService).filter(BusinessService.tenant_id == tenant_id).all()
    return [
        {
            "id": s.id,
            "service_name": s.service_name,
            "owner_name": s.owner_name,
            "business_unit": s.business_unit,
            "impact_level": s.impact_level,
        }
        for s in services
    ]


def create_business_service(
    db: Session,
    tenant_id: str,
    service_name: str,
    owner_name: str | None = None,
    business_unit: str | None = None,
    impact_level: str = "medium",
    description: str | None = None,
) -> dict:
    svc = BusinessService(
        tenant_id=tenant_id,
        service_name=service_name,
        owner_name=owner_name,
        business_unit=business_unit,
        impact_level=impact_level,
        description=description,
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    return {"id": svc.id, "service_name": svc.service_name}


def get_crown_jewels(db: Session, tenant_id: str) -> list[dict]:
    crown_jewels = db.query(CrownJewelAsset).filter(CrownJewelAsset.tenant_id == tenant_id).all()
    result = []
    for cj in crown_jewels:
        asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == cj.asset_id).first()
        result.append({
            "id": cj.id,
            "asset_id": cj.asset_id,
            "hostname": asset.hostname if asset else None,
            "reason": cj.reason,
            "designated_by": cj.designated_by,
            "created_at": cj.created_at.isoformat() if cj.created_at else None,
        })
    return result


def designate_crown_jewel(
    db: Session,
    tenant_id: str,
    asset_id: int,
    reason: str | None = None,
    designated_by: str | None = None,
) -> dict:
    existing = db.query(CrownJewelAsset).filter(
        CrownJewelAsset.tenant_id == tenant_id,
        CrownJewelAsset.asset_id == asset_id,
    ).first()
    if not existing:
        db.add(CrownJewelAsset(
            tenant_id=tenant_id,
            asset_id=asset_id,
            reason=reason,
            designated_by=designated_by,
        ))
        db.commit()
        calculate_asset_criticality(db, tenant_id, asset_id)
    return {"asset_id": asset_id, "crown_jewel": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _infer_role(hostname: str, software_names: set[str], open_ports: set) -> str:
    hn = hostname.lower()
    for pattern, role in _ROLE_PATTERNS:
        if re.search(pattern, hn, re.IGNORECASE):
            return role

    # Fall back to software and ports
    if any(sw in software_names for sw in {"sql server", "mysql", "postgresql", "oracle"}):
        return "database_server"
    if any(p in open_ports for p in _CRITICAL_PORTS):
        return "domain_controller"
    if any(p in open_ports for p in _DB_PORTS):
        return "database_server"
    if any(p in open_ports for p in _WEB_PORTS):
        return "web_server"
    return "workstation"


def _profile_to_dict(p: AssetCriticalityProfile, db: Session) -> dict:
    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == p.asset_id).first()
    is_crown = db.query(CrownJewelAsset).filter(
        CrownJewelAsset.tenant_id == p.tenant_id,
        CrownJewelAsset.asset_id == p.asset_id,
    ).first() is not None
    return {
        "asset_id": p.asset_id,
        "hostname": asset.hostname if asset else None,
        "asset_role": p.asset_role,
        "criticality_score": p.criticality_score,
        "confidentiality_score": p.confidentiality_score,
        "integrity_score": p.integrity_score,
        "availability_score": p.availability_score,
        "confidence": p.confidence,
        "is_crown_jewel": is_crown,
        "reasoning": p.reasoning_json,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
