from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from models.posture_record import PostureDomain, PostureEvidenceItem, PostureRecord, PostureRecordVersion
from services.posture_snapshot_service import build_posture_snapshot
from services.verification_service import issue_credential


SCHEMA_VERSION = "1.0"


def _hash_snapshot(snapshot: dict[str, Any]) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ensure_posture_record(db: Session, tenant_id: str) -> PostureRecord:
    record = db.query(PostureRecord).filter(PostureRecord.tenant_id == tenant_id).first()
    if record:
        return record
    record = PostureRecord(
        tenant_id=tenant_id,
        record_uuid=str(uuid.uuid4()),
        status="active",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def create_posture_version(db: Session, tenant_id: str, generated_by: str = "posture_api", issue_default_credential: bool = True) -> dict[str, Any]:
    record = ensure_posture_record(db, tenant_id)
    current = db.query(PostureRecordVersion).filter(
        PostureRecordVersion.posture_record_id == record.id,
        PostureRecordVersion.is_current.is_(True),
    ).order_by(PostureRecordVersion.id.desc()).first()
    next_version = (current.version_no + 1) if current else 1
    snapshot = build_posture_snapshot(db, tenant_id)
    signed_hash = _hash_snapshot(snapshot | {"version_no": next_version, "schema_version": SCHEMA_VERSION})

    if current:
        current.is_current = False

    version = PostureRecordVersion(
        posture_record_id=record.id,
        tenant_id=tenant_id,
        version_no=next_version,
        schema_version=SCHEMA_VERSION,
        generated_by=generated_by,
        overall_score=snapshot["overall_score"],
        risk_band=snapshot["risk_band"],
        insurance_readiness_score=snapshot["insurance_readiness_score"],
        supply_chain_score=snapshot["supply_chain_score"],
        compliance_score=snapshot["compliance_score"],
        identity_score=snapshot["identity_score"],
        exposure_score=snapshot["exposure_score"],
        resilience_score=snapshot["resilience_score"],
        patch_score=snapshot["patch_score"],
        drift_score=snapshot["drift_score"],
        asset_count=snapshot["asset_count"],
        critical_findings_count=snapshot["critical_findings_count"],
        open_cves_count=snapshot["open_cves_count"],
        darkweb_findings_count=snapshot["darkweb_findings_count"],
        attack_path_count=snapshot["attack_path_count"],
        crown_jewel_assets_count=snapshot["crown_jewel_assets_count"],
        credential_exposure_count=snapshot["credential_exposure_count"],
        summary_json=snapshot["summary_json"],
        score_breakdown_json=snapshot["score_breakdown_json"],
        top_risks_json=snapshot["top_risks_json"],
        evidence_summary_json=snapshot["evidence_summary_json"],
        controls_json=snapshot["controls_json"],
        metadata_json=snapshot["metadata_json"],
        signed_hash=signed_hash,
        is_current=True,
    )
    db.add(version)
    db.commit()
    db.refresh(version)

    for domain in snapshot.get("domains", []):
        db.add(PostureDomain(
            posture_record_version_id=version.id,
            domain_name=domain["domain_name"],
            score=domain["score"],
            risk_band=domain["risk_band"],
            summary=domain["summary"],
            evidence_count=domain["evidence_count"],
            details_json=domain["details_json"],
        ))

    for item in snapshot.get("evidence", []):
        db.add(PostureEvidenceItem(
            posture_record_version_id=version.id,
            evidence_type=item["evidence_type"],
            source_module=item["source_module"],
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            asset_ref=item["asset_ref"],
            control_ref=item["control_ref"],
            external_ref=item["external_ref"],
            raw_json=item["raw_json"],
        ))

    db.commit()
    record.current_version_id = version.id
    db.commit()
    db.refresh(version)

    credential = None
    if issue_default_credential:
        credential = issue_credential(db, version, credential_type="verified_posture")

    return {
        "record": record,
        "version": version,
        "credential": credential,
    }


def get_current_posture_version(db: Session, tenant_id: str) -> PostureRecordVersion | None:
    record = db.query(PostureRecord).filter(PostureRecord.tenant_id == tenant_id).first()
    if not record:
        return None
    if record.current_version_id:
        found = db.query(PostureRecordVersion).filter(PostureRecordVersion.id == record.current_version_id).first()
        if found:
            return found
    return db.query(PostureRecordVersion).filter(
        PostureRecordVersion.posture_record_id == record.id,
        PostureRecordVersion.is_current.is_(True),
    ).order_by(PostureRecordVersion.id.desc()).first()


def list_posture_versions(db: Session, tenant_id: str, limit: int = 20) -> list[PostureRecordVersion]:
    return db.query(PostureRecordVersion).filter(
        PostureRecordVersion.tenant_id == tenant_id,
    ).order_by(PostureRecordVersion.id.desc()).limit(limit).all()


def get_posture_domains(db: Session, version_id: int) -> list[PostureDomain]:
    return db.query(PostureDomain).filter(PostureDomain.posture_record_version_id == version_id).order_by(PostureDomain.id.asc()).all()


def get_posture_evidence(db: Session, version_id: int, severity: str | None = None) -> list[PostureEvidenceItem]:
    q = db.query(PostureEvidenceItem).filter(PostureEvidenceItem.posture_record_version_id == version_id)
    if severity:
        q = q.filter(PostureEvidenceItem.severity == severity)
    return q.order_by(PostureEvidenceItem.id.asc()).all()
