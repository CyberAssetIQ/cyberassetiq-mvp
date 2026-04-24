from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.sql import func

from models.mixins import Base


class PostureRecord(Base):
    __tablename__ = "posture_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, nullable=False, unique=True, index=True)
    record_uuid = Column(String, nullable=False, unique=True, index=True)
    current_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=True, index=True)
    status = Column(String, nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class PostureRecordVersion(Base):
    __tablename__ = "posture_record_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    posture_record_id = Column(Integer, ForeignKey("posture_records.id"), nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    version_no = Column(Integer, nullable=False)
    schema_version = Column(String, nullable=False, default="1.0")
    generated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    generated_by = Column(String, nullable=False, default="posture_snapshot_service")

    overall_score = Column(Integer, nullable=False, default=0)
    risk_band = Column(String, nullable=False, default="Unknown", index=True)
    insurance_readiness_score = Column(Integer, nullable=False, default=0)
    supply_chain_score = Column(Integer, nullable=False, default=0)
    compliance_score = Column(Integer, nullable=False, default=0)
    identity_score = Column(Integer, nullable=False, default=0)
    exposure_score = Column(Integer, nullable=False, default=0)
    resilience_score = Column(Integer, nullable=False, default=0)
    patch_score = Column(Integer, nullable=False, default=0)
    drift_score = Column(Integer, nullable=False, default=0)

    asset_count = Column(Integer, nullable=False, default=0)
    critical_findings_count = Column(Integer, nullable=False, default=0)
    open_cves_count = Column(Integer, nullable=False, default=0)
    darkweb_findings_count = Column(Integer, nullable=False, default=0)
    attack_path_count = Column(Integer, nullable=False, default=0)
    crown_jewel_assets_count = Column(Integer, nullable=False, default=0)
    credential_exposure_count = Column(Integer, nullable=False, default=0)

    summary_json = Column(JSON, nullable=False, default=dict)
    score_breakdown_json = Column(JSON, nullable=False, default=dict)
    top_risks_json = Column(JSON, nullable=False, default=list)
    evidence_summary_json = Column(JSON, nullable=False, default=dict)
    controls_json = Column(JSON, nullable=False, default=dict)
    metadata_json = Column(JSON, nullable=False, default=dict)

    signed_hash = Column(String, nullable=False, index=True)
    is_current = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PostureDomain(Base):
    __tablename__ = "posture_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    posture_record_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=False, index=True)
    domain_name = Column(String, nullable=False, index=True)
    score = Column(Integer, nullable=False, default=0)
    risk_band = Column(String, nullable=False, default="Unknown")
    summary = Column(Text, nullable=False, default="")
    evidence_count = Column(Integer, nullable=False, default=0)
    details_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PostureEvidenceItem(Base):
    __tablename__ = "posture_evidence_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    posture_record_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=False, index=True)
    evidence_type = Column(String, nullable=False, index=True)
    source_module = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    severity = Column(String, nullable=False, default="info", index=True)
    asset_ref = Column(String, nullable=False, default="")
    control_ref = Column(String, nullable=False, default="")
    external_ref = Column(String, nullable=False, default="")
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
