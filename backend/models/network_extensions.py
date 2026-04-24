from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.mixins import Base, TimestampMixin


class ExtensionServiceJob(TimestampMixin, Base):
    __tablename__ = "extension_service_jobs"
    __table_args__ = (
        Index("ix_extension_service_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_extension_service_jobs_tenant_type", "tenant_id", "job_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_type: Mapped[str] = mapped_column(String(64), index=True)
    service_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class PassiveDiscoveryResult(TimestampMixin, Base):
    __tablename__ = "passive_discovery_results"
    __table_args__ = (
        Index("ix_passive_discovery_results_tenant_job", "tenant_id", "job_id"),
        Index("ix_passive_discovery_results_tenant_ip", "tenant_id", "ip_address"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    job_id: Mapped[int] = mapped_column(Integer, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(32), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class ExposureFinding(TimestampMixin, Base):
    __tablename__ = "exposure_findings"
    __table_args__ = (
        Index("ix_exposure_findings_tenant_job", "tenant_id", "job_id"),
        Index("ix_exposure_findings_tenant_ip", "tenant_id", "ip_address"),
        Index("ix_exposure_findings_tenant_severity", "tenant_id", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    job_id: Mapped[int] = mapped_column(Integer, index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class AttackPathFinding(TimestampMixin, Base):
    __tablename__ = "attack_path_findings"
    __table_args__ = (
        Index("ix_attack_path_findings_tenant_job", "tenant_id", "job_id"),
        Index("ix_attack_path_findings_tenant_ip", "tenant_id", "ip_address"),
        Index("ix_attack_path_findings_tenant_type", "tenant_id", "path_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    job_id: Mapped[int] = mapped_column(Integer, index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    path_type: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    narrative: Mapped[str] = mapped_column(Text)
    related_services_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    related_cves_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
