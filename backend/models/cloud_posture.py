"""cloud_posture.py

Tables for Cloud / SaaS / Identity Posture (Phase 4).

cloud_accounts          — connected cloud provider accounts
cloud_assets            — assets discovered via cloud APIs
cloud_posture_findings  — misconfigurations in cloud infrastructure
identity_posture_findings — identity/IAM risks (Entra, AWS IAM, GWS)
saas_apps               — SaaS applications discovered
saas_posture_findings   — SaaS security posture gaps
connector_sync_logs     — audit trail for each provider sync
"""
from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text, Float, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class CloudAccount(TimestampMixin, Base):
    """A connected cloud provider account or tenant."""
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        Index("ix_cloud_accounts_tenant_provider", "tenant_id", "provider"),
        Index("ix_cloud_accounts_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    provider: Mapped[str] = mapped_column(String(32), index=True)
    # m365 | azure | aws | gcp | google_workspace | okta | github | dropbox

    account_name: Mapped[str] = mapped_column(String(256))
    account_identifier: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # tenant_id for M365/Entra, account_id for AWS, project_id for GCP

    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | connected | error | disconnected | auth_expired

    connection_metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # Non-sensitive metadata only — no secrets stored here

    posture_score: Mapped[float] = mapped_column(Float, default=0.0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings_count: Mapped[int] = mapped_column(Integer, default=0)

    last_synced_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class CloudAsset(TimestampMixin, Base):
    """An asset discovered via a cloud provider API."""
    __tablename__ = "cloud_assets"
    __table_args__ = (
        Index("ix_cloud_assets_tenant_account", "tenant_id", "cloud_account_id"),
        Index("ix_cloud_assets_type", "tenant_id", "asset_type"),
        Index("ix_cloud_assets_external_id", "tenant_id", "external_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    cloud_account_id: Mapped[int] = mapped_column(Integer, index=True)

    asset_type: Mapped[str] = mapped_column(String(64), index=True)
    # vm | storage_bucket | database | function | container | identity | app_registration
    # managed_disk | load_balancer | key_vault | dns_zone | subnet | security_group

    external_id: Mapped[str] = mapped_column(String(512), index=True)
    name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # production | staging | development | unknown

    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_mfa: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    tags_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    discovered_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudPostureFinding(TimestampMixin, Base):
    """A misconfiguration or security gap in cloud infrastructure."""
    __tablename__ = "cloud_posture_findings"
    __table_args__ = (
        Index("ix_cloud_posture_findings_tenant", "tenant_id"),
        Index("ix_cloud_posture_findings_account", "tenant_id", "cloud_account_id"),
        Index("ix_cloud_posture_findings_severity", "tenant_id", "severity"),
        Index("ix_cloud_posture_findings_type", "tenant_id", "finding_type"),
        Index("ix_cloud_posture_findings_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    cloud_account_id: Mapped[int] = mapped_column(Integer, index=True)
    cloud_asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    provider: Mapped[str] = mapped_column(String(32), index=True)

    finding_type: Mapped[str] = mapped_column(String(128), index=True)
    # public_storage | exposed_compute | missing_mfa | overprivileged_identity
    # no_encryption | public_snapshot | missing_logging | broad_iam | exposed_secret
    # legacy_auth_enabled | no_conditional_access | stale_admin | guest_access_risk

    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    resource_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    compliance_controls: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # ["CE_A2", "ISO27001_A.9", "DSPT_6.1"]

    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    # open | resolved | accepted_risk | false_positive

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    resolved_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityPostureFinding(TimestampMixin, Base):
    """An identity or IAM risk finding from M365/Entra, AWS IAM, or GWS."""
    __tablename__ = "identity_posture_findings"
    __table_args__ = (
        Index("ix_identity_posture_findings_tenant", "tenant_id"),
        Index("ix_identity_posture_findings_provider", "tenant_id", "provider"),
        Index("ix_identity_posture_findings_severity", "tenant_id", "severity"),
        Index("ix_identity_posture_findings_type", "tenant_id", "finding_type"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    cloud_account_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    provider: Mapped[str] = mapped_column(String(32), index=True)
    identity_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    identity_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # user | service_principal | managed_identity | group | role

    finding_type: Mapped[str] = mapped_column(String(128), index=True)
    # mfa_disabled | stale_admin | privileged_no_mfa | guest_with_admin
    # no_conditional_access | excessive_permissions | shared_account
    # inactive_privileged_account | risky_app_consent | external_member_in_admin_role

    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    affected_count: Mapped[int] = mapped_column(Integer, default=1)
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SaaSApp(TimestampMixin, Base):
    """A SaaS application detected in the environment."""
    __tablename__ = "saas_apps"
    __table_args__ = (
        Index("ix_saas_apps_tenant", "tenant_id"),
        Index("ix_saas_apps_name", "tenant_id", "app_name"),
        Index("ix_saas_apps_status", "tenant_id", "approved_status"),
        Index("ix_saas_apps_risk", "tenant_id", "risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)

    app_name: Mapped[str] = mapped_column(String(256), index=True)
    app_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)

    source: Mapped[str] = mapped_column(String(64), default="software_inventory", index=True)
    # software_inventory | m365_oauth_apps | browser_extension | dns_lookup | manual

    discovered_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # asset_id or "network_scan" or "manual"

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_flags: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # ["no_sso", "no_mfa", "data_residency_risk", "no_contract", "shadow_it"]

    approved_status: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    # approved | unapproved | blacklisted | unknown | under_review

    user_count: Mapped[int] = mapped_column(Integer, default=0)
    has_data_access: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    data_classifications: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SaaSPostureFinding(TimestampMixin, Base):
    """A security posture gap in a SaaS application."""
    __tablename__ = "saas_posture_findings"
    __table_args__ = (
        Index("ix_saas_posture_findings_tenant", "tenant_id"),
        Index("ix_saas_posture_findings_app", "tenant_id", "app_id"),
        Index("ix_saas_posture_findings_severity", "tenant_id", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[int] = mapped_column(Integer, index=True)

    finding_type: Mapped[str] = mapped_column(String(128), index=True)
    # no_sso | no_mfa | shared_credentials | excessive_permissions
    # no_audit_log | data_outside_uk | no_contract | unmanaged_access

    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)

    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ConnectorSyncLog(TimestampMixin, Base):
    """Audit log for every cloud/SaaS connector sync run."""
    __tablename__ = "connector_sync_logs"
    __table_args__ = (
        Index("ix_connector_sync_logs_tenant_provider", "tenant_id", "provider"),
        Index("ix_connector_sync_logs_status", "tenant_id", "status"),
        Index("ix_connector_sync_logs_started", "tenant_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    cloud_account_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)

    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    # running | completed | failed | partial

    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    summary_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    started_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    finished_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
