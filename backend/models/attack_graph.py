from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String, Text, DateTime
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from models.mixins import Base, TimestampMixin


class AttackGraphNode(TimestampMixin, Base):
    """A node in the attack graph — either an asset, identity, secret, or service."""
    __tablename__ = "attack_graph_nodes"
    __table_args__ = (
        Index("ix_attack_graph_nodes_tenant_type", "tenant_id", "node_type"),
        Index("ix_attack_graph_nodes_tenant_asset", "tenant_id", "asset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    node_type: Mapped[str] = mapped_column(String(32), index=True)
    # asset | identity | secret | service | crown_jewel | internet
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    identity_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    label: Mapped[str] = mapped_column(String(255))
    node_metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class AttackGraphEdge(TimestampMixin, Base):
    """A directed edge between two nodes representing a potential attack step."""
    __tablename__ = "attack_graph_edges"
    __table_args__ = (
        Index("ix_attack_graph_edges_tenant_source", "tenant_id", "source_node_id"),
        Index("ix_attack_graph_edges_tenant_target", "tenant_id", "target_node_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_node_id: Mapped[int] = mapped_column(Integer, index=True)
    target_node_id: Mapped[int] = mapped_column(Integer, index=True)
    edge_type: Mapped[str] = mapped_column(String(64), index=True)
    # admin_access | smb_reachable | rdp_reachable | shared_credential |
    # trust_relationship | exposed_service | business_dependency
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AttackPath(TimestampMixin, Base):
    """A computed path from a start node to a target (typically a crown jewel)."""
    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("ix_attack_paths_tenant_target", "tenant_id", "target_node_id"),
        Index("ix_attack_paths_tenant_risk", "tenant_id", "risk_score"),
        Index("ix_attack_paths_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    start_node_id: Mapped[int] = mapped_column(Integer, index=True)
    target_node_id: Mapped[int] = mapped_column(Integer, index=True)
    path_json: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    # list of node IDs in order from start → target
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    blast_radius_score: Mapped[float] = mapped_column(Float, default=0.0)
    hop_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    # active | mitigated | suppressed
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class IdentityRelationship(TimestampMixin, Base):
    """Links an identity (user/service account) to an asset it can access."""
    __tablename__ = "identity_relationships"
    __table_args__ = (
        Index("ix_identity_relationships_tenant_identity", "tenant_id", "source_identity"),
        Index("ix_identity_relationships_tenant_asset", "tenant_id", "target_asset_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source_identity: Mapped[str] = mapped_column(String(255), index=True)
    target_asset_id: Mapped[int] = mapped_column(Integer, index=True)
    relationship_type: Mapped[str] = mapped_column(String(64))
    # local_admin | domain_admin | rdp_user | service_account | ssh_key
    privilege_level: Mapped[str] = mapped_column(String(32), default="standard")
    # admin | elevated | standard
    evidence_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )


class CredentialExposureLink(TimestampMixin, Base):
    """Links a dark-web credential exposure to a specific asset and identity."""
    __tablename__ = "credential_exposure_links"
    __table_args__ = (
        Index("ix_credential_exposure_links_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_credential_exposure_links_tenant_identity", "tenant_id", "identity_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    identity_name: Mapped[str] = mapped_column(String(255), index=True)
    secret_type: Mapped[str] = mapped_column(String(64))
    # password | api_key | token | certificate | ssh_key
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="high", index=True)
    detected_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
