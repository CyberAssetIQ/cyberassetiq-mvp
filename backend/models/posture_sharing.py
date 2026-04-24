from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class PostureConsumer(Base):
    __tablename__ = "posture_consumers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    consumer_type = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    external_org_id = Column(String, nullable=False, default="", index=True)
    contact_email = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="active", index=True)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class PostureAccessGrant(Base):
    __tablename__ = "posture_access_grants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, nullable=False, index=True)
    consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=False, index=True)
    grant_type = Column(String, nullable=False, index=True)
    scope_json = Column(JSON, nullable=False, default=dict)
    access_level = Column(String, nullable=False, default="standard", index=True)
    status = Column(String, nullable=False, default="pending", index=True)
    approved_by = Column(String, nullable=False, default="")
    approved_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_accessed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class PostureShareLink(Base):
    __tablename__ = "posture_share_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, nullable=False, index=True)
    posture_record_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=False, index=True)
    consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=True, index=True)
    share_token = Column(String, nullable=False, unique=True, index=True)
    share_type = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(String, nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PostureAccessAudit(Base):
    __tablename__ = "posture_access_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, nullable=False, index=True)
    consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=True, index=True)
    grant_id = Column(Integer, ForeignKey("posture_access_grants.id"), nullable=True, index=True)
    access_method = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=False, index=True)
    resource_id = Column(String, nullable=False, default="")
    action = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False, default="")
    user_agent = Column(String, nullable=False, default="")
    accessed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
