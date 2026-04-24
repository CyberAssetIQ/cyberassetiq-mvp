from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class VerificationCredential(Base):
    __tablename__ = "verification_credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, nullable=False, index=True)
    posture_record_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=False, index=True)
    credential_uuid = Column(String, nullable=False, unique=True, index=True)
    credential_type = Column(String, nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String, nullable=False, default="valid", index=True)
    assurance_level = Column(String, nullable=False, default="continuous-monitoring")
    trust_mark = Column(String, nullable=False, default="CyberAssetIQ Verified")
    claims_json = Column(JSON, nullable=False, default=dict)
    verification_token = Column(String, nullable=False, unique=True, index=True)
    signed_hash = Column(String, nullable=False, index=True)
    public_summary_json = Column(JSON, nullable=False, default=dict)


class VerificationEvent(Base):
    __tablename__ = "verification_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    credential_id = Column(Integer, ForeignKey("verification_credentials.id"), nullable=False, index=True)
    verified_by_consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=True, index=True)
    verification_result = Column(String, nullable=False, index=True)
    verified_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    metadata_json = Column(JSON, nullable=False, default=dict)
