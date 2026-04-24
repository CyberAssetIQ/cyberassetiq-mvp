from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.sql import func

from models.mixins import Base


class BuyerAccount(Base):
    __tablename__ = "buyer_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=False, index=True)
    buyer_code = Column(String, nullable=False, unique=True, index=True)
    industry = Column(String, nullable=False, default="general")
    status = Column(String, nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SupplierRelationship(Base):
    __tablename__ = "supplier_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    buyer_account_id = Column(Integer, ForeignKey("buyer_accounts.id"), nullable=False, index=True)
    supplier_tenant_id = Column(String, nullable=False, index=True)
    supplier_name = Column(String, nullable=False)
    relationship_status = Column(String, nullable=False, default="invited", index=True)
    tier = Column(String, nullable=False, default="tier-1")
    criticality = Column(String, nullable=False, default="medium")
    contract_ref = Column(String, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AssuranceRequest(Base):
    __tablename__ = "assurance_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    buyer_account_id = Column(Integer, ForeignKey("buyer_accounts.id"), nullable=False, index=True)
    supplier_tenant_id = Column(String, nullable=False, index=True)
    request_type = Column(String, nullable=False, default="initial", index=True)
    requested_controls_json = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="requested", index=True)
    requested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    latest_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=True, index=True)


class SupplierAttestation(Base):
    __tablename__ = "supplier_attestations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assurance_request_id = Column(Integer, ForeignKey("assurance_requests.id"), nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    attested_by = Column(String, nullable=False)
    attestation_text = Column(Text, nullable=False)
    answers_json = Column(JSON, nullable=False, default=dict)
    submitted_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AssuranceReview(Base):
    __tablename__ = "assurance_reviews"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assurance_request_id = Column(Integer, ForeignKey("assurance_requests.id"), nullable=False, index=True)
    buyer_account_id = Column(Integer, ForeignKey("buyer_accounts.id"), nullable=False, index=True)
    review_status = Column(String, nullable=False, default="accepted", index=True)
    review_notes = Column(Text, nullable=False, default="")
    reviewed_by = Column(String, nullable=False)
    reviewed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
