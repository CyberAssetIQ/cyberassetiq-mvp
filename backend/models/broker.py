from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.sql import func

from models.mixins import Base


class BrokerAccount(Base):
    __tablename__ = "broker_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    consumer_id = Column(Integer, ForeignKey("posture_consumers.id"), nullable=False, index=True)
    broker_code = Column(String, nullable=False, unique=True, index=True)
    regulator_ref = Column(String, nullable=False, default="")
    plan = Column(String, nullable=False, default="broker-standard")
    status = Column(String, nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class BrokerUser(Base):
    __tablename__ = "broker_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    broker_account_id = Column(Integer, ForeignKey("broker_accounts.id"), nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="broker-analyst")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BrokerClientLink(Base):
    __tablename__ = "broker_client_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    broker_account_id = Column(Integer, ForeignKey("broker_accounts.id"), nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    client_name = Column(String, nullable=False)
    relationship_status = Column(String, nullable=False, default="invited", index=True)
    consent_grant_id = Column(Integer, ForeignKey("posture_access_grants.id"), nullable=True, index=True)
    renewal_date = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class BrokerQuoteRequest(Base):
    __tablename__ = "broker_quote_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    broker_account_id = Column(Integer, ForeignKey("broker_accounts.id"), nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    request_type = Column(String, nullable=False, default="new_quote", index=True)
    requested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String, nullable=False, default="requested", index=True)
    snapshot_version_id = Column(Integer, ForeignKey("posture_record_versions.id"), nullable=True, index=True)
    response_json = Column(JSON, nullable=False, default=dict)
