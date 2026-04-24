from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.broker import BrokerAccount, BrokerClientLink, BrokerQuoteRequest
from services.broker_service import (
    add_broker_user,
    build_quote_pack,
    create_quote_request,
    get_broker_portfolio,
    invite_client,
    register_broker_account,
)

router = APIRouter(prefix="/api/brokers", tags=["brokers"])


class BrokerAccountCreateBody(BaseModel):
    name: str = Field(...)
    contact_email: str = Field(...)
    regulator_ref: str = Field(...)
    plan: str = Field(...)


class BrokerUserCreateBody(BaseModel):
    broker_account_id: int = Field(...)
    email: str = Field(...)
    full_name: str = Field(...)
    role: str = Field(...)


class BrokerInviteBody(BaseModel):
    broker_account_id: int = Field(...)
    tenant_id: str = Field(...)
    client_name: str = Field(...)
    renewal_date: str = Field(...)
    notes: str = Field(...)
    access_level: str = Field(...)


class BrokerQuoteRequestBody(BaseModel):
    broker_account_id: int = Field(...)
    request_type: str = Field(...)


@router.post("/accounts")
def create_broker_account(
    body: BrokerAccountCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    data = register_broker_account(db, body.name, body.contact_email, body.regulator_ref, body.plan)
    account = data["account"]
    consumer = data["consumer"]
    return {
        "broker_account_id": account.id,
        "consumer_id": consumer.id,
        "broker_code": account.broker_code,
        "plan": account.plan,
        "status": account.status,
    }


@router.post("/users")
def create_broker_user(
    body: BrokerUserCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = add_broker_user(db, body.broker_account_id, body.email, body.full_name, body.role)
    return {
        "id": user.id,
        "broker_account_id": user.broker_account_id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": bool(user.is_active),
    }


@router.post("/clients/invite")
def invite_broker_client(
    body: BrokerInviteBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    data = invite_client(db, body.broker_account_id, body.tenant_id, body.client_name, body.renewal_date, body.notes, body.access_level)
    return {
        "link_id": data["link"].id,
        "grant_id": data["grant"].id,
        "relationship_status": data["link"].relationship_status,
        "grant_status": data["grant"].status,
    }




@router.get("/clients")
def list_broker_clients(
    broker_account_id: int = None,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    q = db.query(BrokerClientLink)
    if broker_account_id is not None:
        q = q.filter(BrokerClientLink.broker_account_id == broker_account_id)
    rows = q.order_by(BrokerClientLink.id.desc()).all()
    return [{
        "id": row.id,
        "broker_account_id": row.broker_account_id,
        "tenant_id": row.tenant_id,
        "client_name": row.client_name,
        "relationship_status": row.relationship_status,
        "consent_grant_id": row.consent_grant_id,
        "renewal_date": row.renewal_date,
        "notes": row.notes,
        "created_at": row.created_at,
    } for row in rows]


@router.get("/portfolio/{broker_account_id}")
def broker_portfolio(
    broker_account_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    return get_broker_portfolio(db, broker_account_id)


@router.get("/clients/{tenant_id}/quote-pack")
def broker_quote_pack(
    tenant_id: str,
    broker_account_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    return build_quote_pack(db, broker_account_id, tenant_id)


@router.get("/clients/{tenant_id}/insurance-summary")
def broker_insurance_summary(
    tenant_id: str,
    broker_account_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    return build_quote_pack(db, broker_account_id, tenant_id)


@router.get("/clients/{tenant_id}/posture")
def broker_client_posture(
    tenant_id: str,
    broker_account_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    data = build_quote_pack(db, broker_account_id, tenant_id)
    return {
        "broker_account_id": broker_account_id,
        "tenant_id": tenant_id,
        "posture": data,
    }


@router.post("/clients/{tenant_id}/quote-request")
def broker_create_quote_request(
    tenant_id: str,
    body: BrokerQuoteRequestBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    req = create_quote_request(db, body.broker_account_id, tenant_id, body.request_type)
    return {
        "id": req.id,
        "broker_account_id": req.broker_account_id,
        "tenant_id": req.tenant_id,
        "request_type": req.request_type,
        "status": req.status,
        "requested_at": req.requested_at,
        "snapshot_version_id": req.snapshot_version_id,
        "response": req.response_json,
    }
