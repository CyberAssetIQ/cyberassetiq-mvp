from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from models.posture_sharing import PostureAccessAudit, PostureAccessGrant, PostureConsumer, PostureShareLink
from services.posture_sharing_service import (
    approve_access_grant,
    create_access_grant,
    create_share_link,
    ensure_consumer,
    record_access_audit,
    revoke_access_grant,
)

router = APIRouter(prefix="/api/posture-sharing", tags=["posture-sharing"])


class ConsumerCreateBody(BaseModel):
    consumer_type: str = Field(...)
    name: str = Field(...)
    external_org_id: str = Field(...)
    contact_email: str = Field(...)
    metadata_json: dict = Field(...)


class GrantCreateBody(BaseModel):
    consumer_id: int = Field(...)
    grant_type: str = Field(...)
    access_level: str = Field(...)
    scope_json: dict = Field(...)
    expires_in_days: int = Field(..., ge=1, le=365)


class GrantDecisionBody(BaseModel):
    acted_by: str = Field(...)


class ShareLinkCreateBody(BaseModel):
    share_type: str = Field(...)
    created_by: str = Field(...)
    consumer_id: int | None = Field(default=None)
    expires_in_days: int = Field(..., ge=1, le=180)


@router.post("/consumers")
def create_consumer(
    body: ConsumerCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    consumer = ensure_consumer(db, body.consumer_type, body.name, body.external_org_id, body.contact_email, body.metadata_json)
    return {
        "id": consumer.id,
        "consumer_type": consumer.consumer_type,
        "name": consumer.name,
        "contact_email": consumer.contact_email,
        "status": consumer.status,
        "metadata": consumer.metadata_json,
    }


@router.post("/grants")
def create_grant(
    body: GrantCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    grant = create_access_grant(db, auth.tenant_id, body.consumer_id, body.grant_type, body.access_level, body.scope_json, body.expires_in_days)
    return {
        "id": grant.id,
        "tenant_id": grant.tenant_id,
        "consumer_id": grant.consumer_id,
        "grant_type": grant.grant_type,
        "access_level": grant.access_level,
        "status": grant.status,
        "expires_at": grant.expires_at,
        "scope": grant.scope_json,
    }


@router.get("/grants")
def list_grants(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rows = db.query(PostureAccessGrant).filter(PostureAccessGrant.tenant_id == auth.tenant_id).order_by(PostureAccessGrant.id.desc()).all()
    return [{
        "id": g.id,
        "consumer_id": g.consumer_id,
        "grant_type": g.grant_type,
        "access_level": g.access_level,
        "status": g.status,
        "approved_by": g.approved_by,
        "approved_at": g.approved_at,
        "expires_at": g.expires_at,
        "scope": g.scope_json,
    } for g in rows]


@router.post("/grants/{grant_id}/approve")
def approve_grant(
    grant_id: int,
    body: GrantDecisionBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    grant = approve_access_grant(db, grant_id, body.acted_by)
    if not grant or grant.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=404, detail="Grant not found")
    return {"status": grant.status, "approved_by": grant.approved_by, "approved_at": grant.approved_at}


@router.post("/grants/{grant_id}/revoke")
def revoke_grant(
    grant_id: int,
    body: GrantDecisionBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    grant = revoke_access_grant(db, grant_id, body.acted_by)
    if not grant or grant.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=404, detail="Grant not found")
    return {"status": grant.status, "acted_by": body.acted_by}


@router.post("/share-links")
def make_share_link(
    body: ShareLinkCreateBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    link = create_share_link(db, auth.tenant_id, body.share_type, body.created_by, body.consumer_id, body.expires_in_days)
    return {
        "id": link.id,
        "share_token": link.share_token,
        "share_type": link.share_type,
        "expires_at": link.expires_at,
        "version_id": link.posture_record_version_id,
    }


@router.get("/share-links")
def list_share_links(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rows = db.query(PostureShareLink).filter(PostureShareLink.tenant_id == auth.tenant_id).order_by(PostureShareLink.id.desc()).all()
    return [{
        "id": row.id,
        "share_token": row.share_token,
        "share_type": row.share_type,
        "consumer_id": row.consumer_id,
        "expires_at": row.expires_at,
        "is_active": row.is_active,
        "version_id": row.posture_record_version_id,
    } for row in rows]


@router.get("/audit")
def audit_log(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rows = db.query(PostureAccessAudit).filter(PostureAccessAudit.tenant_id == auth.tenant_id).order_by(PostureAccessAudit.id.desc()).limit(200).all()
    return [{
        "id": row.id,
        "consumer_id": row.consumer_id,
        "grant_id": row.grant_id,
        "access_method": row.access_method,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "action": row.action,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "accessed_at": row.accessed_at,
    } for row in rows]


@router.post("/audit/record")
def create_audit_record(
    request: Request,
    resource_type: str,
    resource_id: str,
    action: str,
    consumer_id: int | None = None,
    grant_id: int | None = None,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    row = record_access_audit(
        db=db,
        tenant_id=auth.tenant_id,
        consumer_id=consumer_id,
        grant_id=grant_id,
        access_method="api",
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )
    return {"id": row.id, "recorded_at": row.accessed_at}
