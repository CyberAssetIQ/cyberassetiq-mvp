from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.posture_sharing import PostureAccessAudit, PostureAccessGrant, PostureConsumer, PostureShareLink
from services.posture_record_service import get_current_posture_version


def ensure_consumer(db: Session, consumer_type: str, name: str, external_org_id: str,
                    contact_email: str, metadata_json: dict[str, Any]) -> PostureConsumer:
    consumer = db.query(PostureConsumer).filter(
        PostureConsumer.consumer_type == consumer_type,
        PostureConsumer.name == name,
        PostureConsumer.contact_email == contact_email,
    ).first()
    if consumer:
        consumer.external_org_id = external_org_id
        consumer.metadata_json = metadata_json
        consumer.status = "active"
        db.commit()
        db.refresh(consumer)
        return consumer
    consumer = PostureConsumer(
        consumer_type=consumer_type,
        name=name,
        external_org_id=external_org_id,
        contact_email=contact_email,
        status="active",
        metadata_json=metadata_json,
    )
    db.add(consumer)
    db.commit()
    db.refresh(consumer)
    return consumer


def create_access_grant(db: Session, tenant_id: str, consumer_id: int, grant_type: str,
                        access_level: str, scope_json: dict[str, Any], expires_in_days: int) -> PostureAccessGrant:
    grant = PostureAccessGrant(
        tenant_id=tenant_id,
        consumer_id=consumer_id,
        grant_type=grant_type,
        access_level=access_level,
        scope_json=scope_json,
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)
    return grant


def approve_access_grant(db: Session, grant_id: int, approved_by: str) -> PostureAccessGrant | None:
    grant = db.query(PostureAccessGrant).filter(PostureAccessGrant.id == grant_id).first()
    if not grant:
        return None
    grant.status = "approved"
    grant.approved_by = approved_by
    grant.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(grant)
    return grant


def revoke_access_grant(db: Session, grant_id: int, revoked_by: str) -> PostureAccessGrant | None:
    grant = db.query(PostureAccessGrant).filter(PostureAccessGrant.id == grant_id).first()
    if not grant:
        return None
    grant.status = "revoked"
    grant.approved_by = revoked_by
    db.commit()
    db.refresh(grant)
    return grant


def create_share_link(db: Session, tenant_id: str, share_type: str, created_by: str,
                      consumer_id: int | None = None, expires_in_days: int = 14) -> PostureShareLink:
    version = get_current_posture_version(db, tenant_id)
    if not version:
        raise ValueError("No posture record exists yet for this tenant")
    link = PostureShareLink(
        tenant_id=tenant_id,
        posture_record_version_id=version.id,
        consumer_id=consumer_id,
        share_token=secrets.token_urlsafe(20),
        share_type=share_type,
        expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
        is_active=True,
        created_by=created_by,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def record_access_audit(db: Session, tenant_id: str, consumer_id: int | None, grant_id: int | None,
                        access_method: str, resource_type: str, resource_id: str,
                        action: str, ip_address: str, user_agent: str) -> PostureAccessAudit:
    audit = PostureAccessAudit(
        tenant_id=tenant_id,
        consumer_id=consumer_id,
        grant_id=grant_id,
        access_method=access_method,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(audit)
    db.commit()
    return audit
