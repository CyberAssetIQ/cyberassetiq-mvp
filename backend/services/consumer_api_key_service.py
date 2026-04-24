"""
consumer_api_key_service.py

External Consumer API Key Management.

Brokers and enterprise buyers are external organisations — they cannot be
given the tenant's internal admin API key. This service issues separate,
scoped API credentials to registered consumers (brokers, buyers, auditors)
allowing them to query posture data via their own authenticated access.

Key design:
  - Each consumer (broker/buyer) gets their own API key
  - Consumer keys are scoped to permitted tenants only (via access grants)
  - Consumer keys have read-only access to posture data — no admin operations
  - Keys can be revoked without affecting tenant operations
  - Full audit trail of consumer API access
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_consumer_key() -> tuple[str, str]:
    """Return (plaintext, hash). Plaintext shown once — only hash stored."""
    raw = "ciq_consumer_" + secrets.token_urlsafe(32)
    return raw, _hash_key(raw)


# ---------------------------------------------------------------------------
# Key issuance
# ---------------------------------------------------------------------------

def issue_consumer_key(
    db: Session,
    consumer_id: int,
    label: str,
    validity_days: int = 365,
    permitted_tenant_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Issue a new API key for a registered posture consumer (broker or buyer).
    Returns the plaintext key — store it securely, it is shown only once.
    """
    from models.consumer_api_key import ConsumerAPIKey

    plaintext, key_hash = generate_consumer_key()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=validity_days)

    key_record = ConsumerAPIKey(
        consumer_id=consumer_id,
        key_hash=key_hash,
        label=label,
        permitted_tenants=permitted_tenant_ids or [],
        is_active=True,
        issued_at=now,
        expires_at=expires,
        last_used_at=None,
        use_count=0,
    )
    db.add(key_record)
    db.commit()
    db.refresh(key_record)

    logger.info("Consumer API key issued: consumer_id=%d label=%s", consumer_id, label)

    return {
        "key_id": key_record.id,
        "consumer_id": consumer_id,
        "api_key": plaintext,  # shown once only
        "label": label,
        "permitted_tenants": permitted_tenant_ids or [],
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "status": "active",
        "warning": "Store this API key securely. It will not be shown again.",
    }


def list_consumer_keys(db: Session, consumer_id: int) -> list[dict]:
    """List all API keys for a consumer (without revealing the key hash)."""
    from models.consumer_api_key import ConsumerAPIKey

    rows = (
        db.query(ConsumerAPIKey)
        .filter(ConsumerAPIKey.consumer_id == consumer_id)
        .order_by(ConsumerAPIKey.id.desc())
        .all()
    )
    return [
        {
            "key_id": r.id,
            "consumer_id": r.consumer_id,
            "label": r.label,
            "permitted_tenants": r.permitted_tenants or [],
            "is_active": bool(r.is_active),
            "issued_at": r.issued_at.isoformat() if r.issued_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "use_count": r.use_count or 0,
        }
        for r in rows
    ]


def revoke_consumer_key(db: Session, key_id: int, consumer_id: int) -> bool:
    """Revoke a consumer API key. Returns True if revoked, False if not found."""
    from models.consumer_api_key import ConsumerAPIKey

    row = db.query(ConsumerAPIKey).filter(
        ConsumerAPIKey.id == key_id,
        ConsumerAPIKey.consumer_id == consumer_id,
    ).first()
    if not row:
        return False
    row.is_active = False
    db.commit()
    logger.info("Consumer API key revoked: key_id=%d consumer_id=%d", key_id, consumer_id)
    return True


# ---------------------------------------------------------------------------
# Authentication resolution
# ---------------------------------------------------------------------------

def resolve_consumer_auth(
    db: Session,
    api_key: str,
    requested_tenant_id: str,
) -> dict[str, Any] | None:
    """
    Validate a consumer API key and return consumer identity if authorised.
    Returns None if the key is invalid, expired, or not permitted for the tenant.
    """
    from models.consumer_api_key import ConsumerAPIKey
    from models.posture_sharing import PostureConsumer

    key_hash = _hash_key(api_key)
    now = datetime.now(timezone.utc)

    row = (
        db.query(ConsumerAPIKey)
        .filter(
            ConsumerAPIKey.key_hash == key_hash,
            ConsumerAPIKey.is_active == True,
        )
        .first()
    )
    if not row:
        return None

    # Check expiry
    if row.expires_at and row.expires_at.replace(tzinfo=timezone.utc) < now:
        return None

    # Check tenant permission
    permitted = row.permitted_tenants or []
    if permitted and requested_tenant_id not in permitted:
        return None

    # Verify active access grant still exists for this tenant
    from models.posture_sharing import PostureAccessGrant
    grant = (
        db.query(PostureAccessGrant)
        .filter(
            PostureAccessGrant.tenant_id == requested_tenant_id,
            PostureAccessGrant.consumer_id == row.consumer_id,
            PostureAccessGrant.status == "approved",
        )
        .first()
    )
    if not grant:
        return None

    # Update usage tracking (best-effort)
    try:
        row.last_used_at = now
        row.use_count = (row.use_count or 0) + 1
        grant.last_accessed_at = now
        db.commit()
    except Exception:
        db.rollback()

    # Get consumer details
    consumer = db.query(PostureConsumer).filter(
        PostureConsumer.id == row.consumer_id
    ).first()

    return {
        "consumer_id": row.consumer_id,
        "consumer_type": consumer.consumer_type if consumer else "unknown",
        "consumer_name": consumer.name if consumer else "Unknown",
        "tenant_id": requested_tenant_id,
        "grant_id": grant.id,
        "access_level": grant.access_level,
        "key_id": row.id,
        "role": "consumer",  # read-only, scoped role
    }
